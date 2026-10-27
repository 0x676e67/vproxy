/** Browser-local write-ahead notes, not server receipts or authorization.
 *
 * A scope lock is held until the request owner explicitly releases it. The
 * registry lock protects only insertion/capacity checks, never a network wait.
 * Web Locks coordinate cooperative tabs in the same storage partition:
 * https://www.w3.org/TR/2025/WD-web-locks-20250924/#api-lock-manager-request
 * Clearing browser data can remove these notes; server CAS/authorization remain
 * authoritative and no saved note may cause an automatic replay.
 */
export const JOURNAL_PREFIX = "vproxy.review.v1.";
const MAX_NOTES = 32;
const MAX_BYTES = 4096;
const MAX_STORAGE_KEYS = 4096;
const keyPattern = /^[A-Za-z0-9._:-]{1,160}$/;
const noteIdPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type JournalIssue =
  "unsupported" | "unavailable" | "invalid" | "capacity";

/** Decoders must reject unknown fields and copy only non-secret metadata. */
export interface JournalCodec<T> {
  decode(value: unknown): T | null;
  key(value: T): string;
}

/** Explicit platform boundary for deterministic storage/lock fault tests. */
export interface JournalEnvironment {
  storage(): Storage;
  locks: Pick<LockManager, "request">;
  listen(listener: () => void): () => void;
}

export type JournalEntry<T> = Readonly<{
  id: string;
  key: string;
  value: T;
}>;

/** An in-memory lock owner, never a server operation ID or a replay key. */
export interface JournalLease<T> {
  readonly id: string;
  readonly key: string;
  persist(value: T): boolean;
  remove(): boolean;
  release(): void;
}

export type JournalFactory = <T>(
  namespace: "nodes" | "routing" | "alerts" | "notifications",
  codec: JournalCodec<T>,
) => ReviewJournal<T>;

/** Resolve the browser boundary without touching its storage or credentials.
 * No API fallback silently degrades a persistent write into a memory-only one.
 */
function browserEnvironment(): JournalEnvironment | null {
  try {
    if (
      typeof window === "undefined" ||
      typeof navigator === "undefined" ||
      typeof navigator.locks?.request !== "function"
    )
      return null;
    return {
      storage: () => window.localStorage,
      locks: navigator.locks,
      listen: (listener) => {
        const changed = (event: StorageEvent) => {
          if (event.key === null || event.key.startsWith(JOURNAL_PREFIX))
            listener();
        };
        window.addEventListener("storage", changed);
        return () => window.removeEventListener("storage", changed);
      },
    };
  } catch {
    return null;
  }
}

export const browserJournal: JournalFactory = (namespace, codec) =>
  new ReviewJournal(namespace, codec);

/** Bounded metadata only. Malformed/unreadable storage is never treated as an
 * empty history and unresolved entries are never evicted or expired by time.
 */
export class ReviewJournal<T> {
  private readonly prefix: string;
  private readonly environment: JournalEnvironment | null;
  private problem: JournalIssue | null;
  private readonly listeners = new Set<() => void>();
  private detach: (() => void) | null = null;
  private notification = false;

  constructor(
    namespace: "nodes" | "routing" | "alerts" | "notifications",
    private readonly codec: JournalCodec<T>,
    environment?: JournalEnvironment,
  ) {
    this.prefix = `${JOURNAL_PREFIX}${namespace}.`;
    this.environment = environment ?? browserEnvironment();
    this.problem = this.environment ? null : "unsupported";
  }

  issue(): JournalIssue | null {
    return this.problem;
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    if (this.listeners.size === 1 && this.environment) {
      try {
        this.detach = this.environment.listen(() => this.notify());
      } catch {
        this.fault("unavailable");
      }
    }
    return () => {
      this.listeners.delete(listener);
      if (this.listeners.size === 0) {
        this.detach?.();
        this.detach = null;
      }
    };
  }

  /** Reading validates the whole namespace before returning any entry. */
  load(): readonly JournalEntry<T>[] {
    if (!this.environment || this.fatal()) return [];
    try {
      const storage = this.environment.storage();
      if (storage.length > MAX_STORAGE_KEYS) return this.invalid();
      // Snapshot names in one native operation. Iterating key(index) can skip
      // an unresolved entry when another tab deletes an earlier, different key.
      const names = Object.getOwnPropertyNames(storage).filter((name) =>
        name.startsWith(this.prefix),
      );
      if (names.length > MAX_NOTES) return this.invalid();
      const entries: JournalEntry<T>[] = [];
      const ids = new Set<string>();
      const keys = new Set<string>();
      for (const name of names) {
        const raw = storage.getItem(name);
        // Another scope may have been acknowledged since the names snapshot.
        // Deletion only reduces capacity; it is not corrupt metadata or a
        // receipt that permits a registry to clear its own old in-memory note.
        if (raw === null) continue;
        const entry = this.decode(raw);
        if (
          !entry ||
          name !== this.prefix + entry.key ||
          ids.has(entry.id) ||
          keys.has(entry.key)
        )
          return this.invalid();
        entries.push(entry);
        ids.add(entry.id);
        keys.add(entry.key);
        if (entries.length > MAX_NOTES) return this.invalid();
      }
      if (this.problem === "capacity" && entries.length < MAX_NOTES) {
        this.problem = null;
        this.notify();
      }
      return Object.freeze(entries);
    } catch {
      this.fault("unavailable");
      return [];
    }
  }

  /** Acquire a cooperative scope lock, then write and read back the browser
   * note before resolving. This is not an fsync or power-loss guarantee. The
   * caller must recheck its session and release in finally.
   */
  async acquire(
    value: T,
    current: () => boolean,
  ): Promise<JournalLease<T> | null> {
    if (!this.environment || this.fatal()) return null;
    const copy = this.checked(value);
    if (copy === null) return null;
    const key = this.codec.key(copy);
    const environment = this.environment;
    let settle: (lease: JournalLease<T> | null) => void = () => {};
    const acquired = new Promise<JournalLease<T> | null>((resolve) => {
      settle = resolve;
    });
    // request() resolves only after releasing the lock, so a separate result
    // promise transfers ownership while its callback continues holding it.
    try {
      void environment.locks
        .request(this.scopeLock(key), { ifAvailable: true }, async (lock) => {
          if (!lock || !current() || this.fatal()) {
            settle(null);
            return;
          }
          let unlock: () => void = () => {};
          const held = new Promise<void>((resolve) => {
            unlock = resolve;
          });
          let released = false;
          const release = () => {
            if (released) return;
            released = true;
            unlock();
          };
          const insertion = new AbortController();
          const timer = setTimeout(() => insertion.abort(), 1000);
          try {
            const entry = await environment.locks.request(
              `${this.prefix}registry`,
              { signal: insertion.signal },
              () => {
                const entries = this.load();
                if (this.fatal() || !current()) return null;
                // The per-scope lock makes this exact read independent of the
                // namespace scan; an unresolved note must never be overwritten.
                const existing = environment
                  .storage()
                  .getItem(this.prefix + key);
                if (existing !== null) {
                  if (!this.decode(existing)) this.fault("invalid");
                  return null;
                }
                if (entries.length >= MAX_NOTES) {
                  this.fault("capacity");
                  return null;
                }
                const entry: JournalEntry<T> = Object.freeze({
                  id: crypto.randomUUID(),
                  key,
                  value: copy,
                });
                return this.store(entry) ? entry : null;
              },
            );
            clearTimeout(timer);
            if (!entry) {
              settle(null);
              return;
            }
            settle({
              id: entry.id,
              key,
              persist: (next) => {
                if (released || this.fatal()) return false;
                const copy = this.checked(next);
                if (copy === null || this.codec.key(copy) !== key) return false;
                return this.owned(entry, () =>
                  this.store({ id: entry.id, key, value: copy }),
                );
              },
              remove: () =>
                !released &&
                !this.fatal() &&
                this.owned(entry, () => this.erase(key)),
              release,
            });
            await held;
          } finally {
            clearTimeout(timer);
            release();
          }
        })
        .catch(() => {
          this.fault("unavailable");
          settle(null);
        });
    } catch {
      this.fault("unavailable");
      settle(null);
    }
    return acquired;
  }

  /** Explicit fresh review may clear only this note, never a newer replacement.
   * An absent browser entry is not proof of no effect; the caller still needs
   * its fresh observation and explicit acknowledgement before calling this.
   */
  async clear(
    key: string,
    id: string,
    current: () => boolean,
  ): Promise<boolean> {
    if (
      !this.environment ||
      this.fatal() ||
      !keyPattern.test(key) ||
      !noteIdPattern.test(id)
    )
      return false;
    try {
      return await this.environment.locks.request(
        this.scopeLock(key),
        { ifAvailable: true },
        (lock) => {
          if (!lock || !current() || this.fatal()) return false;
          const raw = this.environment?.storage().getItem(this.prefix + key);
          if (raw === null) return true;
          if (raw === undefined) return false;
          const entry = this.decode(raw);
          if (!entry) {
            this.fault("invalid");
            return false;
          }
          if (entry.key !== key || entry.id !== id) return false;
          return this.erase(key);
        },
      );
    } catch {
      this.fault("unavailable");
      return false;
    }
  }

  private scopeLock(key: string): string {
    return `${this.prefix}scope:${key}`;
  }

  private checked(value: unknown): T | null {
    try {
      const copy = this.codec.decode(value);
      if (copy !== null && keyPattern.test(this.codec.key(copy))) return copy;
    } catch {
      // A codec failure is malformed metadata, never a raw diagnostic.
    }
    this.fault("invalid");
    return null;
  }

  private decode(raw: string): JournalEntry<T> | null {
    if (raw.length > MAX_BYTES) return null;
    try {
      const value: unknown = JSON.parse(raw);
      if (!value || typeof value !== "object" || Array.isArray(value))
        return null;
      const record = value as Record<string, unknown>;
      if (
        Object.keys(record).sort().join(",") !== "id,key,value,version" ||
        record.version !== 1 ||
        typeof record.id !== "string" ||
        !noteIdPattern.test(record.id) ||
        typeof record.key !== "string" ||
        !keyPattern.test(record.key)
      )
        return null;
      const copy = this.codec.decode(record.value);
      if (copy === null || this.codec.key(copy) !== record.key) return null;
      return Object.freeze({ id: record.id, key: record.key, value: copy });
    } catch {
      return null;
    }
  }

  private store(entry: JournalEntry<T>): boolean {
    try {
      const raw = JSON.stringify({ version: 1, ...entry });
      if (raw.length > MAX_BYTES || !this.decode(raw)) {
        this.fault("invalid");
        return false;
      }
      const storage = this.environment?.storage();
      if (!storage) return false;
      storage.setItem(this.prefix + entry.key, raw);
      // A no-op or interfering storage adapter must not admit a write either.
      if (storage.getItem(this.prefix + entry.key) !== raw) {
        this.fault("unavailable");
        return false;
      }
      return true;
    } catch {
      this.fault("unavailable");
      return false;
    }
  }

  private owned(entry: JournalEntry<T>, work: () => boolean): boolean {
    try {
      const raw = this.environment?.storage().getItem(this.prefix + entry.key);
      const saved = typeof raw === "string" ? this.decode(raw) : null;
      if (!saved || saved.key !== entry.key || saved.id !== entry.id) {
        // Do not remove a replacement or treat external deletion as a receipt.
        this.fault("invalid");
        return false;
      }
      return work();
    } catch {
      this.fault("unavailable");
      return false;
    }
  }

  private erase(key: string): boolean {
    try {
      const storage = this.environment?.storage();
      if (!storage) return false;
      storage.removeItem(this.prefix + key);
      if (storage.getItem(this.prefix + key) !== null) {
        this.fault("unavailable");
        return false;
      }
      if (this.problem === "capacity") this.problem = null;
      return true;
    } catch {
      this.fault("unavailable");
      return false;
    }
  }

  private fatal(): boolean {
    return this.problem !== null && this.problem !== "capacity";
  }

  private invalid(): readonly JournalEntry<T>[] {
    this.fault("invalid");
    return [];
  }

  private fault(issue: JournalIssue): void {
    if (this.problem === issue || this.fatal()) return;
    this.problem = issue;
    this.notify();
  }

  private notify(): void {
    if (this.notification) return;
    this.notification = true;
    queueMicrotask(() => {
      this.notification = false;
      this.listeners.forEach((listener) => listener());
    });
  }
}
