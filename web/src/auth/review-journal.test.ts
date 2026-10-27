import { describe, expect, it, vi } from "vitest";
import {
  browserJournal,
  JOURNAL_PREFIX,
  ReviewJournal,
  type JournalCodec,
  type JournalEnvironment,
} from "./review-journal";
import { createTestLocks, createTestStorage } from "../test/web-locks";

type Note = Readonly<{ scope: string; phase: "pending" | "unknown" }>;

const codec: JournalCodec<Note> = {
  decode(value) {
    if (!value || typeof value !== "object" || Array.isArray(value))
      return null;
    const row = value as Record<string, unknown>;
    return Object.keys(row).sort().join(",") === "phase,scope" &&
      typeof row.scope === "string" &&
      /^[a-z0-9-]{1,40}$/.test(row.scope) &&
      (row.phase === "pending" || row.phase === "unknown")
      ? { scope: row.scope, phase: row.phase }
      : null;
  },
  key: (value) => value.scope,
};

const note = (scope = "scope-a", phase: Note["phase"] = "pending"): Note => ({
  scope,
  phase,
});
const storageKey = (key: string, namespace = "nodes") =>
  `${JOURNAL_PREFIX}${namespace}.${key}`;
const uuid = (number: number) =>
  `00000000-0000-4000-8000-${number.toString(16).padStart(12, "0")}`;
const envelope = (value: Note, id = uuid(1)) => ({
  version: 1,
  id,
  key: value.scope,
  value,
});
const current = () => true;

function deferred() {
  let resolve = () => {};
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve: () => resolve() };
}

function harness(storage = createTestStorage(), locks = createTestLocks()) {
  const listeners = new Set<() => void>();
  const environment: JournalEnvironment = {
    storage: () => storage,
    locks,
    listen(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
  return {
    storage,
    locks,
    environment,
    changed: () => listeners.forEach((listener) => listener()),
    listenerCount: () => listeners.size,
    journal: (namespace: "nodes" | "routing" = "nodes") =>
      new ReviewJournal(namespace, codec, environment),
  };
}

function snapshot(storage: Storage) {
  return Object.fromEntries(
    Object.getOwnPropertyNames(storage)
      .sort()
      .map((key) => [key, storage.getItem(key)]),
  );
}

describe("test-only browser primitives", () => {
  it("holds callbacks until their promises settle, queues exclusively and returns null when unavailable", async () => {
    const locks = createTestLocks();
    const held = deferred();
    const entered = deferred();
    const calls: string[] = [];
    const first = locks.request("scope", async (lock) => {
      expect(lock?.name).toBe("scope");
      calls.push("first");
      entered.resolve();
      await held.promise;
      calls.push("released");
    });
    await entered.promise;
    expect(
      await locks.request("scope", { ifAvailable: true }, (lock) => lock),
    ).toBeNull();
    const second = locks.request("scope", () => {
      calls.push("second");
    });
    const third = locks.request("scope", () => {
      calls.push("third");
    });
    await Promise.resolve();
    expect(calls).toEqual(["first"]);
    held.resolve();
    await Promise.all([first, second, third]);
    expect(calls).toEqual(["first", "released", "second", "third"]);

    await expect(
      locks.request("scope", () => {
        throw new Error("fixture failure");
      }),
    ).rejects.toThrow("fixture failure");
    expect(
      await locks.request("scope", { ifAvailable: true }, (lock) => lock?.mode),
    ).toBe("exclusive");
  });

  it("aborts queued requests without expiring an already granted lock, and exposes only Storage names", async () => {
    const locks = createTestLocks();
    const entered = deferred();
    const held = deferred();
    const ownerAbort = new AbortController();
    const first = locks.request("scope", { signal: ownerAbort.signal }, () => {
      entered.resolve();
      return held.promise;
    });
    await entered.promise;
    ownerAbort.abort();
    expect(
      await locks.request("scope", { ifAvailable: true }, (lock) => lock),
    ).toBeNull();
    const queuedAbort = new AbortController();
    const called = vi.fn();
    const queued = locks.request(
      "scope",
      { signal: queuedAbort.signal },
      called,
    );
    const rejected = expect(queued).rejects.toMatchObject({
      name: "AbortError",
    });
    queuedAbort.abort();
    await rejected;
    expect(called).not.toHaveBeenCalled();
    held.resolve();
    await first;

    const storage = createTestStorage();
    storage.setItem("a", "first");
    storage.setItem("b", "second");
    expect(Object.getOwnPropertyNames(storage)).toEqual(["a", "b"]);
    expect(Object.keys(storage)).toEqual(["a", "b"]);
    expect(Object.getOwnPropertyDescriptor(storage, "a")?.enumerable).toBe(
      true,
    );
    expect(storage.length).toBe(2);
    expect(storage.key(0)).toBe("a");
    storage.removeItem("a");
    expect(storage.key(0)).toBe("b");
    storage.clear();
    expect(Object.getOwnPropertyNames(storage)).toEqual([]);
  });
});

describe("bounded non-secret review journal", () => {
  it("does not create browser globals or silently fall back when the browser boundary is absent", async () => {
    expect(typeof window).toBe("undefined");
    const journal = browserJournal("nodes", codec);
    expect(journal.issue()).toBe("unsupported");
    expect(journal.load()).toEqual([]);
    expect(await journal.acquire(note(), current)).toBeNull();
    expect(await journal.clear("scope-a", uuid(1), current)).toBe(false);
  });

  it("persists only the exact envelope and keeps the scope held until an explicit release", async () => {
    const h = harness();
    const first = h.journal();
    const other = h.journal();
    const lease = await first.acquire(note(), current);
    if (!lease) throw new Error("expected journal lease");
    try {
      expect(lease.id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
      expect(
        JSON.parse(h.storage.getItem(storageKey(lease.key)) ?? "null"),
      ).toEqual(envelope(note(), lease.id));
      expect(other.load()).toEqual([
        { id: lease.id, key: "scope-a", value: note() },
      ]);
      expect(await other.acquire(note(), current)).toBeNull();
      expect(await other.clear(lease.key, lease.id, current)).toBe(false);
      expect(lease.persist(note("scope-a", "unknown"))).toBe(true);
      expect(lease.persist(note("scope-b"))).toBe(false);
      expect(other.load()[0]?.value.phase).toBe("unknown");
      // The registry lock must not be retained while the first request owns its
      // scope: an independent scope can still record its own intent.
      const independent = await other.acquire(note("scope-b"), current);
      if (!independent) throw new Error("independent scope was blocked");
      independent.release();
    } finally {
      lease.release();
      lease.release();
    }
    expect(lease.persist(note())).toBe(false);
    expect(lease.remove()).toBe(false);
    // Releasing ownership preserves unresolved history; it is not a receipt.
    expect(await other.acquire(note(), current)).toBeNull();
    expect(await other.clear(lease.key, lease.id, current)).toBe(true);
    const replacement = await other.acquire(note(), current);
    if (!replacement) throw new Error("cleared scope did not become available");
    expect(replacement.id).not.toBe(lease.id);
    replacement.release();
  });

  it("cancels a queued insertion before persistence and never treats current=false as authority to clear", async () => {
    const h = harness();
    const entered = deferred();
    const held = deferred();
    const registry = h.locks.request(`${JOURNAL_PREFIX}nodes.registry`, () => {
      entered.resolve();
      return held.promise;
    });
    await entered.promise;
    let active = true;
    const journal = h.journal();
    const pending = journal.acquire(note(), () => active);
    // The scope callback runs first and queues at the held registry. No wall
    // clock advancement, polling or timer expiry is needed for this race.
    await Promise.resolve();
    active = false;
    held.resolve();
    await registry;
    expect(await pending).toBeNull();
    expect(snapshot(h.storage)).toEqual({});
    expect(await journal.clear("scope-a", uuid(1), () => false)).toBe(false);
    expect(await journal.clear("scope-a", uuid(1), current)).toBe(true);
  });

  it("serializes the final capacity slot across instances and never evicts another unresolved note", async () => {
    const h = harness();
    for (let index = 0; index < 31; index++) {
      const value = note(`scope-${index}`);
      h.storage.setItem(
        storageKey(value.scope),
        JSON.stringify(envelope(value, uuid(index + 1))),
      );
    }
    const a = h.journal();
    const b = h.journal();
    const results = await Promise.all([
      a.acquire(note("last-a"), current),
      b.acquire(note("last-b"), current),
    ]);
    try {
      expect(results.filter(Boolean)).toHaveLength(1);
      expect(Object.getOwnPropertyNames(h.storage)).toHaveLength(32);
      expect([a.issue(), b.issue()]).toContain("capacity");
      expect(a.load()).toHaveLength(32);
      const routing = h.journal("routing");
      const separate = await routing.acquire(note("scope-0"), current);
      if (!separate) throw new Error("namespace capacity leaked");
      separate.release();
    } finally {
      results.forEach((lease) => lease?.release());
    }
  });

  it("rejects a whole malformed namespace without deleting or returning partial history", async () => {
    const original = envelope(note());
    const invalid = [
      "not-json",
      "x".repeat(4097),
      JSON.stringify({ ...original, version: 2 }),
      JSON.stringify({ ...original, id: "A".repeat(22) }),
      JSON.stringify({ ...original, secret: "must-not-enter-history" }),
      JSON.stringify({ ...original, key: "another-scope" }),
      JSON.stringify({
        ...original,
        value: { ...note(), secret: "not-accepted" },
      }),
    ];
    for (const raw of invalid) {
      const h = harness();
      h.storage.setItem(
        storageKey("valid"),
        JSON.stringify(envelope(note("valid"), uuid(2))),
      );
      h.storage.setItem(storageKey("scope-a"), raw);
      const before = snapshot(h.storage);
      const journal = h.journal();
      expect(journal.load()).toEqual([]);
      expect(journal.issue()).toBe("invalid");
      expect(await journal.acquire(note("new"), current)).toBeNull();
      expect(await journal.clear("scope-a", uuid(1), current)).toBe(false);
      expect(snapshot(h.storage)).toEqual(before);
    }
    for (const duplicate of ["id", "capacity"] as const) {
      const h = harness();
      for (let index = 0; index < (duplicate === "id" ? 2 : 33); index++) {
        const value = note(`scope-${index}`);
        h.storage.setItem(
          storageKey(value.scope),
          JSON.stringify(
            envelope(value, uuid(duplicate === "id" ? 1 : index + 1)),
          ),
        );
      }
      const before = snapshot(h.storage);
      const journal = h.journal();
      expect(journal.load()).toEqual([]);
      expect(journal.issue()).toBe("invalid");
      expect(snapshot(h.storage)).toEqual(before);
    }
  });

  it("does not skip a different unresolved name when a read races another scope's deletion", () => {
    const real = createTestStorage();
    for (let index = 0; index < 3; index++) {
      const value = note(`scope-${index}`);
      real.setItem(
        storageKey(value.scope),
        JSON.stringify(envelope(value, uuid(index + 1))),
      );
    }
    let deleted = false;
    const storage = new Proxy(real, {
      get(target, key) {
        if (key === "getItem")
          return (name: string) => {
            const raw = target.getItem(name);
            if (!deleted) {
              deleted = true;
              target.removeItem(name);
            }
            return raw;
          };
        return Reflect.get(target, key);
      },
    });
    const journal = harness(storage).journal();
    expect(journal.load().map((entry) => entry.key)).toEqual([
      "scope-0",
      "scope-1",
      "scope-2",
    ]);
    expect(journal.issue()).toBeNull();
    expect(real.getItem(storageKey("scope-1"))).not.toBeNull();

    const later = createTestStorage();
    for (let index = 0; index < 3; index++) {
      const value = note(`scope-${index}`);
      later.setItem(
        storageKey(value.scope),
        JSON.stringify(envelope(value, uuid(index + 1))),
      );
    }
    let removedFuture = false;
    const missing = new Proxy(later, {
      get(target, key) {
        if (key === "getItem")
          return (name: string) => {
            const raw = target.getItem(name);
            if (!removedFuture) {
              removedFuture = true;
              target.removeItem(storageKey("scope-1"));
            }
            return raw;
          };
        return Reflect.get(target, key);
      },
    });
    const reader = harness(missing).journal();
    // A real cross-tab deletion between names and getItem is not corruption or
    // a receipt for an old in-memory operation. This read simply omits the row.
    expect(reader.load().map((entry) => entry.key)).toEqual([
      "scope-0",
      "scope-2",
    ]);
    expect(reader.issue()).toBeNull();
  });

  it("enforces the library key bound even when a codec accepts the value", async () => {
    for (const key of ["", "scope/elsewhere", "x".repeat(161)]) {
      const h = harness();
      const journal = new ReviewJournal(
        "nodes",
        { ...codec, key: () => key },
        h.environment,
      );
      expect(await journal.acquire(note(), current)).toBeNull();
      expect(journal.issue()).toBe("invalid");
      expect(h.storage.length).toBe(0);
    }
  });

  it("preserves a newer exact ID and refuses an externally replaced or deleted lease", async () => {
    const h = harness();
    const journal = h.journal();
    const lease = await journal.acquire(note(), current);
    if (!lease) throw new Error("expected journal lease");
    const newer = JSON.stringify(
      envelope(note("scope-a", "unknown"), uuid(42)),
    );
    h.storage.setItem(storageKey(lease.key), newer);
    expect(lease.persist(note())).toBe(false);
    expect(lease.remove()).toBe(false);
    expect(journal.issue()).toBe("invalid");
    lease.release();
    // Wait for the callback-held native lock to finish rather than assuming a
    // void release() makes an ifAvailable request win in this same microtask.
    await h.locks.request(
      `${JOURNAL_PREFIX}nodes.scope:${lease.key}`,
      () => {},
    );
    const fresh = h.journal();
    expect(await fresh.clear(lease.key, lease.id, current)).toBe(false);
    expect(h.storage.getItem(storageKey(lease.key))).toBe(newer);
    expect(await fresh.clear(lease.key, uuid(42), current)).toBe(true);
    // Explicit acknowledgement may clear an already absent old note, but is
    // never permission for a stale lease to recreate it.
    expect(await fresh.clear(lease.key, lease.id, current)).toBe(true);
    expect(lease.persist(note())).toBe(false);
    const missing = await fresh.acquire(note("missing"), current);
    if (!missing) throw new Error("expected second lease");
    h.storage.removeItem(storageKey(missing.key));
    expect(missing.persist(note("missing"))).toBe(false);
    expect(missing.remove()).toBe(false);
    missing.release();
    expect(h.storage.getItem(storageKey(missing.key))).toBeNull();
  });

  it("fails closed on storage acquisition/enumeration/read/write failures without hiding a possibly persisted note", async () => {
    for (const failure of [
      "storage",
      "enumerate",
      "get",
      "set",
      "noop",
      "post-set",
    ] as const) {
      const real = createTestStorage();
      let wrote = false;
      const storage = new Proxy(real, {
        ownKeys(target) {
          if (failure === "enumerate") throw new Error("private fixture cause");
          return Reflect.ownKeys(target);
        },
        get(target, key) {
          if (key === "getItem")
            return (name: string) => {
              if (failure === "get" || (failure === "post-set" && wrote))
                throw new Error("private fixture cause");
              return target.getItem(name);
            };
          if (key === "setItem")
            return (name: string, value: string) => {
              if (failure === "set")
                throw new DOMException(
                  "private fixture cause",
                  "QuotaExceededError",
                );
              if (failure !== "noop") target.setItem(name, value);
              wrote = true;
            };
          return Reflect.get(target, key);
        },
      });
      const h = harness(storage);
      const environment = {
        ...h.environment,
        storage: () => {
          if (failure === "storage")
            throw new DOMException("private fixture cause", "SecurityError");
          return storage;
        },
      };
      const journal = new ReviewJournal("nodes", codec, environment);
      expect(await journal.acquire(note(), current)).toBeNull();
      expect(journal.issue()).toBe("unavailable");
      expect(journal.load()).toEqual([]);
      expect(real.length).toBe(failure === "post-set" ? 1 : 0);
      if (failure === "post-set")
        expect(harness(real).journal().load()).toHaveLength(1);
    }
  });

  it("does not report removal after a throw/no-op/post-remove read failure", async () => {
    for (const failure of ["remove", "noop", "post-remove"] as const) {
      const real = createTestStorage();
      real.setItem(storageKey("scope-a"), JSON.stringify(envelope(note())));
      let removed = false;
      const storage = new Proxy(real, {
        get(target, key) {
          if (key === "removeItem")
            return (name: string) => {
              if (failure === "remove")
                throw new Error("private fixture cause");
              if (failure !== "noop") target.removeItem(name);
              removed = true;
            };
          if (key === "getItem")
            return (name: string) => {
              if (failure === "post-remove" && removed)
                throw new Error("private fixture cause");
              return target.getItem(name);
            };
          return Reflect.get(target, key);
        },
      });
      const journal = harness(storage).journal();
      expect(await journal.clear("scope-a", uuid(1), current)).toBe(false);
      expect(journal.issue()).toBe("unavailable");
      expect(real.getItem(storageKey("scope-a")) === null).toBe(
        failure === "post-remove",
      );
    }
  });

  it("notifies external storage and issue changes, leaving successful own model publication to its caller", async () => {
    const h = harness();
    const journal = h.journal();
    const listener = vi.fn();
    const unsubscribe = journal.subscribe(listener);
    expect(h.listenerCount()).toBe(1);
    const lease = await journal.acquire(note(), current);
    if (!lease) throw new Error("expected journal lease");
    try {
      expect(lease.persist(note("scope-a", "unknown"))).toBe(true);
      await Promise.resolve();
      expect(listener).not.toHaveBeenCalled();
      h.changed();
      await Promise.resolve();
      expect(listener).toHaveBeenCalledTimes(1);
      h.storage.setItem(storageKey("malformed"), "not-json");
      expect(journal.load()).toEqual([]);
      await Promise.resolve();
      expect(listener).toHaveBeenCalledTimes(2);
      expect(journal.issue()).toBe("invalid");
    } finally {
      lease.release();
      unsubscribe();
    }
    expect(h.listenerCount()).toBe(0);
    h.changed();
    await Promise.resolve();
    expect(listener).toHaveBeenCalledTimes(2);
  });
});
