import { canonicalId, canonicalRevision, shape } from "../api/proxy";
import type {
  JournalFactory,
  JournalLease,
  ReviewJournal,
} from "./review-journal";

/** Original non-secret assertions only. Restoring a note never sends an acknowledgement. */
export interface AckIntent {
  administratorId: string;
  nodeId: string;
  episodeId: string;
  transitionSequence: string;
}
export interface AckReview {
  token: object;
  intent: Readonly<AckIntent>;
  phase: "pending" | "unknown";
}
type Note = Pick<AckReview, "intent" | "phase">;
const LIMIT = 32;
const key = (intent: AckIntent) =>
  `${intent.administratorId}:${intent.nodeId}:${intent.episodeId}`;
const codec = {
  key: (value: Note) => key(value.intent),
  decode(value: unknown): Note | null {
    try {
      shape(value, ["intent", "phase"]);
      shape(value.intent, [
        "administratorId",
        "nodeId",
        "episodeId",
        "transitionSequence",
      ]);
      if (
        !canonicalId(value.intent.administratorId) ||
        !canonicalId(value.intent.nodeId) ||
        !canonicalRevision(value.intent.episodeId) ||
        !canonicalRevision(value.intent.transitionSequence) ||
        BigInt(value.intent.episodeId) >
          BigInt(value.intent.transitionSequence) ||
        !["pending", "unknown"].includes(value.phase as string)
      )
        return null;
      return {
        intent: Object.freeze({ ...value.intent }) as unknown as AckIntent,
        phase: value.phase as Note["phase"],
      };
    } catch {
      return null;
    }
  },
};

/** Independent review fences keep an unknown acknowledgement from locking node
 * configuration. The generic journal owns storage/Web Locks and their bounds. */
export class AlertAcknowledgements {
  private records: readonly AckReview[] = Object.freeze([]);
  private readonly listeners = new Set<() => void>();
  private readonly journal: ReviewJournal<Note> | null;
  private readonly leases = new Map<object, JournalLease<Note>>();
  private readonly identities = new Map<object, { id: string; key: string }>();
  private detach: (() => void) | null = null;
  constructor(factory?: JournalFactory) {
    this.journal = factory?.("alerts", codec) ?? null;
    this.restore();
  }
  readonly snapshot = () => this.records;
  readonly subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    if (this.journal && !this.detach)
      this.detach = this.journal.subscribe(() => {
        const previous = this.records;
        this.restore();
        if (this.records === previous) this.publish([...previous]);
      });
    return () => {
      this.listeners.delete(listener);
      if (!this.listeners.size) {
        this.detach?.();
        this.detach = null;
      }
    };
  };
  issue() {
    return this.journal?.issue() ?? null;
  }
  find(intent: Pick<AckIntent, "administratorId" | "nodeId" | "episodeId">) {
    return (
      this.records.find(
        (row) =>
          row.intent.administratorId === intent.administratorId &&
          row.intent.nodeId === intent.nodeId &&
          row.intent.episodeId === intent.episodeId,
      ) ?? null
    );
  }
  async begin(
    intent: AckIntent,
    current: () => boolean,
  ): Promise<object | null> {
    const note = codec.decode({ intent, phase: "pending" });
    if (
      !note ||
      !current() ||
      this.issue() ||
      this.find(intent) ||
      this.records.length >= LIMIT
    )
      return null;
    const token = Object.freeze({}),
      record: AckReview = Object.freeze({ token, ...note });
    this.publish([...this.records, record]);
    if (this.journal) {
      const lease = await this.journal.acquire(note, current);
      if (!lease) {
        this.remove(token);
        this.restore();
        return null;
      }
      this.leases.set(token, lease);
      this.identities.set(token, { id: lease.id, key: lease.key });
      if (!current()) {
        this.complete(token);
        this.release(token);
        return null;
      }
    }
    return token;
  }
  unknown(token: object): void {
    const record = this.records.find((row) => row.token === token);
    if (!record || record.phase === "unknown") return;
    const next = Object.freeze({ ...record, phase: "unknown" as const });
    // A failed update must retain the in-memory fence; the original write-ahead
    // pending note also restores as unknown if the browser is refreshed.
    this.leases.get(token)?.persist({ intent: next.intent, phase: "unknown" });
    this.publish(this.records.map((row) => (row.token === token ? next : row)));
  }
  /** Only an actual successful response or a callback never entered may finish
   * the pending owner synchronously. Unknown outcomes require explicit review. */
  complete(token: object): boolean {
    const record = this.records.find((row) => row.token === token);
    if (!record || record.phase !== "pending") return false;
    if (this.journal && !this.leases.get(token)?.remove()) {
      this.unknown(token);
      return false;
    }
    return this.remove(token);
  }
  release(token: object): void {
    const lease = this.leases.get(token);
    this.leases.delete(token);
    lease?.release();
  }
  /** The caller binds an explicit decision to its same fresh exact-ID read.
   * Clearing this browser reminder never means the remote state was repaired. */
  async reviewed(token: object, current: () => boolean): Promise<boolean> {
    const record = this.records.find((row) => row.token === token);
    const valid = () =>
      current() && this.records.find((row) => row.token === token) === record;
    if (
      !record ||
      record.phase !== "unknown" ||
      this.leases.has(token) ||
      !valid()
    )
      return false;
    if (this.journal) {
      const identity = this.identities.get(token);
      if (
        !identity ||
        !(await this.journal.clear(identity.key, identity.id, valid))
      )
        return false;
    }
    return valid() && this.remove(token);
  }
  private restore(): void {
    if (!this.journal) return;
    const restored = [...this.records];
    for (const entry of this.journal.load()) {
      if (
        restored.some((row) => key(row.intent) === entry.key) ||
        restored.length >= LIMIT
      )
        continue;
      const record: AckReview = Object.freeze({
        token: Object.freeze({}),
        intent: Object.freeze({ ...entry.value.intent }),
        phase: "unknown",
      });
      restored.push(record);
      this.identities.set(record.token, { id: entry.id, key: entry.key });
    }
    if (restored.length !== this.records.length) this.publish(restored);
  }
  private remove(token: object): boolean {
    if (!this.records.some((row) => row.token === token)) return false;
    this.identities.delete(token);
    this.publish(this.records.filter((row) => row.token !== token));
    this.restore();
    return true;
  }
  private publish(records: readonly AckReview[]): void {
    this.records = Object.freeze(records);
    this.listeners.forEach((listener) => listener());
  }
}
