import { ApiError } from "../api/error";
import { canonicalId, canonicalRevision, shape } from "../api/proxy";
import { drainRequest, type DrainRequest } from "../api/runtime";
import { serviceOperation, type ServiceOperation } from "../api/proxyService";
import type { Owner, Target } from "../api/targets";
import type {
  JournalCodec,
  JournalFactory,
  JournalLease,
  ReviewJournal,
} from "./review-journal";

export type Scope = Readonly<{
  administratorId: string;
  nodeId: string;
}>;

export type Intent = Readonly<
  | { kind: "proxy-service"; operation: Readonly<ServiceOperation> }
  | {
      kind: "runtime-drain";
      targetId: string | null;
      targetRevision: string | null;
      request: Readonly<DrainRequest>;
    }
  | {
      kind: "target";
      action:
        "configure" | "register" | "pause" | "resume" | "reactivate" | "retire";
      targetId: string;
      expectedRevision: string | null;
    }
  | {
      kind: "owner";
      action: "grant" | "takeover";
      controllerId: string | null;
      expectedEpoch: string;
    }
  | {
      kind: "maintenance";
      targetId: string | null;
      accepting: boolean;
      expectedRevision: string;
      expectedEpoch: string;
      targetRevision: string | null;
      commandId: string | null;
      jobId: string | null;
    }
>;

/** An in-memory object identity, not a server operation ID or replay key. */
export type Token = object;

export type Observation = Readonly<{
  generation: number;
  owner: Readonly<Owner>;
  target: Readonly<Target> | null;
}>;

export type NodeChange = Readonly<{
  token: Token;
  scope: Scope;
  intent: Intent;
  phase: "pending" | "unknown" | "rejected";
  error: ApiError | null;
  observation: Observation | null;
  restored: boolean;
}>;

const MAX_SCOPES = 32;

type Note = Pick<NodeChange, "scope" | "intent" | "phase">;

const scopeKey = (scope: Scope): string =>
  `${scope.administratorId}:${scope.nodeId}`;

function copyIntent(intent: Intent): Intent {
  if (intent.kind === "proxy-service")
    return Object.freeze({
      kind: intent.kind,
      operation: Object.freeze(serviceOperation(intent.operation)),
    });
  if (intent.kind === "runtime-drain")
    return Object.freeze({
      kind: intent.kind,
      targetId: intent.targetId,
      targetRevision: intent.targetRevision,
      request: Object.freeze(drainRequest(intent.request)),
    });
  if (intent.kind === "maintenance")
    return Object.freeze({
      kind: intent.kind,
      targetId: intent.targetId,
      accepting: intent.accepting,
      expectedRevision: intent.expectedRevision,
      expectedEpoch: intent.expectedEpoch,
      targetRevision: intent.targetRevision,
      commandId: intent.commandId,
      jobId: intent.jobId,
    });
  return Object.freeze(
    intent.kind === "target"
      ? {
          kind: intent.kind,
          action: intent.action,
          targetId: intent.targetId,
          expectedRevision: intent.expectedRevision,
        }
      : {
          kind: intent.kind,
          action: intent.action,
          controllerId: intent.controllerId,
          expectedEpoch: intent.expectedEpoch,
        },
  );
}

/** Browser data is a reminder, not authority. Reject unknown fields rather
 * than retaining a form, response body, secret or old read observation. */
const codec: JournalCodec<Note> = {
  key: (value) => scopeKey(value.scope),
  decode(value) {
    try {
      shape(value, ["scope", "intent", "phase"]);
      shape(value.scope, ["administratorId", "nodeId"]);
      const phase = value.phase;
      if (
        !canonicalId(value.scope.administratorId) ||
        !canonicalId(value.scope.nodeId) ||
        (phase !== "pending" && phase !== "unknown" && phase !== "rejected")
      )
        return null;
      const intent = value.intent;
      if (typeof intent !== "object" || intent === null) return null;
      let decoded: Intent;
      if ("kind" in intent && intent.kind === "proxy-service") {
        shape(value.intent, ["kind", "operation"]);
        const operation = serviceOperation(value.intent.operation);
        if (operation.expected_node_id !== value.scope.nodeId) return null;
        decoded = Object.freeze({
          kind: "proxy-service",
          operation: Object.freeze(operation),
        });
      } else if ("kind" in intent && intent.kind === "runtime-drain") {
        shape(value.intent, ["kind", "targetId", "targetRevision", "request"]);
        const runtime = value.intent;
        const request = drainRequest(runtime.request);
        if (
          runtime.targetId === null
            ? runtime.targetRevision !== null ||
              request.expected_node_id !== value.scope.nodeId
            : !canonicalId(runtime.targetId) ||
              !canonicalRevision(runtime.targetRevision) ||
              runtime.targetId !== request.expected_node_id
        )
          return null;
        decoded = Object.freeze({
          kind: "runtime-drain",
          targetId: runtime.targetId as string | null,
          targetRevision: runtime.targetRevision as string | null,
          request: Object.freeze(request),
        });
      } else if ("kind" in intent && intent.kind === "target") {
        shape(value.intent, ["kind", "action", "targetId", "expectedRevision"]);
        const target = value.intent;
        const action = target.action;
        if (
          !canonicalId(target.targetId) ||
          (action !== "configure" &&
            action !== "register" &&
            action !== "pause" &&
            action !== "resume" &&
            action !== "reactivate" &&
            action !== "retire")
        )
          return null;
        let expectedRevision: string | null;
        if (action === "register") {
          if (target.expectedRevision !== null) return null;
          expectedRevision = null;
        } else {
          if (!canonicalRevision(target.expectedRevision)) return null;
          expectedRevision = target.expectedRevision;
        }
        decoded = Object.freeze({
          kind: "target",
          action,
          targetId: target.targetId,
          expectedRevision,
        });
      } else if ("kind" in intent && intent.kind === "maintenance") {
        shape(value.intent, [
          "kind",
          "targetId",
          "accepting",
          "expectedRevision",
          "expectedEpoch",
          "targetRevision",
          "commandId",
          "jobId",
        ]);
        const maintenance = value.intent;
        if (
          typeof maintenance.accepting !== "boolean" ||
          !canonicalRevision(maintenance.expectedRevision) ||
          !canonicalRevision(maintenance.expectedEpoch) ||
          !(maintenance.jobId === null || canonicalId(maintenance.jobId)) ||
          (maintenance.targetId === null
            ? maintenance.targetRevision !== null ||
              maintenance.commandId !== null ||
              maintenance.jobId !== null
            : !canonicalId(maintenance.targetId) ||
              !canonicalRevision(maintenance.targetRevision) ||
              !canonicalRevision(maintenance.commandId))
        )
          return null;
        decoded = Object.freeze({
          kind: "maintenance",
          targetId: maintenance.targetId as string | null,
          accepting: maintenance.accepting,
          expectedRevision: maintenance.expectedRevision,
          expectedEpoch: maintenance.expectedEpoch,
          targetRevision: maintenance.targetRevision as string | null,
          commandId: maintenance.commandId as string | null,
          jobId: maintenance.jobId as string | null,
        });
      } else {
        shape(value.intent, [
          "kind",
          "action",
          "controllerId",
          "expectedEpoch",
        ]);
        const owner = value.intent;
        if (owner.kind !== "owner" || !canonicalRevision(owner.expectedEpoch))
          return null;
        if (owner.action === "grant" && canonicalId(owner.controllerId)) {
          decoded = Object.freeze({
            kind: "owner",
            action: "grant",
            controllerId: owner.controllerId,
            expectedEpoch: owner.expectedEpoch,
          });
        } else if (owner.action === "takeover" && owner.controllerId === null) {
          decoded = Object.freeze({
            kind: "owner",
            action: "takeover",
            controllerId: null,
            expectedEpoch: owner.expectedEpoch,
          });
        } else return null;
      }
      return Object.freeze({
        scope: Object.freeze({
          administratorId: value.scope.administratorId,
          nodeId: value.scope.nodeId,
        }),
        intent: decoded,
        phase,
      });
    } catch {
      return null;
    }
  },
};

function sameScope(left: Scope, right: Scope): boolean {
  return (
    left.administratorId === right.administratorId &&
    left.nodeId === right.nodeId
  );
}

/** Only these request guards are known to reject before admitting the write. */
function rejectedBeforeWrite(error: ApiError): boolean {
  return (
    error.kind === "server" &&
    error.status === 403 &&
    (error.code === "invalid_origin" ||
      error.code === "invalid_csrf" ||
      error.code === "authentication_required")
  );
}

/** One bounded review fence per administrator and local node. Persistence is
 * optional for isolated model tests; production acquires a browser scope lease
 * before dispatch. Recovered notes never restore authorization or observations. */
export class NodeChanges {
  private records: readonly NodeChange[] = Object.freeze([]);
  private readonly listeners = new Set<() => void>();
  private readonly journal: ReviewJournal<Note> | null;
  private readonly leases = new Map<Token, JournalLease<Note>>();
  private readonly identities = new Map<Token, { id: string; key: string }>();
  private journalSubscription: (() => void) | null = null;

  constructor(factory?: JournalFactory) {
    this.journal = factory?.("nodes", codec) ?? null;
    this.restore();
  }

  readonly snapshot = (): readonly NodeChange[] => this.records;

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    if (this.journal && this.journalSubscription === null) {
      this.journalSubscription = this.journal.subscribe(() => {
        const previous = this.records;
        this.restore();
        if (this.records === previous) this.publish([...this.records]);
      });
    }
    return () => {
      this.listeners.delete(listener);
      if (this.listeners.size === 0) {
        this.journalSubscription?.();
        this.journalSubscription = null;
      }
    };
  };

  issue(): ReturnType<ReviewJournal<Note>["issue"]> {
    return this.journal?.issue() ?? null;
  }

  find(scope: Scope): NodeChange | null {
    return (
      this.records.find((record) => sameScope(record.scope, scope)) ?? null
    );
  }

  /** A full registry refuses a new scope; unresolved records are never evicted. */
  available(scope: Scope): boolean {
    return (
      this.issue() === null &&
      this.find(scope) === null &&
      this.records.length < MAX_SCOPES
    );
  }

  /** Reserve memory synchronously, then persist before the caller may dispatch.
   * The current guard is rechecked by the journal after waiting for a lock. */
  async begin(
    scope: Scope,
    intent: Intent,
    current = () => true,
  ): Promise<Token | null> {
    if (!current() || !this.available(scope)) return null;
    const token = Object.freeze({});
    const record: NodeChange = Object.freeze({
      token,
      scope: Object.freeze({
        administratorId: scope.administratorId,
        nodeId: scope.nodeId,
      }),
      intent: copyIntent(intent),
      phase: "pending",
      error: null,
      observation: null,
      restored: false,
    });
    this.publish([...this.records, record]);
    if (this.journal) {
      const lease = await this.journal.acquire(this.note(record), current);
      if (!lease) {
        this.update(token, () => null);
        this.restore();
        this.listeners.forEach((listener) => listener());
        return null;
      }
      this.leases.set(token, lease);
      this.identities.set(token, { id: lease.id, key: lease.key });
      if (!current()) {
        this.notStarted(token);
        this.release(token);
        return null;
      }
    }
    return token;
  }

  /** A late success cannot erase a record already classified as uncertain. */
  succeed(token: Token): boolean {
    return this.finish(token);
  }

  fail(token: Token, error: ApiError): boolean {
    return this.update(token, (record) => {
      if (record.phase !== "pending") return record;
      const next: NodeChange = {
        ...record,
        phase: rejectedBeforeWrite(error) ? "rejected" : "unknown",
        error: Object.freeze(
          new ApiError(error.kind, error.code, error.status),
        ),
        observation: null,
      };
      if (this.journal && !this.leases.get(token)?.persist(this.note(next))) {
        return { ...next, phase: "unknown" };
      }
      return next;
    });
  }

  /** Retain the first delivery's exact non-secret ticket. A later current-slot
   * read cannot assign an unknown request a different command identity. */
  maintenanceTicket(token: Token, id: string): boolean {
    if (!canonicalId(id)) return false;
    return this.update(token, (record) => {
      if (
        record.phase !== "pending" ||
        record.intent.kind !== "maintenance" ||
        record.intent.targetId === null
      )
        return record;
      const next: NodeChange = {
        ...record,
        phase: "unknown",
        intent: copyIntent({ ...record.intent, jobId: id }),
        observation: null,
      };
      if (this.journal && !this.leases.get(token)?.persist(this.note(next)))
        return { ...record, phase: "unknown", observation: null };
      return next;
    });
  }

  /** A 202 retains the exact non-secret request, not proof that drain finished. */
  runtimeAccepted(token: Token): boolean {
    return this.accepted(token, "runtime-drain");
  }

  serviceAccepted(token: Token): boolean {
    return this.accepted(token, "proxy-service");
  }

  private accepted(
    token: Token,
    kind: "runtime-drain" | "proxy-service",
  ): boolean {
    return this.update(token, (record) => {
      if (record.phase !== "pending" || record.intent.kind !== kind)
        return record;
      const next: NodeChange = {
        ...record,
        phase: "unknown",
        observation: null,
      };
      if (this.journal && !this.leases.get(token)?.persist(this.note(next)))
        return { ...next, phase: "unknown" };
      return next;
    });
  }

  /** Call only when the actual work callback was never entered. Cancellation
   * after dispatch is not proof of this and must use fail instead. */
  notStarted(token: Token): boolean {
    return this.finish(token);
  }

  /** Abort does not finish an admitted callback. Hold the lease until its
   * actual owner reaches finally, including a transport which ignores abort. */
  release(token: Token): void {
    const lease = this.leases.get(token);
    this.leases.delete(token);
    lease?.release();
  }

  /** The caller must supply a fresh, identity-checked read, never a list row
   * inferred to prove the earlier request's outcome or ownership. */
  observe(token: Token, observation: Observation): boolean {
    return this.update(token, (record) =>
      record.phase === "pending"
        ? record
        : {
            ...record,
            observation: Object.freeze({
              generation: observation.generation,
              owner: Object.freeze({ ...observation.owner }),
              target:
                observation.target === null
                  ? null
                  : Object.freeze({ ...observation.target }),
            }),
          },
    );
  }

  invalidateObservation(token: Token): boolean {
    return this.update(token, (record) =>
      record.observation === null ? record : { ...record, observation: null },
    );
  }

  /** Explicit acknowledgement permits a new intent, never a replay. A caller
   * in another generation must first obtain its own fresh observation. */
  async continue(
    token: Token,
    generation: number,
    current = () => true,
  ): Promise<boolean> {
    const record = this.records.find((record) => record.token === token);
    if (
      !record ||
      record.phase === "pending" ||
      record.observation?.generation !== generation ||
      !current()
    )
      return false;
    const observation = record.observation;
    const valid = () =>
      current() &&
      this.records.find((item) => item.token === token)?.observation ===
        observation;
    if (this.journal) {
      const identity = this.identities.get(token);
      if (
        !identity ||
        this.leases.has(token) ||
        !(await this.journal.clear(identity.key, identity.id, valid))
      )
        return false;
    }
    if (!valid()) return false;
    return this.update(token, () => null);
  }

  private note(record: NodeChange): Note {
    return { scope: record.scope, intent: record.intent, phase: record.phase };
  }

  private finish(token: Token): boolean {
    const record = this.records.find((record) => record.token === token);
    if (!record || record.phase !== "pending") return false;
    if (this.journal && !this.leases.get(token)?.remove()) {
      this.update(token, (value) => ({
        ...value,
        phase: "unknown",
        observation: null,
      }));
      return false;
    }
    return this.update(token, () => null);
  }

  private restore(): void {
    if (!this.journal) return;
    const records = [...this.records];
    for (const stored of this.journal.load()) {
      // Keep local tokens and leases, even when another tab removes or replaces
      // its disk entry. Missing data never acknowledges an uncertain request.
      if (records.some((record) => sameScope(record.scope, stored.value.scope)))
        continue;
      // Other tabs may explicitly clear disk notes while this tab still keeps
      // their uncertain outcomes. Do not evict those fences or grow on each
      // replacement batch; omitted disk notes remain guarded by the journal.
      if (records.length >= MAX_SCOPES) break;
      const token = Object.freeze({});
      this.identities.set(token, { id: stored.id, key: stored.key });
      records.push(
        Object.freeze({
          token,
          scope: stored.value.scope,
          intent: stored.value.intent,
          phase: "unknown",
          error: null,
          observation: null,
          restored: true,
        }),
      );
    }
    if (records.length !== this.records.length) this.publish(records);
  }

  private update(
    token: Token,
    change: (record: NodeChange) => NodeChange | null,
  ): boolean {
    const index = this.records.findIndex((record) => record.token === token);
    if (index < 0) return false;
    const previous = this.records[index];
    const next = change(previous);
    if (next === previous) return false;
    const records = [...this.records];
    if (next === null) {
      records.splice(index, 1);
      this.identities.delete(token);
    } else records[index] = Object.freeze(next);
    this.publish(records);
    // An explicit acknowledgement or known local completion can free a slot.
    // Recover any omitted disk entry as a fresh unknown token, never as the
    // removed token's observation or permission to replay an earlier request.
    if (next === null) this.restore();
    return true;
  }

  private publish(records: NodeChange[]): void {
    this.records = Object.freeze(records);
    this.listeners.forEach((listener) => listener());
  }
}
