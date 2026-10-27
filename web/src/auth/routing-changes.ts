import { ApiError } from "../api/error";
import type { PresetReference } from "../api/presets";
import type { RoutingReference } from "../api/routing";
import type { Job, PolicyJob } from "../api/targets";
import { canonicalId, canonicalRevision } from "../api/proxy";
import type {
  JournalCodec,
  JournalFactory,
  JournalLease,
  ReviewJournal,
} from "./review-journal";

export type Scope = Readonly<{
  administratorId: string;
  nodeId: string;
  peer: string | null;
}>;

export type Intent = Readonly<{
  action:
    | "create"
    | "retire"
    | "drain"
    | "resume"
    | "add_member"
    | "remove_member"
    | "set_preset";
  kind: "prefixes" | "addresses" | "pools" | "pool_preset";
  resourceId: string | null;
  memberId: string | null;
  expectedRevision: string;
  targetRevision: string | null;
  controllerId: string | null;
  controllerEpoch: string | null;
  commandId: string | null;
}>;

/** Object identity only; it is neither a durable operation ID nor a replay key. */
export type Token = object;

type JobFields = Pick<
  Job,
  | "node_id"
  | "job_id"
  | "controller_epoch"
  | "command_id"
  | "expected_policy_revision"
  | "state"
  | "policy_revision"
>;

export type ObservedJob = Readonly<
  JobFields & {
    resource?: "proxy_endpoints";
    routing?: Readonly<RoutingReference>;
    preset?: Readonly<PresetReference>;
    maintenance?: Readonly<{ accepting: boolean }>;
  }
>;

export type TicketMetadata = Readonly<
  Pick<PolicyJob, keyof JobFields> & {
    routing?: Readonly<RoutingReference>;
    preset?: Readonly<PresetReference>;
  }
>;

export type Observation = Readonly<{
  generation: number;
  policyRevision: string;
  controllerId: string | null;
  controllerEpoch: string;
  lastTerminalCommand: string;
  targetRevision: string | null;
  writable: boolean;
  job: ObservedJob | null;
}>;

export type RoutingChange = Readonly<{
  token: Token;
  scope: Scope;
  intent: Intent;
  phase: "pending" | "unknown" | "rejected" | "waiting";
  error: ApiError | null;
  ticket: TicketMetadata | null;
  observation: Observation | null;
  /** A persisted ticket is an untrusted hint, never permission to retry it. */
  restored?: true;
}>;

const MAX_SCOPES = 32;

const sameScope = (left: Scope, right: Scope): boolean =>
  left.administratorId === right.administratorId &&
  left.nodeId === right.nodeId &&
  left.peer === right.peer;

const pending = (job: Pick<Job, "state"> | null): boolean =>
  job?.state === "pending" || job?.state === "blocked";

/** Select only non-secret fields, including references without response bodies. */
export function observedJob(value: Job | null): ObservedJob | null {
  if (value === null) return null;
  return copyJob(value);
}

function copyJob(value: ObservedJob): ObservedJob {
  return Object.freeze({
    node_id: value.node_id,
    job_id: value.job_id,
    controller_epoch: value.controller_epoch,
    command_id: value.command_id,
    expected_policy_revision: value.expected_policy_revision,
    state: value.state,
    policy_revision: value.policy_revision,
    ...(value.resource !== undefined ? { resource: value.resource } : {}),
    ...(value.maintenance !== undefined
      ? {
          maintenance: Object.freeze({
            accepting: value.maintenance.accepting,
          }),
        }
      : {}),
    ...(value.routing
      ? {
          routing: Object.freeze({
            kind: value.routing.kind,
            id: value.routing.id,
          }),
        }
      : {}),
    ...(value.preset
      ? {
          preset: Object.freeze({
            kind: value.preset.kind,
            id: value.preset.id,
          }),
        }
      : {}),
  });
}

/** Input has already passed the API's typed Job validator. Endpoint jobs and
 * user creation cannot be claimed as resource mutations. */
export function ticketMetadata(value: Job | null): TicketMetadata | null {
  if (
    value === null ||
    value.resource !== undefined ||
    value.user_creation === true ||
    value.maintenance !== undefined
  )
    return null;
  return Object.freeze({
    node_id: value.node_id,
    job_id: value.job_id,
    controller_epoch: value.controller_epoch,
    command_id: value.command_id,
    expected_policy_revision: value.expected_policy_revision,
    state: value.state,
    policy_revision: value.policy_revision,
    ...(value.routing
      ? {
          routing: Object.freeze({
            kind: value.routing.kind,
            id: value.routing.id,
          }),
        }
      : {}),
    ...(value.preset
      ? {
          preset: Object.freeze({
            kind: value.preset.kind,
            id: value.preset.id,
          }),
        }
      : {}),
  });
}

function matchesIntent(record: RoutingChange, job: PolicyJob): boolean {
  const { scope, intent } = record;
  if (
    scope.peer === null ||
    job.node_id !== scope.peer ||
    job.user_creation === true ||
    job.maintenance !== undefined ||
    job.controller_epoch !== intent.controllerEpoch ||
    job.command_id !== intent.commandId ||
    job.expected_policy_revision !== intent.expectedRevision
  )
    return false;
  if (intent.kind === "pool_preset")
    return (
      intent.action === "set_preset" &&
      intent.resourceId !== null &&
      job.routing === undefined &&
      (job.preset === undefined ||
        (job.preset.kind === "pool" && job.preset.id === intent.resourceId))
    );
  if (
    job.preset !== undefined ||
    intent.action === "set_preset" ||
    (intent.kind === "prefixes" &&
      intent.action !== "create" &&
      intent.action !== "retire") ||
    ((intent.action === "add_member" || intent.action === "remove_member") &&
      (intent.kind !== "pools" || intent.memberId === null)) ||
    (intent.action !== "create" && intent.resourceId === null)
  )
    return false;
  const kind =
    intent.kind === "prefixes"
      ? "prefix"
      : intent.kind === "addresses"
        ? "address"
        : "pool";
  // Pending and rejected jobs may have no entity reference. A reference that
  // does exist must agree with the original kind and known subject. Membership
  // tickets identify the pool, not proof of a particular member's final state.
  return (
    job.routing === undefined ||
    (job.routing.kind === kind &&
      (intent.resourceId === null || job.routing.id === intent.resourceId))
  );
}

/** Check the retained identity, not just job_id. A pending ticket may gain its
 * first entity reference; an already known subject cannot be replaced. State
 * changes are observations of this ticket, not evidence of a new intent. */
export function matchesTicket(
  ticket: TicketMetadata,
  current: Job | null,
): boolean {
  return (
    current !== null &&
    current.resource === undefined &&
    current.user_creation !== true &&
    current.maintenance === undefined &&
    current.node_id === ticket.node_id &&
    current.job_id === ticket.job_id &&
    current.controller_epoch === ticket.controller_epoch &&
    current.command_id === ticket.command_id &&
    current.expected_policy_revision === ticket.expected_policy_revision &&
    (ticket.routing === undefined ||
      (current.routing?.kind === ticket.routing.kind &&
        current.routing.id === ticket.routing.id)) &&
    (ticket.preset === undefined ||
      (current.preset?.kind === ticket.preset.kind &&
        current.preset.id === ticket.preset.id))
  );
}

/** Run before a ticket action as well as after a read. A different current job
 * is display-only; matching an ID alone never adopts it as this request. */
export function knownTicket(
  record: RoutingChange,
  current: Job | null,
): boolean {
  return (
    record.restored !== true &&
    record.ticket !== null &&
    matchesTicket(record.ticket, current) &&
    current !== null &&
    current.resource === undefined &&
    matchesIntent(record, current)
  );
}

/** Only bounded public identities survive a reload; observations and API errors
 * belong to the live request and must never be restored as write authority. */
type StoredChange = Readonly<{
  scope: Scope;
  intent: Intent;
  phase: RoutingChange["phase"];
  ticket: TicketMetadata | null;
}>;

function object(
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

const nullableId = (value: unknown): value is string | null =>
  value === null || canonicalId(value);
const nullableRevision = (value: unknown): value is string | null =>
  value === null || canonicalRevision(value);

function scopeKey(scope: Scope): string {
  return `${scope.administratorId}:${scope.nodeId}:${scope.peer ?? "local"}`;
}

function stored(record: RoutingChange): StoredChange {
  return {
    scope: record.scope,
    intent: record.intent,
    phase: record.phase,
    ticket: record.ticket,
  };
}

function decodeStored(value: unknown): StoredChange | null {
  if (!object(value, ["scope", "intent", "phase", "ticket"])) return null;
  const { scope, intent, ticket } = value;
  if (
    !object(scope, ["administratorId", "nodeId", "peer"]) ||
    !canonicalId(scope.administratorId) ||
    !canonicalId(scope.nodeId) ||
    !nullableId(scope.peer) ||
    !object(intent, [
      "action",
      "kind",
      "resourceId",
      "memberId",
      "expectedRevision",
      "targetRevision",
      "controllerId",
      "controllerEpoch",
      "commandId",
    ]) ||
    ![
      "create",
      "retire",
      "drain",
      "resume",
      "add_member",
      "remove_member",
      "set_preset",
    ].includes(intent.action as string) ||
    !["prefixes", "addresses", "pools", "pool_preset"].includes(
      intent.kind as string,
    ) ||
    !nullableId(intent.resourceId) ||
    !nullableId(intent.memberId) ||
    !canonicalRevision(intent.expectedRevision) ||
    !nullableRevision(intent.targetRevision) ||
    !nullableId(intent.controllerId) ||
    !canonicalRevision(intent.controllerEpoch) ||
    !nullableRevision(intent.commandId) ||
    !["pending", "unknown", "rejected", "waiting"].includes(
      value.phase as string,
    )
  )
    return null;
  if (
    scope.peer === null
      ? intent.targetRevision !== null ||
        intent.commandId !== null ||
        intent.controllerId !== null
      : !canonicalRevision(intent.targetRevision) ||
        !canonicalRevision(intent.commandId) ||
        intent.controllerId !== scope.nodeId
  )
    return null;
  if (intent.kind === "pool_preset") {
    if (
      intent.action !== "set_preset" ||
      intent.resourceId === null ||
      intent.memberId !== null
    )
      return null;
  } else if (
    intent.action === "set_preset" ||
    (intent.kind === "prefixes" &&
      intent.action !== "create" &&
      intent.action !== "retire") ||
    (intent.action === "create"
      ? intent.resourceId !== null
      : intent.resourceId === null) ||
    (["add_member", "remove_member"].includes(intent.action as string)
      ? intent.kind !== "pools" || intent.memberId === null
      : intent.memberId !== null)
  )
    return null;
  let checkedTicket: TicketMetadata | null = null;
  if (ticket !== null) {
    if (typeof ticket !== "object" || Array.isArray(ticket)) return null;
    const raw = ticket as Record<string, unknown>;
    const keys = [
      "node_id",
      "job_id",
      "controller_epoch",
      "command_id",
      "expected_policy_revision",
      "state",
      "policy_revision",
    ];
    if (Object.hasOwn(raw, "routing")) keys.push("routing");
    if (Object.hasOwn(raw, "preset")) keys.push("preset");
    if (
      !object(raw, keys) ||
      !canonicalId(raw.node_id) ||
      !canonicalId(raw.job_id) ||
      !canonicalRevision(raw.controller_epoch) ||
      !canonicalRevision(raw.command_id) ||
      !canonicalRevision(raw.expected_policy_revision) ||
      !nullableRevision(raw.policy_revision) ||
      ![
        "pending",
        "blocked",
        "saved",
        "applied",
        "rejected",
        "superseded",
      ].includes(raw.state as string) ||
      (raw.state === "saved" || raw.state === "applied") !==
        (raw.policy_revision !== null)
    )
      return null;
    if (
      raw.policy_revision !== null &&
      BigInt(raw.policy_revision as string) !==
        BigInt(raw.expected_policy_revision as string) + 1n
    )
      return null;
    if (
      raw.routing !== undefined &&
      (!object(raw.routing, ["kind", "id"]) ||
        !["prefix", "address", "pool"].includes(raw.routing.kind as string) ||
        !canonicalId(raw.routing.id))
    )
      return null;
    if (
      raw.preset !== undefined &&
      (!object(raw.preset, ["kind", "id"]) ||
        raw.preset.kind !== "pool" ||
        !canonicalId(raw.preset.id))
    )
      return null;
    checkedTicket = copyJob(raw as unknown as TicketMetadata) as TicketMetadata;
    const record = { scope, intent } as unknown as RoutingChange;
    if (!matchesIntent(record, checkedTicket as PolicyJob)) return null;
  }
  return {
    scope: Object.freeze({ ...scope }) as Scope,
    intent: Object.freeze({ ...intent }) as Intent,
    phase: value.phase as RoutingChange["phase"],
    ticket: checkedTicket,
  };
}

const codec: JournalCodec<StoredChange> = {
  decode: decodeStored,
  key: (value) => scopeKey(value.scope),
};

/** One runtime owner per administrator/local node/target, optionally backed by
 * a non-secret browser journal. Tabs and pool presets share the same scope.
 * A browser note is not a server receipt: no payload, replay or authorization
 * survives a reload, and new work still requires explicit fresh review. */
export class RoutingChanges {
  private records: readonly RoutingChange[] = Object.freeze([]);
  private readonly listeners = new Set<() => void>();
  private readonly journal: ReviewJournal<StoredChange> | null;
  private readonly leases = new Map<Token, JournalLease<StoredChange>>();
  private readonly notes = new Map<Token, { id: string; key: string }>();
  private readonly acquiring = new Set<Token>();
  private unsubscribeJournal: (() => void) | null = null;

  constructor(factory?: JournalFactory) {
    this.journal = factory?.("routing", codec) ?? null;
    this.restore();
  }

  issue(): ReturnType<ReviewJournal<StoredChange>["issue"]> {
    return this.journal?.issue() ?? null;
  }

  readonly snapshot = (): readonly RoutingChange[] => this.records;

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    if (this.journal && this.unsubscribeJournal === null) {
      this.unsubscribeJournal = this.journal.subscribe(() => this.restore());
      this.restore();
    }
    return () => {
      this.listeners.delete(listener);
      if (this.listeners.size === 0) {
        this.unsubscribeJournal?.();
        this.unsubscribeJournal = null;
      }
    };
  };

  find(scope: Scope): RoutingChange | null {
    return (
      this.records.find((record) => sameScope(record.scope, scope)) ?? null
    );
  }

  /** Capacity exhaustion refuses new work without evicting unresolved scopes. */
  available(scope: Scope): boolean {
    return (
      this.issue() === null &&
      this.find(scope) === null &&
      this.records.length < MAX_SCOPES
    );
  }

  /** Claim synchronously before dispatch or the caller's first await. The node
   * identity and current write context must already have been verified. */
  async begin(
    scope: Scope,
    intent: Intent,
    current: () => boolean = () => true,
  ): Promise<Token | null> {
    if (!this.available(scope)) return null;
    const token = Object.freeze({});
    this.publish([
      ...this.records,
      Object.freeze({
        token,
        scope: Object.freeze({
          administratorId: scope.administratorId,
          nodeId: scope.nodeId,
          peer: scope.peer,
        }),
        intent: Object.freeze({
          action: intent.action,
          kind: intent.kind,
          resourceId: intent.resourceId,
          memberId: intent.memberId,
          expectedRevision: intent.expectedRevision,
          targetRevision: intent.targetRevision,
          controllerId: intent.controllerId,
          controllerEpoch: intent.controllerEpoch,
          commandId: intent.commandId,
        }),
        phase: "pending",
        error: null,
        ticket: null,
        observation: null,
      }),
    ]);
    if (!this.journal) return token;
    this.acquiring.add(token);
    const record = this.find(scope)!;
    try {
      const lease = await this.journal.acquire(
        stored(record),
        () => current() && this.find(scope)?.token === token,
      );
      if (!lease) {
        this.publish(this.records.filter((value) => value.token !== token));
        return null;
      }
      this.notes.set(token, { id: lease.id, key: lease.key });
      this.leases.set(token, lease);
      if (!current() || this.find(scope)?.token !== token) {
        this.notStarted(token);
        this.release(token);
        return null;
      }
      return token;
    } finally {
      this.acquiring.delete(token);
      this.restore();
    }
  }

  /** The actual request owns the scope lease until its final cleanup, even
   * after cancellation has already changed the visible result to unknown. */
  release(token: Token): void {
    this.leases.get(token)?.release();
    this.leases.delete(token);
    this.restore();
  }

  /** A late reply cannot clear unknown or waiting work. Accepted nonterminal
   * jobs stay fenced until a fresh review and explicit acknowledgement. */
  succeed(token: Token): boolean {
    return this.update(token, (record) =>
      record.phase !== "pending"
        ? record
        : pending(record.ticket)
          ? { ...record, phase: "waiting", observation: null }
          : null,
    );
  }

  fail(token: Token, error: ApiError): boolean {
    return this.update(token, (record) => {
      if (record.phase !== "pending") return record;
      const rejected =
        error.kind === "server" &&
        error.status === 403 &&
        ["invalid_origin", "invalid_csrf", "authentication_required"].includes(
          error.code ?? "",
        );
      return {
        ...record,
        phase: rejected ? "rejected" : "unknown",
        error: Object.freeze(
          new ApiError(error.kind, error.code, error.status),
        ),
        observation: null,
      };
    });
  }

  /** Only a callback that was never entered may report not-started. An
   * admitted request, including one later cancelled, must use fail instead. */
  notStarted(token: Token): boolean {
    return this.update(token, (record) =>
      record.phase === "pending" && record.ticket === null ? null : record,
    );
  }

  /** Retain only an intent-correlated validated ticket. A late ticket can add
   * evidence to unknown work but cannot clear it or replace an earlier ticket. */
  captureTicket(token: Token, current: Job): boolean {
    return this.update(token, (record) => {
      const ticket = ticketMetadata(current);
      if (
        record.restored === true ||
        record.phase === "rejected" ||
        ticket === null ||
        current.resource !== undefined ||
        !matchesIntent(record, current) ||
        (record.ticket !== null && !matchesTicket(record.ticket, current))
      )
        return record;
      return { ...record, ticket, observation: null };
    });
  }

  wait(token: Token): boolean {
    return this.update(token, (record) =>
      record.phase === "pending"
        ? { ...record, phase: "waiting", observation: null }
        : record,
    );
  }

  /** Supply a fresh identity-checked read, including the current job. Reading
   * a different job never attributes its outcome to the retained ticket. */
  observe(token: Token, observation: Observation): boolean {
    return this.update(
      token,
      (record) =>
        record.phase === "pending"
          ? record
          : {
              ...record,
              observation: Object.freeze({
                generation: observation.generation,
                policyRevision: observation.policyRevision,
                controllerId: observation.controllerId,
                controllerEpoch: observation.controllerEpoch,
                lastTerminalCommand: observation.lastTerminalCommand,
                targetRevision: observation.targetRevision,
                writable: observation.writable,
                job: observation.job === null ? null : copyJob(observation.job),
              }),
            },
      false,
    );
  }

  invalidateObservation(token: Token): boolean {
    return this.update(
      token,
      (record) =>
        record.observation === null ? record : { ...record, observation: null },
      false,
    );
  }

  /** Acknowledge a reviewed scope to start new work; this never declares the
   * old write successful or replays it. Other current work must finish first. */
  async continue(
    token: Token,
    generation: number,
    current: () => boolean = () => true,
  ): Promise<boolean> {
    const ready = (record: RoutingChange) =>
      current() &&
      record.phase !== "pending" &&
      record.observation !== null &&
      record.observation.generation === generation &&
      record.observation.writable &&
      !pending(record.observation.job);
    const record = this.records.find((value) => value.token === token);
    if (
      !record ||
      !ready(record) ||
      this.leases.has(token) ||
      this.acquiring.has(token)
    )
      return false;
    const observation = record.observation;
    const valid = () => {
      const actual = this.records.find((value) => value.token === token);
      return (
        actual !== undefined &&
        actual.observation === observation &&
        ready(actual)
      );
    };
    const note = this.notes.get(token);
    if (
      this.journal &&
      (!note || !(await this.journal.clear(note.key, note.id, valid)))
    )
      return false;
    if (!valid()) return false;
    this.notes.delete(token);
    this.publish(this.records.filter((value) => value.token !== token));
    this.restore();
    return true;
  }

  private update(
    token: Token,
    change: (record: RoutingChange) => RoutingChange | null,
    persist = true,
  ): boolean {
    const index = this.records.findIndex((record) => record.token === token);
    if (index < 0) return false;
    const previous = this.records[index];
    let next = change(previous);
    if (next === previous) return false;
    const lease = this.leases.get(token);
    if (
      persist &&
      lease &&
      !(next === null ? lease.remove() : lease.persist(stored(next)))
    ) {
      next = { ...previous, phase: "unknown", observation: null };
      const records = [...this.records];
      records[index] = Object.freeze(next);
      this.publish(records);
      return false;
    }
    const records = [...this.records];
    if (next === null) {
      records.splice(index, 1);
      this.notes.delete(token);
    } else records[index] = Object.freeze(next);
    this.publish(records);
    return true;
  }

  private restore(): void {
    if (!this.journal) return;
    const loaded = this.journal.load();
    if (this.journal.issue() !== null && this.journal.issue() !== "capacity") {
      this.publish([...this.records]);
      return;
    }
    // External deletion is not acknowledgement in this tab. Keep its original
    // token/note ID so a replacement can neither unlock nor be adopted as ours.
    const records = [...this.records];
    for (const note of loaded) {
      if (records.some((record) => scopeKey(record.scope) === note.key))
        continue;
      // Other tabs may clear disk notes without acknowledging this runtime's
      // unknown work. Keep those old fences, but never grow their union with
      // later disk batches beyond the same bounded scope registry.
      if (records.length >= MAX_SCOPES) break;
      const existing = this.records.find(
        (record) =>
          this.notes.get(record.token)?.id === note.id &&
          this.notes.get(record.token)?.key === note.key,
      );
      if (existing) records.push(existing);
      else {
        const token = Object.freeze({});
        this.notes.set(token, { id: note.id, key: note.key });
        records.push(
          Object.freeze({
            token,
            ...note.value,
            phase: "unknown",
            error: null,
            observation: null,
            restored: true,
          }),
        );
      }
    }
    if (
      records.length !== this.records.length ||
      records.some((record, index) => record !== this.records[index])
    )
      this.publish(records);
    else this.publish([...this.records]);
  }

  private publish(records: RoutingChange[]): void {
    this.records = Object.freeze(records);
    this.listeners.forEach((listener) => listener());
  }
}
