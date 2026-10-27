import { ApiError } from "./error";
import {
  canonicalIp,
  routingReference,
  validIp,
  type RoutingReference,
} from "./routing";
import { presetReference, type PresetReference } from "./presets";
import {
  canonicalId,
  canonicalRevision,
  count,
  idPath,
  policyStatus,
  proxyCredential,
  proxyUser,
  shape,
  targetFilter,
  userInput,
  type PolicyStatus,
  type ProxyCredential,
  type ProxyUser,
  type UserInput,
} from "./proxy";

export interface Owner {
  controller_node_id: string | null;
  epoch: string;
  last_terminal_command: string;
}
export interface Target {
  node_id: string;
  name: string;
  origin: string;
  /** Operator-entered metadata, not an observed egress or a connection address. */
  server_ip: string | null;
  active: boolean;
  retired: boolean;
  revision: string;
  observed_epoch: string | null;
  observed_command: string | null;
  observed_policy_revision: string | null;
  rollback_detected: boolean;
}
export interface TargetPage {
  items: Target[];
  next_cursor: string | null;
  controller_available: boolean;
}

/** Only canonical registered node IDs may enter this fixed internal route. */
export function usersHref(peer: string): string {
  if (!canonicalId(peer)) throw new ApiError("format");
  return `/users?${new URLSearchParams({ target: peer })}`;
}

/** A resource link selects a registered scope, never a remote URL or pattern. */
export function resourcesHref(
  peer: string | null = null,
  address: string | null = null,
): string {
  if (
    (peer !== null && !canonicalId(peer)) ||
    (address !== null && !canonicalId(address))
  )
    throw new ApiError("format");
  const query = new URLSearchParams();
  if (peer !== null) query.set("target", peer);
  if (address !== null) query.set("address", address);
  return query.size ? `/resources?${query}` : "/resources";
}

export interface RemotePolicy extends PolicyStatus {
  controller_node_id: string | null;
  controller_epoch: string;
  last_terminal_command: string;
}
/** Reactivation changes delivery admission, never enrollment or rollback floors. */
export function deliveryAction(
  value: Pick<Target, "active" | "retired">,
): "pause" | "resume" | "reactivate" {
  return value.retired ? "reactivate" : value.active ? "pause" : "resume";
}
export type JobState =
  "pending" | "blocked" | "saved" | "applied" | "rejected" | "superseded";
export interface PolicyJob {
  maintenance?: { accepting: boolean };
  /** Absent on older managers; only true advertises a retained create intent. */
  user_creation?: boolean;
  resource?: never;
  endpoint?: never;
  expected_metadata_revision?: never;
  metadata_revision?: never;
  routing?: RoutingReference;
  preset?: PresetReference;
  node_id: string;
  job_id: string;
  controller_epoch: string;
  command_id: string;
  expected_policy_revision: string;
  state: JobState;
  policy_revision: string | null;
  outcome_code: string | null;
  attempts: number;
  next_attempt: string;
}
export interface MetadataJob {
  maintenance?: never;
  user_creation?: false;
  resource: "proxy_endpoints";
  routing?: never;
  preset?: never;
  node_id: string;
  job_id: string;
  controller_epoch: string;
  command_id: string;
  expected_policy_revision: null;
  policy_revision: null;
  expected_metadata_revision: string;
  metadata_revision: string | null;
  state: Exclude<JobState, "applied">;
  outcome_code:
    "remote_rejected" | "node_permission_or_state" | "node_unavailable" | null;
  attempts: number;
  next_attempt: string;
  endpoint: { listener_id: string; generation: string };
}
export type Job = PolicyJob | MetadataJob;
export type Mutation =
  | ({ action: "create_user" } & UserInput)
  | ({ action: "update_user"; id: string } & UserInput)
  | { action: "set_user_active"; id: string; active: boolean }
  | { action: "delete_user"; id: string }
  | { action: "create_credential"; user_id: string }
  | { action: "set_credential_active"; id: string; active: boolean }
  | { action: "rotate_credential" | "revoke_credential"; id: string };
export interface Receipt {
  controller_epoch: string;
  command_id: string;
  status: "saved" | "applied" | "rejected";
  policy_revision: string | null;
  rejection: string | null;
  user_id: string | null;
  credential_id: string | null;
}
export interface CommandReply {
  receipt: Receipt;
  replayed: boolean;
  user: ProxyUser | null;
  credential: ProxyCredential | null;
  secret: string | null;
  secret_available: boolean;
}
export interface Submission {
  job: Job;
  response: CommandReply | null;
}
export interface UserResult {
  job: PolicyJob;
  user_id: string;
}
export interface CommandInput {
  expected_target_revision: string;
  controller_epoch: string;
  command_id: string;
  expected_policy_revision: string;
  mutation: Mutation;
}

export function shapeCommandInput(value: CommandInput): void {
  shape(value, [
    "expected_target_revision",
    "controller_epoch",
    "command_id",
    "expected_policy_revision",
    "mutation",
  ]);
  for (const key of [
    "expected_target_revision",
    "controller_epoch",
    "command_id",
    "expected_policy_revision",
  ] as const)
    if (!canonicalRevision(value[key])) return invalid();
  const mutation = value.mutation;
  if (!mutation || typeof mutation !== "object") return invalid();
  switch (mutation.action) {
    case "create_user":
    case "update_user":
      shape(mutation, [
        "action",
        ...(mutation.action === "update_user" ? ["id"] : []),
        "name",
        "protocols",
        "concurrent_limit",
      ]);
      userInput(mutation);
      if (mutation.action === "update_user") idPath(mutation.id);
      break;
    case "set_user_active":
    case "set_credential_active":
      shape(mutation, ["action", "id", "active"]);
      idPath(mutation.id);
      if (typeof mutation.active !== "boolean") return invalid();
      break;
    case "create_credential":
      shape(mutation, ["action", "user_id"]);
      idPath(mutation.user_id);
      break;
    case "delete_user":
    case "rotate_credential":
    case "revoke_credential":
      shape(mutation, ["action", "id"]);
      idPath(mutation.id);
      break;
    default:
      return invalid();
  }
}

export const decimalZero = (value: unknown): value is string =>
  value === "0" || canonicalRevision(value);
const nullable = (value: unknown, validate = canonicalRevision) =>
  value === null || validate(value);
const invalid = (): never => {
  throw new ApiError("format");
};
export function canonicalOrigin(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 300) return false;
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" && url.port !== "0" && value === url.origin
    );
  } catch {
    return false;
  }
}

/** Match metadata admission, without claiming address ownership or reachability. */
export function validServerIp(value: unknown): value is string {
  if (!validIp(value)) return false;
  let ipv4: number;
  if (value.includes(":")) {
    const normalized = canonicalIp(value);
    if (normalized === "[::]" || normalized.startsWith("[ff")) return false;
    // URL normalization accepts expanded/mixed IPv6 and exposes mapped IPv4
    // as two hexadecimal groups. Only mapped addresses inherit IPv4 exclusions.
    const mapped = /^\[::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})\]$/.exec(
      normalized,
    );
    if (!mapped) return true;
    ipv4 =
      Number.parseInt(mapped[1], 16) * 65536 + Number.parseInt(mapped[2], 16);
  } else {
    ipv4 = value
      .split(".")
      .reduce((total, part) => total * 256 + Number(part), 0);
  }
  return (
    ipv4 !== 0 &&
    ipv4 !== 0xffffffff &&
    !(ipv4 >= 0xe0000000 && ipv4 <= 0xefffffff)
  );
}

export function nextCommand(value: string): string {
  if (!decimalZero(value) || BigInt(value) >= 9223372036854775807n)
    return invalid();
  return (BigInt(value) + 1n).toString();
}
export function owner(value: unknown): Owner {
  shape(value, ["controller_node_id", "epoch", "last_terminal_command"]);
  if (
    !nullable(value.controller_node_id, canonicalId) ||
    !canonicalRevision(value.epoch) ||
    !decimalZero(value.last_terminal_command)
  )
    return invalid();
  return value as unknown as Owner;
}
export function target(value: unknown): Target {
  const hasServerIp =
    typeof value === "object" &&
    value !== null &&
    Object.hasOwn(value, "server_ip");
  shape(value, [
    "node_id",
    "name",
    "origin",
    "active",
    "retired",
    "revision",
    "observed_epoch",
    "observed_command",
    "observed_policy_revision",
    "rollback_detected",
    ...(hasServerIp ? ["server_ip"] : []),
  ]);
  // Older management servers omit this one known metadata field.
  const serverIp = hasServerIp ? value.server_ip : null;
  if (
    !canonicalId(value.node_id) ||
    typeof value.name !== "string" ||
    !value.name.length ||
    new TextEncoder().encode(value.name).length > 128 ||
    /[\u0000-\u001f\u007f-\u009f]/.test(value.name) ||
    !canonicalOrigin(value.origin) ||
    (serverIp !== null && !validServerIp(serverIp)) ||
    typeof value.active !== "boolean" ||
    typeof value.retired !== "boolean" ||
    (value.retired && value.active) ||
    !canonicalRevision(value.revision) ||
    !nullable(value.observed_epoch) ||
    !nullable(value.observed_command, decimalZero) ||
    !nullable(value.observed_policy_revision) ||
    typeof value.rollback_detected !== "boolean" ||
    (value.observed_epoch === null) !== (value.observed_command === null) ||
    (value.observed_epoch === null) !==
      (value.observed_policy_revision === null)
  )
    return invalid();
  return { ...value, server_ip: serverIp } as unknown as Target;
}
export function targetPage(value: unknown): TargetPage {
  shape(value, ["items", "next_cursor", "controller_available"]);
  if (
    !Array.isArray(value.items) ||
    value.items.length > 25 ||
    !nullable(value.next_cursor, canonicalId) ||
    typeof value.controller_available !== "boolean"
  )
    return invalid();
  const items = value.items.map(target);
  if (
    items.some(
      (item, index) => index > 0 && items[index - 1].node_id >= item.node_id,
    ) ||
    (value.next_cursor !== null && value.next_cursor !== items.at(-1)?.node_id)
  )
    return invalid();
  return {
    items,
    next_cursor: value.next_cursor as string | null,
    controller_available: value.controller_available,
  };
}
export function remotePolicy(value: unknown): RemotePolicy {
  shape(value, [
    "controller_node_id",
    "controller_epoch",
    "last_terminal_command",
    "saved_revision",
    "applied_revision",
    "durable_applied_revision",
    "proxy_running",
    "user_count",
    "credential_count",
  ]);
  owner({
    controller_node_id: value.controller_node_id,
    epoch: value.controller_epoch,
    last_terminal_command: value.last_terminal_command,
  });
  const {
    controller_node_id,
    controller_epoch,
    last_terminal_command,
    ...facts
  } = value;
  return {
    ...policyStatus(facts),
    controller_node_id,
    controller_epoch,
    last_terminal_command,
  } as RemotePolicy;
}
export function job(value: unknown, node: string): Job | null {
  if (value === null) return null;
  if (
    typeof value === "object" &&
    value !== null &&
    Object.hasOwn(value, "resource")
  ) {
    shape(value, [
      "resource",
      "node_id",
      "job_id",
      "controller_epoch",
      "command_id",
      "expected_policy_revision",
      "policy_revision",
      "expected_metadata_revision",
      "metadata_revision",
      "state",
      "outcome_code",
      "attempts",
      "next_attempt",
      "endpoint",
      ...(Object.hasOwn(value, "user_creation") ? ["user_creation"] : []),
    ]);
    shape(value.endpoint, ["listener_id", "generation"]);
    if (
      value.resource !== "proxy_endpoints" ||
      (Object.hasOwn(value, "user_creation") &&
        value.user_creation !== false) ||
      value.node_id !== node ||
      !canonicalId(value.job_id) ||
      !canonicalRevision(value.controller_epoch) ||
      !canonicalRevision(value.command_id) ||
      value.expected_policy_revision !== null ||
      value.policy_revision !== null ||
      !canonicalRevision(value.expected_metadata_revision) ||
      !["pending", "blocked", "saved", "rejected", "superseded"].includes(
        value.state as string,
      ) ||
      !(
        value.outcome_code === null ||
        [
          "remote_rejected",
          "node_permission_or_state",
          "node_unavailable",
        ].includes(value.outcome_code as string)
      ) ||
      !count(value.attempts, 4294967295) ||
      !decimalZero(value.next_attempt) ||
      !canonicalId(value.endpoint.listener_id) ||
      typeof value.endpoint.generation !== "string" ||
      !/^[0-9a-f]{64}$/.test(value.endpoint.generation) ||
      (value.state === "saved"
        ? value.metadata_revision !==
          nextCommand(value.expected_metadata_revision)
        : value.metadata_revision !== null)
    )
      return invalid();
    return value as unknown as MetadataJob;
  }
  shape(value, [
    "node_id",
    "job_id",
    "controller_epoch",
    "command_id",
    "expected_policy_revision",
    "state",
    "policy_revision",
    "outcome_code",
    "attempts",
    "next_attempt",
    ...(typeof value === "object" && Object.hasOwn(value, "user_creation")
      ? ["user_creation"]
      : []),
    ...(typeof value === "object" && Object.hasOwn(value, "routing")
      ? ["routing"]
      : []),
    ...(typeof value === "object" && Object.hasOwn(value, "preset")
      ? ["preset"]
      : []),
    ...(typeof value === "object" && Object.hasOwn(value, "maintenance")
      ? ["maintenance"]
      : []),
  ]);
  if (Object.hasOwn(value, "maintenance")) {
    shape(value.maintenance, ["accepting"]);
    if (
      typeof value.maintenance.accepting !== "boolean" ||
      value.user_creation === true ||
      Object.hasOwn(value, "routing") ||
      Object.hasOwn(value, "preset")
    )
      return invalid();
  }
  if (Object.hasOwn(value, "routing")) routingReference(value.routing);
  if (
    Object.hasOwn(value, "user_creation") &&
    (typeof value.user_creation !== "boolean" ||
      (value.user_creation &&
        (Object.hasOwn(value, "routing") || Object.hasOwn(value, "preset"))))
  )
    return invalid();
  if (Object.hasOwn(value, "preset")) {
    presetReference(value.preset);
    if (Object.hasOwn(value, "routing")) return invalid();
  }
  if (
    value.node_id !== node ||
    !canonicalId(value.job_id) ||
    !canonicalRevision(value.controller_epoch) ||
    !canonicalRevision(value.command_id) ||
    !canonicalRevision(value.expected_policy_revision) ||
    ![
      "pending",
      "blocked",
      "saved",
      "applied",
      "rejected",
      "superseded",
    ].includes(value.state as string) ||
    !nullable(value.policy_revision) ||
    !(
      value.outcome_code === null ||
      [
        "remote_rejected",
        "node_permission_or_state",
        "node_unavailable",
      ].includes(value.outcome_code as string)
    ) ||
    !count(value.attempts, 4294967295) ||
    !decimalZero(value.next_attempt)
  )
    return invalid();
  const completed = value.state === "saved" || value.state === "applied";
  if (
    completed
      ? value.policy_revision !== nextCommand(value.expected_policy_revision)
      : value.policy_revision !== null
  )
    return invalid();
  return value as unknown as Job;
}

/** Bind a non-secret result to the exact retained create ticket, not latest. */
export function userResult(
  value: unknown,
  node: string,
  expected: PolicyJob,
): UserResult {
  const prior = job(expected, node);
  if (
    !prior ||
    prior.resource !== undefined ||
    prior.user_creation !== true ||
    prior.routing ||
    prior.preset ||
    ["rejected", "superseded"].includes(prior.state)
  )
    return invalid();
  shape(value, ["job", "user_id"]);
  const current = job(value.job, node);
  if (
    !current ||
    current.resource !== undefined ||
    current.user_creation !== true ||
    current.routing ||
    current.preset ||
    !["saved", "applied"].includes(current.state) ||
    current.outcome_code !== null ||
    current.next_attempt !== "0" ||
    (prior.state === "applied" && current.state !== "applied") ||
    current.job_id !== prior.job_id ||
    current.controller_epoch !== prior.controller_epoch ||
    current.command_id !== prior.command_id ||
    current.expected_policy_revision !== prior.expected_policy_revision ||
    !canonicalId(value.user_id)
  )
    return invalid();
  return { job: current, user_id: value.user_id };
}
function receipt(value: unknown): Receipt {
  shape(value, [
    "controller_epoch",
    "command_id",
    "status",
    "policy_revision",
    "rejection",
    "user_id",
    "credential_id",
  ]);
  if (
    !canonicalRevision(value.controller_epoch) ||
    !canonicalRevision(value.command_id) ||
    !["saved", "applied", "rejected"].includes(value.status as string) ||
    !nullable(value.policy_revision) ||
    !nullable(value.user_id, canonicalId) ||
    !nullable(value.credential_id, canonicalId)
  )
    return invalid();
  if (
    value.status === "rejected"
      ? value.policy_revision !== null ||
        value.user_id !== null ||
        value.credential_id !== null ||
        ![
          "invalid_policy",
          "policy_conflict",
          "resource_not_found",
          "policy_capacity",
        ].includes(value.rejection as string)
      : value.rejection !== null ||
        value.policy_revision === null ||
        value.user_id === null
  )
    return invalid();
  return value as unknown as Receipt;
}
export function submission(
  value: unknown,
  node: string,
  input: CommandInput,
  status: number,
): Submission {
  shape(value, ["job", "response"]);
  const saved = job(value.job, node);
  if (
    !saved ||
    saved.resource !== undefined ||
    saved.routing !== undefined ||
    saved.preset !== undefined ||
    saved.maintenance !== undefined ||
    saved.controller_epoch !== input.controller_epoch ||
    saved.command_id !== input.command_id ||
    saved.expected_policy_revision !== input.expected_policy_revision ||
    (status === 202
      ? value.response !== null
      : status !== 200 || value.response === null)
  )
    return invalid();
  if (value.response === null) return { job: saved, response: null };
  shape(value.response, [
    "receipt",
    "replayed",
    "user",
    "credential",
    "secret",
    "secret_available",
  ]);
  const raw = value.response;
  const acknowledged = receipt(raw.receipt);
  const user = raw.user === null ? null : proxyUser(raw.user);
  const credential =
    raw.credential === null ? null : proxyCredential(raw.credential);
  const secret = raw.secret;
  if (
    typeof raw.replayed !== "boolean" ||
    typeof raw.secret_available !== "boolean" ||
    raw.secret_available !== (secret !== null) ||
    !(
      secret === null ||
      (typeof secret === "string" &&
        /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(secret))
    ) ||
    acknowledged.controller_epoch !== input.controller_epoch ||
    acknowledged.command_id !== input.command_id ||
    (acknowledged.status !== "rejected" &&
      acknowledged.policy_revision !==
        nextCommand(input.expected_policy_revision))
  )
    return invalid();
  if (raw.replayed || acknowledged.status === "rejected") {
    if (user !== null || credential !== null || secret !== null)
      return invalid();
  } else {
    if (
      !user ||
      user.id !== acknowledged.user_id ||
      (credential &&
        (credential.id !== acknowledged.credential_id ||
          credential.user_id !== user.id))
    )
      return invalid();
    const mutation = input.mutation;
    if (
      mutation.action === "create_user" ||
      mutation.action === "update_user" ||
      mutation.action === "set_user_active" ||
      mutation.action === "delete_user"
    ) {
      if (
        credential ||
        secret ||
        acknowledged.credential_id !== null ||
        (mutation.action !== "create_user" && user.id !== mutation.id)
      )
        return invalid();
    } else if (
      !credential ||
      (mutation.action === "create_credential"
        ? credential.user_id !== mutation.user_id
        : credential.id !== mutation.id) ||
      (mutation.action === "create_credential" ||
      mutation.action === "rotate_credential"
        ? secret === null
        : secret !== null)
    )
      return invalid();
  }
  return {
    job: saved,
    response: {
      receipt: acknowledged,
      replayed: raw.replayed,
      user,
      credential,
      secret: secret as string | null,
      secret_available: raw.secret_available,
    },
  };
}
export function targetListQuery(options: {
  after?: string;
  limit?: number;
  include_retired?: boolean;
  q?: string;
}): string {
  if (
    Object.keys(options).some(
      (key) => !["after", "limit", "include_retired", "q"].includes(key),
    )
  )
    return invalid();
  const query = new URLSearchParams();
  if (options.after !== undefined) {
    idPath(options.after);
    query.set("after", options.after);
  }
  if (options.limit !== undefined) {
    if (!count(options.limit, 25, 1)) return invalid();
    query.set("limit", String(options.limit));
  }
  if (options.include_retired !== undefined) {
    if (typeof options.include_retired !== "boolean") return invalid();
    query.set("include_retired", String(options.include_retired));
  }
  if (options.q !== undefined) {
    const filter = targetFilter(options.q);
    if (filter) query.set("q", filter);
  }
  return query.size ? `?${query}` : "";
}
