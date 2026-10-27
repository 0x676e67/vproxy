import { ApiError } from "./error";
import { canonicalId, canonicalRevision, shape } from "./proxy";
import { job, nextCommand, owner, type Owner, type PolicyJob } from "./targets";

export interface MaintenanceStatus {
  node_id: string;
  ownership: Owner;
  saved_revision: string;
  durable_applied_revision: string | null;
  running: boolean;
  saved_accepting: boolean;
  applied_revision: string | null;
  runtime_accepting: boolean | null;
  active_operations: string | null;
}
export interface MaintenanceInput {
  expected_node_id: string;
  expected_revision: string;
  expected_epoch: string;
  accepting: boolean;
}
export interface MaintenanceChange {
  saved_revision: string;
  applied_revision: string | null;
  running: boolean;
}
export interface MaintenanceCommand {
  expected_target_revision: string;
  controller_epoch: string;
  command_id: string;
  expected_policy_revision: string;
  mutation: { action: "set_admission"; accepting: boolean };
}
export type MaintenanceJob = PolicyJob & {
  maintenance: { accepting: boolean };
};
export interface MaintenanceSubmission {
  job: MaintenanceJob;
  response: null | { status: "saved" | "applied" | "rejected" };
}

const invalid = (): never => {
  throw new ApiError("format");
};
const optionalRevision = (value: unknown): boolean =>
  value === null || canonicalRevision(value);
const operations = (value: unknown): value is string =>
  typeof value === "string" &&
  /^(0|[1-9][0-9]{0,19})$/.test(value) &&
  BigInt(value) <= 18446744073709551615n;

/** One current observation. A zero counter cannot establish queue flush or safe shutdown. */
export function maintenanceStatus(
  value: unknown,
  node: string,
): MaintenanceStatus {
  shape(value, [
    "node_id",
    "ownership",
    "saved_revision",
    "durable_applied_revision",
    "running",
    "saved_accepting",
    "applied_revision",
    "runtime_accepting",
    "active_operations",
  ]);
  const ownership = owner(value.ownership);
  if (
    !canonicalId(node) ||
    value.node_id !== node ||
    ownership.controller_node_id === node ||
    !canonicalRevision(value.saved_revision) ||
    !optionalRevision(value.durable_applied_revision) ||
    !optionalRevision(value.applied_revision) ||
    typeof value.running !== "boolean" ||
    typeof value.saved_accepting !== "boolean" ||
    !(
      value.runtime_accepting === null ||
      typeof value.runtime_accepting === "boolean"
    ) ||
    !(
      value.active_operations === null || operations(value.active_operations)
    ) ||
    (value.durable_applied_revision !== null &&
      BigInt(value.durable_applied_revision as string) >
        BigInt(value.saved_revision)) ||
    (value.applied_revision !== null &&
      BigInt(value.applied_revision as string) >
        BigInt(value.saved_revision)) ||
    (value.applied_revision === null) !== (value.runtime_accepting === null) ||
    (value.applied_revision === null) !== (value.active_operations === null) ||
    (!value.running &&
      (value.applied_revision !== null ||
        value.runtime_accepting !== null ||
        value.active_operations !== null)) ||
    (value.applied_revision !== null &&
      (value.applied_revision !== value.saved_revision ||
        value.runtime_accepting !== value.saved_accepting))
  )
    return invalid();
  return { ...value, ownership } as unknown as MaintenanceStatus;
}

export function maintenanceInput(value: MaintenanceInput): MaintenanceInput {
  shape(value, [
    "expected_node_id",
    "expected_revision",
    "expected_epoch",
    "accepting",
  ]);
  if (
    !canonicalId(value.expected_node_id) ||
    !canonicalRevision(value.expected_revision) ||
    !canonicalRevision(value.expected_epoch) ||
    typeof value.accepting !== "boolean"
  )
    return invalid();
  return { ...value };
}
export function maintenanceChange(
  value: unknown,
  input: MaintenanceInput,
): MaintenanceChange {
  shape(value, ["saved_revision", "applied_revision", "running"]);
  if (
    value.saved_revision !== nextCommand(input.expected_revision) ||
    !optionalRevision(value.applied_revision) ||
    typeof value.running !== "boolean" ||
    (value.running
      ? value.applied_revision !== value.saved_revision
      : value.applied_revision !== null)
  )
    return invalid();
  return value as unknown as MaintenanceChange;
}
export function maintenanceCommand(
  input: MaintenanceCommand,
): MaintenanceCommand {
  shape(input, [
    "expected_target_revision",
    "controller_epoch",
    "command_id",
    "expected_policy_revision",
    "mutation",
  ]);
  for (const value of [
    input.expected_target_revision,
    input.controller_epoch,
    input.command_id,
    input.expected_policy_revision,
  ])
    if (!canonicalRevision(value)) return invalid();
  shape(input.mutation, ["action", "accepting"]);
  if (
    input.mutation.action !== "set_admission" ||
    typeof input.mutation.accepting !== "boolean"
  )
    return invalid();
  return { ...input, mutation: { ...input.mutation } };
}
export function maintenanceJob(value: unknown, node: string): MaintenanceJob {
  const parsed = job(value, node);
  if (
    !parsed ||
    !parsed.maintenance ||
    parsed.resource !== undefined ||
    parsed.routing ||
    parsed.preset ||
    parsed.user_creation === true
  )
    return invalid();
  return parsed as MaintenanceJob;
}
export function maintenanceSubmission(
  value: unknown,
  node: string,
  input: MaintenanceCommand,
  status: number,
): MaintenanceSubmission {
  shape(value, ["job", "response"]);
  const saved = maintenanceJob(value.job, node);
  if (
    saved.maintenance.accepting !== input.mutation.accepting ||
    saved.controller_epoch !== input.controller_epoch ||
    saved.command_id !== input.command_id ||
    saved.expected_policy_revision !== input.expected_policy_revision ||
    (status === 202
      ? value.response !== null
      : status !== 200 || value.response === null)
  )
    return invalid();
  if (value.response === null) return { job: saved, response: null };
  const reply = value.response;
  shape(reply, [
    "receipt",
    "replayed",
    "user",
    "credential",
    "secret",
    "secret_available",
  ]);
  shape(reply.receipt, [
    "controller_epoch",
    "command_id",
    "status",
    "policy_revision",
    "rejection",
    "user_id",
    "credential_id",
  ]);
  const receipt = reply.receipt;
  if (
    typeof reply.replayed !== "boolean" ||
    reply.user !== null ||
    reply.credential !== null ||
    reply.secret !== null ||
    reply.secret_available !== false ||
    receipt.controller_epoch !== input.controller_epoch ||
    receipt.command_id !== input.command_id ||
    receipt.user_id !== null ||
    receipt.credential_id !== null ||
    !["saved", "applied", "rejected"].includes(receipt.status as string) ||
    (receipt.status === "rejected"
      ? receipt.policy_revision !== null ||
        ![
          "invalid_policy",
          "policy_conflict",
          "resource_not_found",
          "policy_capacity",
        ].includes(receipt.rejection as string)
      : receipt.rejection !== null ||
        receipt.policy_revision !== nextCommand(input.expected_policy_revision))
  )
    return invalid();
  return {
    job: saved,
    response: { status: receipt.status as "saved" | "applied" | "rejected" },
  };
}
