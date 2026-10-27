import { ApiError } from "./error";
import type { ManagementClient } from "./client";
import { canonicalRevision, idPath, shape } from "./proxy";
import { job, nextCommand, type Job } from "./targets";
import {
  readRoutingView,
  routingWritable,
  type RoutingContext,
} from "./remoteRouting";
import {
  poolPreset,
  presetEntity,
  presetReference,
  sameUserPreset,
  userPreset,
  type PoolPreset,
  type PresetCapability,
  type PresetEntity,
  type PresetWireEntity,
  type PresetReference,
  type UserPreset,
} from "./presets";

export type PresetMutation =
  | { action: "set_user_presets"; presets: UserPreset }
  | { action: "set_pool_preset"; preset: PoolPreset };
export interface PresetCommandInput {
  expected_target_revision: string;
  controller_epoch: string;
  command_id: string;
  expected_policy_revision: string;
  mutation: PresetMutation;
}
export interface PresetReceipt {
  controller_epoch: string;
  command_id: string;
  status: "saved" | "applied" | "rejected";
  policy_revision: string | null;
  rejection: string | null;
  user_id: null;
  credential_id: null;
  preset?: PresetReference;
}
export interface PresetReply {
  receipt: PresetReceipt;
  replayed: boolean;
  user: null;
  credential: null;
  secret: null;
  secret_available: false;
  presets?: PresetWireEntity;
}
export interface PresetSubmission {
  job: Job;
  response: PresetReply | null;
}
export interface PresetScopeChange {
  revision: string | null;
  entity: PresetEntity | null;
  submission: PresetSubmission | null;
}
function invalid(): never {
  throw new ApiError("format");
}
const optional = (value: unknown, keys: string[], extras: string[]) =>
  shape(value, [
    ...keys,
    ...extras.filter(
      (key) =>
        typeof value === "object" &&
        value !== null &&
        Object.hasOwn(value, key),
    ),
  ]);
export function shapePresetCommand(value: PresetCommandInput): void {
  shape(value, [
    "expected_target_revision",
    "controller_epoch",
    "command_id",
    "expected_policy_revision",
    "mutation",
  ]);
  if (
    ![
      value.expected_target_revision,
      value.controller_epoch,
      value.command_id,
      value.expected_policy_revision,
    ].every(canonicalRevision)
  )
    invalid();
  nextCommand(value.expected_policy_revision);
  const mutation = value.mutation;
  if (mutation?.action === "set_user_presets") {
    shape(mutation, ["action", "presets"]);
    userPreset(mutation.presets);
  } else if (mutation?.action === "set_pool_preset") {
    shape(mutation, ["action", "preset"]);
    poolPreset(mutation.preset);
  } else invalid();
}
export function presetSubmission(
  value: unknown,
  peer: string,
  input: PresetCommandInput,
  status: number,
): PresetSubmission {
  shapePresetCommand(input);
  shape(value, ["job", "response"]);
  const ticket = job(value.job, peer);
  const mutation = input.mutation;
  const expected: PresetReference =
    mutation.action === "set_user_presets"
      ? { kind: "user", id: mutation.presets.user_id }
      : { kind: "pool", id: mutation.preset.pool_id };
  const matches = (reference: PresetReference) =>
    reference.kind === expected.kind && reference.id === expected.id;
  if (
    !ticket ||
    ticket.resource !== undefined ||
    ticket.routing ||
    ticket.maintenance !== undefined ||
    ticket.controller_epoch !== input.controller_epoch ||
    ticket.command_id !== input.command_id ||
    ticket.expected_policy_revision !== input.expected_policy_revision ||
    (ticket.preset && !matches(ticket.preset)) ||
    (status === 202
      ? value.response !== null
      : status !== 200 || value.response === null)
  )
    invalid();
  if (value.response === null) return { job: ticket, response: null };
  optional(
    value.response,
    ["receipt", "replayed", "user", "credential", "secret", "secret_available"],
    ["presets"],
  );
  const reply = value.response as unknown as PresetReply;
  optional(
    reply.receipt,
    [
      "controller_epoch",
      "command_id",
      "status",
      "policy_revision",
      "rejection",
      "user_id",
      "credential_id",
    ],
    ["preset"],
  );
  const receipt = reply.receipt;
  if (
    typeof reply.replayed !== "boolean" ||
    reply.user !== null ||
    reply.credential !== null ||
    reply.secret !== null ||
    reply.secret_available !== false ||
    receipt.user_id !== null ||
    receipt.credential_id !== null ||
    receipt.controller_epoch !== input.controller_epoch ||
    receipt.command_id !== input.command_id ||
    !["saved", "applied", "rejected"].includes(receipt.status)
  )
    invalid();
  if (receipt.status === "rejected") {
    if (
      receipt.policy_revision !== null ||
      ![
        "invalid_policy",
        "policy_conflict",
        "resource_not_found",
        "policy_capacity",
      ].includes(receipt.rejection ?? "") ||
      Object.hasOwn(receipt, "preset") ||
      Object.hasOwn(reply, "presets") ||
      ticket.preset
    )
      invalid();
  } else {
    if (
      receipt.policy_revision !== nextCommand(input.expected_policy_revision) ||
      receipt.rejection !== null ||
      !Object.hasOwn(receipt, "preset") ||
      !matches(presetReference(receipt.preset))
    )
      invalid();
    if (reply.replayed) {
      if (Object.hasOwn(reply, "presets")) invalid();
    } else {
      const entity = presetEntity(reply.presets);
      if (
        mutation.action === "set_user_presets"
          ? entity.kind !== "user" ||
            !sameUserPreset(
              userPreset(entity.value, expected.id),
              mutation.presets,
            )
          : entity.kind !== "pool" ||
            poolPreset(entity.value, expected.id).default_preset !==
              mutation.preset.default_preset
      )
        invalid();
    }
  }
  return { job: ticket, response: reply };
}
export type PresetReads = Pick<
  ManagementClient,
  "presets" | "userPresets" | "poolPreset"
>;
export function presetReads(
  client: ManagementClient,
  peer: string | null,
): PresetReads {
  return peer === null
    ? client
    : {
        presets: (signal) => client.targetPresets(peer, signal),
        userPresets: (id, signal) => client.targetUserPresets(peer, id, signal),
        poolPreset: (id, signal) => client.targetPoolPreset(peer, id, signal),
      };
}
/** Reuse the existing serial policy/owner/outbox observation, not another store. */
export async function readPresetView<T>(
  client: ManagementClient,
  peer: string | null,
  read: (client: PresetReads, signal: AbortSignal) => Promise<T>,
  revision: ((value: T) => string) | null,
  signal: AbortSignal,
): Promise<{ data: T; capability: PresetCapability; context: RoutingContext }> {
  const result = await readRoutingView(
    client,
    peer,
    async (_routing, signal) => {
      const api = presetReads(client, peer);
      const capability = await api.presets(signal);
      const data = await read(api, signal);
      return { data, capability };
    },
    revision ? (value) => revision(value.data) : null,
    signal,
  );
  return { ...result.data, context: result.context };
}
export async function setPresets(
  client: ManagementClient,
  context: RoutingContext,
  mutation: PresetMutation,
  revision: string,
  csrf: string,
  signal: AbortSignal,
): Promise<PresetScopeChange> {
  if (!routingWritable(context))
    throw new ApiError("server", "node_control_denied", 403);
  if (context.scope.kind === "local") {
    if (mutation.action === "set_user_presets") {
      const value = await client.setUserPresets(
        mutation.presets,
        revision,
        csrf,
        signal,
      );
      return {
        revision: value.revision,
        entity: { kind: "user", data: value.presets },
        submission: null,
      };
    }
    const value = await client.setPoolPreset(
      mutation.preset,
      revision,
      csrf,
      signal,
    );
    return {
      revision: value.revision,
      entity: { kind: "pool", data: value.preset },
      submission: null,
    };
  }
  const { target, policy } = context.scope;
  idPath(target.node_id);
  if (policy.saved_revision !== revision)
    throw new ApiError("server", "policy_conflict", 409);
  const submission = await client.targetPresetCommand(
    target.node_id,
    {
      expected_target_revision: target.revision,
      controller_epoch: policy.controller_epoch,
      command_id: nextCommand(policy.last_terminal_command),
      expected_policy_revision: revision,
      mutation,
    },
    csrf,
    signal,
  );
  const reply = submission.response;
  return {
    revision: reply?.receipt.policy_revision ?? null,
    entity: reply?.presets
      ? ({
          kind: reply.presets.kind,
          data: reply.presets.value,
        } as PresetEntity)
      : null,
    submission,
  };
}
