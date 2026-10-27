import type { ManagementClient } from "./client";
import { ApiError } from "./error";
import {
  canonicalRevision,
  idPath,
  shape,
  validUserName,
  type PolicyStatus,
} from "./proxy";
import {
  addressFamily,
  canonicalIp,
  equivalentCidr,
  nextRoutingRevision,
  permissionInput,
  resourceState,
  routingChange,
  routingEntity,
  routingReference,
  validCidr,
  validIp,
  type AddressInput,
  type PoolInput,
  type PrefixInput,
  type ResourceState,
  type RoutePermission,
  type RoutingChange,
  type RoutingEntity,
  type RoutingReference,
} from "./routing";
import { job, nextCommand, type Job, type Owner } from "./targets";
import type { ProxyScope } from "./scope";

export type RoutingMutation =
  | ({ action: "create_prefix" } & PrefixInput)
  | { action: "retire_prefix"; id: string }
  | ({ action: "create_address" } & AddressInput)
  | { action: "set_address_state"; id: string; state: ResourceState }
  | ({ action: "create_pool" } & PoolInput)
  | { action: "set_pool_state"; id: string; state: ResourceState }
  | {
      action: "add_pool_member" | "remove_pool_member";
      pool_id: string;
      address_id: string;
    }
  | { action: "set_route_permission"; permission: RoutePermission };
export interface RoutingCommandInput {
  expected_target_revision: string;
  controller_epoch: string;
  command_id: string;
  expected_policy_revision: string;
  mutation: RoutingMutation;
}
export interface RoutingReceipt {
  controller_epoch: string;
  command_id: string;
  status: "saved" | "applied" | "rejected";
  policy_revision: string | null;
  rejection: string | null;
  user_id: null;
  credential_id: null;
  routing?: RoutingReference;
}
export interface RoutingReply {
  receipt: RoutingReceipt;
  replayed: boolean;
  user: null;
  credential: null;
  secret: null;
  secret_available: false;
  routing?: RoutingEntity;
}
export interface RoutingSubmission {
  job: Job;
  response: RoutingReply | null;
}
export interface RoutingScopeChange {
  revision: string | null;
  entity: RoutingEntity | null;
  submission: RoutingSubmission | null;
}
export interface RoutingContext {
  scope: ProxyScope;
  policy: PolicyStatus;
  owner: Owner | null;
  localNodeId: string | null;
  job: Job | null;
  supported: boolean;
}
function invalid(): never {
  throw new ApiError("format");
}
function optionalShape(
  value: unknown,
  keys: string[],
  optional: string,
): asserts value is Record<string, unknown> {
  shape(value, [
    ...keys,
    ...(typeof value === "object" &&
    value !== null &&
    Object.hasOwn(value, optional)
      ? [optional]
      : []),
  ]);
}
export function shapeRoutingCommand(input: RoutingCommandInput): void {
  shape(input, [
    "expected_target_revision",
    "controller_epoch",
    "command_id",
    "expected_policy_revision",
    "mutation",
  ]);
  if (
    ![
      input.expected_target_revision,
      input.controller_epoch,
      input.command_id,
      input.expected_policy_revision,
    ].every(canonicalRevision)
  )
    invalid();
  nextRoutingRevision(input.expected_policy_revision);
  const value = input.mutation;
  if (!value || typeof value !== "object") invalid();
  switch (value.action) {
    case "create_prefix":
      shape(value, ["action", "name", "cidr"]);
      if (!validUserName(value.name) || !validCidr(value.cidr)) invalid();
      break;
    case "create_address":
      shape(value, ["action", "name", "ip", "prefix_id"]);
      if (!validUserName(value.name) || !validIp(value.ip)) invalid();
      if (value.prefix_id !== null) idPath(value.prefix_id);
      break;
    case "create_pool":
      shape(value, ["action", "name", "family"]);
      if (!validUserName(value.name) || !addressFamily(value.family)) invalid();
      break;
    case "retire_prefix":
      shape(value, ["action", "id"]);
      idPath(value.id);
      break;
    case "set_address_state":
    case "set_pool_state":
      shape(value, ["action", "id", "state"]);
      idPath(value.id);
      if (!resourceState(value.state)) invalid();
      break;
    case "add_pool_member":
    case "remove_pool_member":
      shape(value, ["action", "pool_id", "address_id"]);
      idPath(value.pool_id);
      idPath(value.address_id);
      break;
    case "set_route_permission":
      shape(value, ["action", "permission"]);
      permissionInput(value.permission);
      break;
    default:
      invalid();
  }
}
function expectedReference(mutation: RoutingMutation): {
  kind: RoutingEntity["kind"];
  id?: string;
} {
  switch (mutation.action) {
    case "create_prefix":
      return { kind: "prefix" };
    case "retire_prefix":
      return { kind: "prefix", id: mutation.id };
    case "create_address":
      return { kind: "address" };
    case "set_address_state":
      return { kind: "address", id: mutation.id };
    case "create_pool":
      return { kind: "pool" };
    case "set_pool_state":
      return { kind: "pool", id: mutation.id };
    case "add_pool_member":
    case "remove_pool_member":
      return { kind: "pool", id: mutation.pool_id };
    case "set_route_permission":
      return { kind: "permission", id: mutation.permission.user_id };
  }
}
export function routingSubmission(
  value: unknown,
  peer: string,
  input: RoutingCommandInput,
  status: number,
): RoutingSubmission {
  shapeRoutingCommand(input);
  shape(value, ["job", "response"]);
  const ticket = job(value.job, peer);
  if (
    !ticket ||
    ticket.resource !== undefined ||
    ticket.preset !== undefined ||
    ticket.maintenance !== undefined ||
    ticket.controller_epoch !== input.controller_epoch ||
    ticket.command_id !== input.command_id ||
    ticket.expected_policy_revision !== input.expected_policy_revision ||
    (status === 202
      ? value.response !== null
      : status !== 200 || value.response === null)
  )
    invalid();
  const expected = expectedReference(input.mutation);
  const matches = (reference: RoutingReference) =>
    reference.kind === expected.kind &&
    (expected.id === undefined || expected.id === reference.id);
  if (ticket.routing && !matches(ticket.routing)) invalid();
  if (value.response === null) return { job: ticket, response: null };
  optionalShape(
    value.response,
    ["receipt", "replayed", "user", "credential", "secret", "secret_available"],
    "routing",
  );
  const reply = value.response;
  optionalShape(
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
    "routing",
  );
  const receipt = reply.receipt;
  const rejected = receipt.status === "rejected";
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
    !["saved", "applied", "rejected"].includes(receipt.status as string)
  )
    invalid();
  if (rejected) {
    if (
      receipt.policy_revision !== null ||
      ![
        "invalid_policy",
        "policy_conflict",
        "resource_not_found",
        "policy_capacity",
      ].includes(receipt.rejection as string) ||
      Object.hasOwn(receipt, "routing") ||
      Object.hasOwn(reply, "routing") ||
      ticket.routing
    )
      invalid();
  } else {
    if (
      receipt.policy_revision !==
        nextRoutingRevision(input.expected_policy_revision) ||
      receipt.rejection !== null ||
      !Object.hasOwn(receipt, "routing")
    )
      invalid();
    const reference = routingReference(receipt.routing);
    if (
      !matches(reference) ||
      (ticket.routing &&
        (ticket.routing.kind !== reference.kind ||
          ticket.routing.id !== reference.id))
    )
      invalid();
    if (reply.replayed) {
      if (Object.hasOwn(reply, "routing")) invalid();
    } else {
      const entity = routingEntity(reply.routing);
      const changed = routingChange(
        { revision: receipt.policy_revision, entity },
        expected.kind,
        input.expected_policy_revision,
        reference.id,
      );
      const mutation = input.mutation;
      if (
        mutation.action === "create_prefix" &&
        (changed.entity.kind !== "prefix" ||
          changed.entity.data.name !== mutation.name ||
          !equivalentCidr(changed.entity.data.cidr, mutation.cidr) ||
          changed.entity.data.retired)
      )
        invalid();
      if (
        mutation.action === "create_address" &&
        (changed.entity.kind !== "address" ||
          changed.entity.data.name !== mutation.name ||
          canonicalIp(changed.entity.data.ip) !== canonicalIp(mutation.ip) ||
          changed.entity.data.prefix_id !== mutation.prefix_id ||
          changed.entity.data.state !== "active")
      )
        invalid();
      if (
        mutation.action === "create_pool" &&
        (changed.entity.kind !== "pool" ||
          changed.entity.data.name !== mutation.name ||
          changed.entity.data.family !== mutation.family ||
          changed.entity.data.state !== "active" ||
          changed.entity.data.member_count !== 0)
      )
        invalid();
      if (
        mutation.action === "retire_prefix" &&
        (changed.entity.kind !== "prefix" || !changed.entity.data.retired)
      )
        invalid();
      if (
        (mutation.action === "set_address_state" ||
          mutation.action === "set_pool_state") &&
        (!("state" in changed.entity.data) ||
          changed.entity.data.state !== mutation.state)
      )
        invalid();
      if (
        mutation.action === "set_route_permission" &&
        (changed.entity.kind !== "permission" ||
          changed.entity.data.legacy_allowed !==
            mutation.permission.legacy_allowed ||
          !(["exits", "pools"] as const).every(
            (key) =>
              changed.entity.kind === "permission" &&
              changed.entity.data[key].length ===
                mutation.permission[key].length &&
              changed.entity.data[key].every((id) =>
                mutation.permission[key].includes(id),
              ),
          ))
      )
        invalid();
      return {
        job: ticket,
        response: {
          ...reply,
          routing: changed.entity,
        } as unknown as RoutingReply,
      };
    }
  }
  return { job: ticket, response: reply as unknown as RoutingReply };
}

export type RoutingReads = Pick<
  ManagementClient,
  "routingCatalog" | "poolMembers" | "routePermission" | "health"
>;
function reads(client: ManagementClient, peer: string | null): RoutingReads {
  return peer === null
    ? client
    : {
        routingCatalog: (kind, options, signal) =>
          client.targetRoutingCatalog(peer, kind, options, signal),
        poolMembers: (id, options, signal) =>
          client.targetPoolMembers(peer, id, options, signal),
        routePermission: (id, signal) =>
          client.targetRoutePermission(peer, id, signal),
        health: (options, signal) => client.targetHealth(peer, options, signal),
      };
}
/** One explicit observation chain per peer; no remote Promise.all or local fallback. */
export async function readRoutingView<T>(
  client: ManagementClient,
  peer: string | null,
  read: (client: RoutingReads, signal: AbortSignal) => Promise<T>,
  revision: ((data: T) => string) | null,
  signal: AbortSignal,
): Promise<{ data: T; context: RoutingContext }> {
  let context: RoutingContext;
  if (peer === null) {
    const policy = await client.policy(signal);
    const owner = await client.owner(signal);
    context = {
      scope: { kind: "local" },
      policy,
      owner,
      localNodeId: null,
      job: null,
      supported: true,
    };
  } else {
    idPath(peer);
    const local = await client.node(signal);
    const target = await client.target(peer, signal);
    const job = await client.targetJob(peer, signal);
    const policy = await client.targetPolicy(peer, signal);
    context = {
      scope: { kind: "target", target, policy },
      policy,
      owner: null,
      localNodeId: local.node_id,
      job,
      supported: false,
    };
  }
  const data = await read(reads(client, peer), signal);
  if (revision && revision(data) !== context.policy.saved_revision)
    throw new ApiError("server", "policy_conflict", 409);
  context.supported = true;
  return { data, context };
}
export function routingWritable(context: RoutingContext | null): boolean {
  if (!context?.supported) return false;
  if (context.scope.kind === "local")
    return !!context.owner && context.owner.controller_node_id === null;
  const { target, policy } = context.scope;
  return (
    target.active &&
    !target.retired &&
    !target.rollback_detected &&
    context.localNodeId !== null &&
    policy.controller_node_id === context.localNodeId &&
    context.job?.state !== "pending" &&
    context.job?.state !== "blocked"
  );
}
/** Do not cancel and replace a live read while the same remote claim drains. */
export function routingReadDisabled(
  peer: string | null,
  loading: boolean,
  blocked: boolean,
): boolean {
  return blocked || (peer !== null && loading);
}
type Operation =
  | "createPrefix"
  | "retirePrefix"
  | "createAddress"
  | "routingState"
  | "createPool"
  | "poolMembership"
  | "setRoutePermission";
export type RoutingOperations = {
  [K in Operation]: (
    ...args: Parameters<ManagementClient[K]>
  ) => Promise<RoutingScopeChange>;
};
export function routingOperations(
  client: ManagementClient,
  context: RoutingContext,
): RoutingOperations {
  const local = async (
    result: Promise<RoutingChange>,
  ): Promise<RoutingScopeChange> => ({ ...(await result), submission: null });
  const remote = async (
    mutation: RoutingMutation,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<RoutingScopeChange> => {
    if (context.scope.kind !== "target" || !routingWritable(context))
      throw new ApiError("server", "node_control_denied", 403);
    const { target, policy } = context.scope;
    if (policy.saved_revision !== revision)
      throw new ApiError("server", "policy_conflict", 409);
    const submission = await client.targetRoutingCommand(
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
    return {
      revision: submission.response?.receipt.policy_revision ?? null,
      entity: submission.response?.routing ?? null,
      submission,
    };
  };
  return {
    createPrefix: (input, revision, csrf, signal) =>
      context.scope.kind === "local"
        ? local(client.createPrefix(input, revision, csrf, signal))
        : remote(
            { action: "create_prefix", name: input.name, cidr: input.cidr },
            revision,
            csrf,
            signal,
          ),
    retirePrefix: (id, revision, csrf, signal) =>
      context.scope.kind === "local"
        ? local(client.retirePrefix(id, revision, csrf, signal))
        : remote({ action: "retire_prefix", id }, revision, csrf, signal),
    createAddress: (input, revision, csrf, signal) =>
      context.scope.kind === "local"
        ? local(client.createAddress(input, revision, csrf, signal))
        : remote(
            {
              action: "create_address",
              name: input.name,
              ip: input.ip,
              prefix_id: input.prefix_id,
            },
            revision,
            csrf,
            signal,
          ),
    routingState: (kind, id, state, revision, csrf, signal) => {
      if (kind !== "addresses" && kind !== "pools")
        throw new ApiError("format");
      return context.scope.kind === "local"
        ? local(client.routingState(kind, id, state, revision, csrf, signal))
        : remote(
            {
              action:
                kind === "addresses" ? "set_address_state" : "set_pool_state",
              id,
              state,
            },
            revision,
            csrf,
            signal,
          );
    },
    createPool: (input, revision, csrf, signal) =>
      context.scope.kind === "local"
        ? local(client.createPool(input, revision, csrf, signal))
        : remote(
            { action: "create_pool", name: input.name, family: input.family },
            revision,
            csrf,
            signal,
          ),
    poolMembership: (pool_id, address_id, remove, revision, csrf, signal) => {
      if (typeof remove !== "boolean") throw new ApiError("format");
      return context.scope.kind === "local"
        ? local(
            client.poolMembership(
              pool_id,
              address_id,
              remove,
              revision,
              csrf,
              signal,
            ),
          )
        : remote(
            {
              action: remove ? "remove_pool_member" : "add_pool_member",
              pool_id,
              address_id,
            },
            revision,
            csrf,
            signal,
          );
    },
    setRoutePermission: (permission, revision, csrf, signal) =>
      context.scope.kind === "local"
        ? local(client.setRoutePermission(permission, revision, csrf, signal))
        : remote(
            { action: "set_route_permission", permission },
            revision,
            csrf,
            signal,
          ),
  };
}
