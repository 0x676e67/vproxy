import { ApiError } from "./error";
import {
  canonicalId,
  canonicalRevision,
  count,
  shape,
  userInput,
  type UserInput,
} from "./proxy";

const actions = [
  "create_user",
  "update_user",
  "set_user_active",
  "delete_user",
] as const;
const states = ["reserved", "saved", "rejected"] as const;
const rejections = [
  "invalid_policy",
  "policy_conflict",
  "resource_not_found",
  "policy_capacity",
  "resource_managed",
  "owner_conflict",
] as const;

export type UserOperationAction = (typeof actions)[number];
export type UserOperationState = (typeof states)[number];
export type UserOperationRejection = (typeof rejections)[number];
export type UserChange =
  | ({ action: "create_user" } & UserInput)
  | ({ action: "update_user"; id: string } & UserInput)
  | { action: "set_user_active"; id: string; active: boolean }
  | { action: "delete_user"; id: string };
export interface UserOperationInput {
  expected_revision: string;
  expected_epoch: string;
  change: UserChange;
}
/** Durable result metadata only: the original payload and credentials are absent. */
export interface UserOperation {
  id: string;
  node_id: string;
  expected_revision: string;
  expected_epoch: string;
  sequence: string;
  action: UserOperationAction;
  user_id: string | null;
  state: UserOperationState;
  saved_revision: string | null;
  rejection: UserOperationRejection | null;
}
export interface UserOperationOptions {
  before?: string;
  limit?: number;
}
export interface UserOperationPage {
  items: UserOperation[];
  next_cursor: string | null;
}

export function userOperationInput(
  value: UserOperationInput,
): UserOperationInput {
  shape(value, ["expected_revision", "expected_epoch", "change"]);
  if (
    !canonicalRevision(value.expected_revision) ||
    !canonicalRevision(value.expected_epoch) ||
    typeof value.change !== "object" ||
    value.change === null ||
    Array.isArray(value.change)
  )
    throw new ApiError("format");
  const change = value.change;
  let checked: UserChange;
  switch (change.action) {
    case "create_user":
      shape(change, ["action", "name", "protocols", "concurrent_limit"]);
      checked = { action: change.action, ...userInput(change) };
      break;
    case "update_user":
      shape(change, ["action", "id", "name", "protocols", "concurrent_limit"]);
      if (!canonicalId(change.id)) throw new ApiError("format");
      checked = { action: change.action, id: change.id, ...userInput(change) };
      break;
    case "set_user_active":
      shape(change, ["action", "id", "active"]);
      if (!canonicalId(change.id) || typeof change.active !== "boolean")
        throw new ApiError("format");
      checked = { action: change.action, id: change.id, active: change.active };
      break;
    case "delete_user":
      shape(change, ["action", "id"]);
      if (!canonicalId(change.id)) throw new ApiError("format");
      checked = { action: change.action, id: change.id };
      break;
    default:
      throw new ApiError("format");
  }
  return {
    expected_revision: value.expected_revision,
    expected_epoch: value.expected_epoch,
    change: checked,
  };
}

/** Validate fixed metadata and any known request identity, never infer execution
 * from a matching action alone. The server binds the complete input digest. */
export function userOperation(
  value: unknown,
  expected: { id?: string; input?: UserOperationInput } = {},
): UserOperation {
  shape(value, [
    "id",
    "node_id",
    "expected_revision",
    "expected_epoch",
    "sequence",
    "action",
    "user_id",
    "state",
    "saved_revision",
    "rejection",
  ]);
  if (
    !canonicalId(value.id) ||
    !canonicalId(value.node_id) ||
    !canonicalRevision(value.expected_revision) ||
    !canonicalRevision(value.expected_epoch) ||
    !canonicalRevision(value.sequence) ||
    !actions.some((action) => action === value.action) ||
    !states.some((state) => state === value.state)
  )
    throw new ApiError("format");
  if (
    value.state === "saved"
      ? !canonicalId(value.user_id) ||
        !canonicalRevision(value.saved_revision) ||
        BigInt(value.saved_revision) !== BigInt(value.expected_revision) + 1n ||
        value.rejection !== null
      : value.saved_revision !== null ||
        (value.action === "create_user"
          ? value.user_id !== null
          : !canonicalId(value.user_id)) ||
        (value.state === "reserved"
          ? value.rejection !== null
          : !rejections.some((code) => code === value.rejection))
  )
    throw new ApiError("format");
  const input = expected.input && userOperationInput(expected.input);
  if (
    (expected.id !== undefined && value.id !== expected.id) ||
    (input &&
      (value.expected_revision !== input.expected_revision ||
        value.expected_epoch !== input.expected_epoch ||
        value.action !== input.change.action ||
        (input.change.action !== "create_user" &&
          value.user_id !== input.change.id)))
  )
    throw new ApiError("format");
  return value as unknown as UserOperation;
}

export function userOperationQuery(options: UserOperationOptions): string {
  if (
    typeof options !== "object" ||
    options === null ||
    Array.isArray(options) ||
    Object.keys(options).some((key) => !["before", "limit"].includes(key)) ||
    (options.before !== undefined && !canonicalRevision(options.before)) ||
    (options.limit !== undefined && !count(options.limit, 50, 1))
  )
    throw new ApiError("format");
  const query = new URLSearchParams();
  if (options.before !== undefined) query.set("before", options.before);
  if (options.limit !== undefined) query.set("limit", String(options.limit));
  return query.size ? `?${query}` : "";
}

/** Sequence is a descending keyset cursor, not a policy revision or proof that
 * a trimmed operation never executed. A page does not reconstruct its payload. */
export function userOperationPage(
  value: unknown,
  options: UserOperationOptions,
): UserOperationPage {
  userOperationQuery(options);
  shape(value, ["items", "next_cursor"]);
  const limit = options.limit ?? 25;
  if (
    !Array.isArray(value.items) ||
    value.items.length > limit ||
    !(value.next_cursor === null || canonicalRevision(value.next_cursor))
  )
    throw new ApiError("format");
  const items = value.items.map((item) => userOperation(item));
  if (
    new Set(items.map((item) => item.id)).size !== items.length ||
    items.some(
      (item, index) =>
        (index > 0 &&
          BigInt(item.sequence) >= BigInt(items[index - 1].sequence)) ||
        item.node_id !== items[0].node_id ||
        (options.before !== undefined &&
          BigInt(item.sequence) >= BigInt(options.before)),
    ) ||
    (value.next_cursor !== null &&
      (items.length !== limit || items.at(-1)?.sequence !== value.next_cursor))
  )
    throw new ApiError("format");
  return { items, next_cursor: value.next_cursor };
}
