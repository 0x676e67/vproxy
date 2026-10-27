import { ApiError } from "./error";
import {
  canonicalId,
  canonicalRevision,
  count,
  idPath,
  revisionInput,
  shape,
  validUserName,
  type Pagination,
} from "./proxy";

export type ResourceKind = "prefixes" | "addresses" | "pools";
export type ResourceState = "active" | "draining" | "retired";
export type AddressFamily = "v4" | "v6";
export interface Prefix {
  id: string;
  name: string;
  cidr: string;
  retired: boolean;
  revision: string;
}
export interface Address {
  id: string;
  name: string;
  ip: string;
  prefix_id: string | null;
  state: ResourceState;
  revision: string;
}
export interface AddressView {
  revision: string;
  address: Address;
}
export interface Pool {
  id: string;
  name: string;
  family: AddressFamily;
  state: ResourceState;
  member_count: number;
  revision: string;
}
export type Resource = Prefix | Address | Pool;
export interface RoutingPage<T> {
  revision: string;
  items: T[];
  next_cursor: string | null;
}
export interface RoutePermission {
  user_id: string;
  legacy_allowed: boolean;
  exits: string[];
  pools: string[];
}
export interface PermissionView {
  revision: string;
  permission: RoutePermission;
}
export type RoutingEntity =
  | { kind: "prefix"; data: Prefix }
  | { kind: "address"; data: Address }
  | { kind: "pool"; data: Pool }
  | { kind: "permission"; data: RoutePermission };
export interface RoutingChange {
  revision: string;
  entity: RoutingEntity;
}
export interface RoutingReference {
  kind: RoutingEntity["kind"];
  id: string;
}
export function routingReference(value: unknown): RoutingReference {
  shape(value, ["kind", "id"]);
  if (
    !["prefix", "address", "pool", "permission"].includes(
      value.kind as string,
    ) ||
    !canonicalId(value.id)
  )
    throw new ApiError("format");
  return value as unknown as RoutingReference;
}
export function routingEntity(value: unknown): RoutingEntity {
  shape(value, ["kind", "data"]);
  if (
    !["prefix", "address", "pool", "permission"].includes(value.kind as string)
  )
    throw new ApiError("format");
  const kind = value.kind as RoutingEntity["kind"];
  const data =
    kind === "prefix"
      ? prefix(value.data)
      : kind === "address"
        ? address(value.data)
        : kind === "pool"
          ? pool(value.data)
          : permission(value.data);
  return { kind, data } as RoutingEntity;
}
export interface PrefixInput {
  name: string;
  cidr: string;
}
export interface AddressInput {
  name: string;
  ip: string;
  prefix_id: string | null;
}
export interface PoolInput {
  name: string;
  family: AddressFamily;
}

/** Syntax assistance only. Source ownership, scope and usability are server decisions. */
export function validIp(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 45 || !value.length)
    return false;
  if (/^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/.test(value))
    return value.split(".").every((part) => Number(part) <= 255);
  if (!value.includes(":") || !/^[0-9a-fA-F:.]+$/.test(value)) return false;
  try {
    return new URL(`http://[${value}]/`).hostname.startsWith("[");
  } catch {
    return false;
  }
}
export function validCidr(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const [ip, bits, extra] = value.split("/");
  return (
    extra === undefined &&
    validIp(ip) &&
    /^(0|[1-9][0-9]{0,2})$/.test(bits ?? "") &&
    Number(bits) <= (ip.includes(":") ? 128 : 32)
  );
}
export function canonicalIp(value: string): string {
  if (!validIp(value)) throw new ApiError("format");
  return value.includes(":") ? new URL(`http://[${value}]/`).hostname : value;
}
function prefixCidr(value: unknown): string {
  if (validCidr(value)) return value;
  // The server's existing wire format omits the mask for a single host.
  if (validIp(value)) return `${value}/${value.includes(":") ? 128 : 32}`;
  throw new ApiError("format");
}
/** Compare the address, family and mask without clearing any host bits. */
export function equivalentCidr(left: string, right: string): boolean {
  const [leftIp, leftBits] = prefixCidr(left).split("/");
  const [rightIp, rightBits] = prefixCidr(right).split("/");
  return (
    leftIp.includes(":") === rightIp.includes(":") &&
    leftBits === rightBits &&
    canonicalIp(leftIp) === canonicalIp(rightIp)
  );
}
export const resourceState = (value: unknown): value is ResourceState =>
  value === "active" || value === "draining" || value === "retired";
export const addressFamily = (value: unknown): value is AddressFamily =>
  value === "v4" || value === "v6";

function identity(value: Record<string, unknown>): void {
  if (
    !canonicalId(value.id) ||
    !validUserName(value.name) ||
    !canonicalRevision(value.revision)
  )
    throw new ApiError("format");
}
export function prefix(value: unknown): Prefix {
  shape(value, ["id", "name", "cidr", "retired", "revision"]);
  identity(value);
  if (typeof value.retired !== "boolean") throw new ApiError("format");
  return { ...value, cidr: prefixCidr(value.cidr) } as unknown as Prefix;
}
export function address(value: unknown): Address {
  shape(value, ["id", "name", "ip", "prefix_id", "state", "revision"]);
  identity(value);
  if (
    !validIp(value.ip) ||
    !(value.prefix_id === null || canonicalId(value.prefix_id)) ||
    !resourceState(value.state)
  )
    throw new ApiError("format");
  return value as unknown as Address;
}
/** A current directory record for one exact identity, without write authority. */
export function addressView(value: unknown, id: string): AddressView {
  idPath(id);
  shape(value, ["revision", "address"]);
  if (!canonicalRevision(value.revision)) throw new ApiError("format");
  const item = address(value.address);
  if (item.id !== id || BigInt(item.revision) > BigInt(value.revision))
    throw new ApiError("format");
  return { revision: value.revision, address: item };
}
export function pool(value: unknown): Pool {
  shape(value, ["id", "name", "family", "state", "member_count", "revision"]);
  identity(value);
  if (
    !addressFamily(value.family) ||
    !resourceState(value.state) ||
    !count(value.member_count, 1024)
  )
    throw new ApiError("format");
  return value as unknown as Pool;
}
export function grantIds(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= 32 &&
    value.every(canonicalId) &&
    new Set(value).size === value.length
  );
}
export function permission(value: unknown): RoutePermission {
  shape(value, ["user_id", "legacy_allowed", "exits", "pools"]);
  if (
    !canonicalId(value.user_id) ||
    typeof value.legacy_allowed !== "boolean" ||
    !grantIds(value.exits) ||
    !grantIds(value.pools)
  )
    throw new ApiError("format");
  // An explicit no-route record is not manufactured into a compatibility grant.
  return {
    user_id: value.user_id,
    legacy_allowed: value.legacy_allowed,
    exits: [...value.exits],
    pools: [...value.pools],
  };
}
export function permissionView(value: unknown, userId: string): PermissionView {
  shape(value, ["revision", "permission"]);
  if (!canonicalRevision(value.revision)) throw new ApiError("format");
  const result = permission(value.permission);
  if (result.user_id !== userId) throw new ApiError("format");
  return { revision: value.revision, permission: result };
}
export function permissionInput(value: RoutePermission): RoutePermission {
  return permission(value);
}

/** Resource APIs allow only bounded cursor pagination, not arbitrary filters. */
export function routingQuery(options: Pagination): string {
  if (Object.keys(options).some((key) => key !== "after" && key !== "limit"))
    throw new ApiError("format");
  const query = new URLSearchParams();
  if (options.after !== undefined) {
    idPath(options.after);
    query.set("after", options.after);
  }
  if (options.limit !== undefined) {
    if (!count(options.limit, 50, 1)) throw new ApiError("format");
    query.set("limit", String(options.limit));
  }
  return query.size ? `?${query}` : "";
}
export function routingPage<T>(
  value: unknown,
  parse: (value: unknown) => T,
  id: (item: T) => string,
  window: Pagination = {},
): RoutingPage<T> {
  shape(value, ["revision", "items", "next_cursor"]);
  if (
    !canonicalRevision(value.revision) ||
    !Array.isArray(value.items) ||
    value.items.length > 50 ||
    !(value.next_cursor === null || canonicalId(value.next_cursor))
  )
    throw new ApiError("format");
  const items = value.items.map(parse);
  const ids = items.map(id);
  if (
    items.length > (window.limit ?? 50) ||
    (window.after !== undefined && ids.some((id) => id <= window.after!)) ||
    ids.some(
      (value, index) =>
        !canonicalId(value) || (index > 0 && ids[index - 1] >= value),
    ) ||
    (value.next_cursor !== null && ids.at(-1) !== value.next_cursor)
  )
    throw new ApiError("format");
  return { revision: value.revision, items, next_cursor: value.next_cursor };
}
export function memberId(value: unknown): string {
  if (!canonicalId(value)) throw new ApiError("format");
  return value;
}
export function nextRoutingRevision(expected: string): string {
  const next = (BigInt(revisionInput(expected)) + 1n).toString();
  if (!canonicalRevision(next)) throw new ApiError("format");
  return next;
}
/** Every successful mutation must identify the exact entity and next global CAS. */
export function routingChange(
  value: unknown,
  kind: RoutingEntity["kind"],
  expected: string,
  id?: string,
): RoutingChange {
  shape(value, ["revision", "entity"]);
  shape(value.entity, ["kind", "data"]);
  if (
    value.revision !== nextRoutingRevision(expected) ||
    value.entity.kind !== kind
  )
    throw new ApiError("format");
  const data =
    kind === "prefix"
      ? prefix(value.entity.data)
      : kind === "address"
        ? address(value.entity.data)
        : kind === "pool"
          ? pool(value.entity.data)
          : permission(value.entity.data);
  if (kind !== "permission" && (data as Resource).revision !== value.revision)
    throw new ApiError("format");
  if (
    id !== undefined &&
    (kind === "permission"
      ? (data as RoutePermission).user_id
      : (data as Resource).id) !== id
  )
    throw new ApiError("format");
  return {
    revision: value.revision as string,
    entity: { kind, data } as RoutingEntity,
  };
}
/** The selector encodes the stable 16-byte ID, never a raw IP or a session suffix. */
export function routingToken(id: string): string {
  idPath(id);
  const bytes = atob(id.replace(/-/g, "+").replace(/_/g, "/") + "==");
  return [...bytes]
    .map((byte) => byte.charCodeAt(0).toString(16).padStart(2, "0"))
    .join("");
}
