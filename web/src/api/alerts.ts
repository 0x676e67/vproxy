import { ApiError } from "./error";
import { canonicalId, count, shape } from "./proxy";
import { validIp } from "./routing";

export const alertKinds = [
  "egress_check",
  "health_catalog",
  "policy",
  "traffic_checkpoint",
  "traffic_continuity",
  "remote_traffic",
  "remote_job",
  "remote_observation",
  "management_https",
  "node_tls",
  "proxy_tls",
] as const;
export const alertStatuses = ["active", "recovered", "unmonitored"] as const;
export const alertCodes = [
  "egress_address_unavailable",
  "egress_connection_refused",
  "egress_timed_out",
  "egress_permission_denied",
  "egress_network_unreachable",
  "egress_failed",
  "egress_family_mismatch",
  "health_catalog_unavailable",
  "health_catalog_stale",
  "proxy_not_running",
  "proxy_drain_failed",
  "proxy_drain_interrupted",
  "policy_publication_unavailable",
  "policy_not_applied",
  "traffic_checkpoint_failed",
  "traffic_checkpoint_stale",
  "traffic_loss_possible",
  "traffic_history_gap",
  "traffic_time_uncertain",
  "remote_traffic_continuity_error",
  "remote_traffic_not_authorized",
  "remote_collector_unavailable",
  "remote_traffic_unsupported",
  "remote_traffic_unavailable",
  "remote_traffic_stale",
  "remote_job_blocked",
  "remote_job_rejected",
  "remote_observation_pending",
  "remote_observation_unavailable",
  "remote_observation_unsupported",
  "remote_observation_not_authorized",
  "remote_observation_stale",
  "remote_observation_changed",
  "remote_observation_capacity",
  "remote_observation_incomplete",
  "https_identity_unavailable",
  "https_identity_expiring",
  "https_identity_expired",
  "https_identity_not_yet_valid",
  "https_identity_metadata_unavailable",
  "node_tls_identity_unavailable",
  "node_tls_identity_expiring",
  "node_tls_identity_expired",
  "node_tls_identity_not_yet_valid",
  "node_tls_identity_metadata_unavailable",
  "proxy_tls_identity_unavailable",
  "proxy_tls_identity_expiring",
  "proxy_tls_identity_expired",
  "proxy_tls_identity_not_yet_valid",
  "proxy_tls_identity_metadata_unavailable",
  "acme_attempt_unavailable",
  "acme_review_required",
  "acme_worker_stopped",
] as const;
export type AlertCode = (typeof alertCodes)[number];
export type AlertKind = (typeof alertKinds)[number];
export type AlertStatus = (typeof alertStatuses)[number];
export type AlertState = "active" | "recent";
export interface AlertOptions {
  state?: AlertState;
  after?: string;
  limit?: number;
}
export interface OperationAlert {
  id: string;
  kind: AlertKind;
  origin_node_id: string;
  resource_id: string | null;
  check: "bind" | "tcp" | null;
  target: string | null;
  status: AlertStatus;
  code: string;
  first_observed_at_unix_ms: string | null;
  last_observed_at_unix_ms: string | null;
  ended_at_unix_ms: string | null;
  age_millis: string;
  evidence_sequence: string | null;
  evidence_fresh: boolean;
}
export interface AlertCoverage {
  local_egress: boolean;
  local_traffic: boolean;
  local_proxy_expected: boolean;
  local_management_https: boolean;
  local_node_tls: boolean;
  local_proxy_tls: boolean;
  remote_cached: boolean;
  remote_egress: boolean;
  remote_observation: boolean;
}
export interface AlertPage {
  boot_id: string;
  revision: string;
  observed_at_unix_ms: string | null;
  age_millis: string | null;
  collection_error: boolean;
  active_count: number;
  recent_count: number;
  dropped: string;
  coverage: AlertCoverage;
  items: OperationAlert[];
  next_cursor: string | null;
}

export type EgressAlertListOptions = AlertOptions;
export interface EgressAlertPage extends Omit<AlertPage, "coverage"> {
  node_id: string;
  monitored: boolean;
}

export const alertDecimal = (value: unknown): value is string =>
  typeof value === "string" &&
  /^(0|[1-9][0-9]{0,19})$/.test(value) &&
  BigInt(value) <= 18446744073709551615n;
const nullableDecimal = (value: unknown): value is string | null =>
  value === null || alertDecimal(value);
export const alertCursor = (value: unknown): value is string =>
  typeof value === "string" && /^[\x21-\x7e]{1,160}$/.test(value);

/** Cursors are opaque and process-bound; no host, target or mutation is accepted. */
export function alertQuery(options: AlertOptions): "" | `?${string}` {
  if (
    typeof options !== "object" ||
    options === null ||
    Array.isArray(options) ||
    Object.keys(options).some(
      (key) => !["state", "after", "limit"].includes(key),
    ) ||
    (options.state !== undefined &&
      !["active", "recent"].includes(options.state)) ||
    (options.after !== undefined && !alertCursor(options.after)) ||
    (options.limit !== undefined && !count(options.limit, 16, 1))
  )
    throw new ApiError("format");
  const query = new URLSearchParams();
  if (options.state !== undefined) query.set("state", options.state);
  if (options.after !== undefined) query.set("after", options.after);
  if (options.limit !== undefined) query.set("limit", String(options.limit));
  return query.size ? `?${query}` : "";
}

export function alertSocket(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 54) return false;
  const match = /^(?:\[([0-9a-fA-F:.]+)\]|([0-9.]+)):([0-9]{1,5})$/.exec(value);
  return (
    !!match &&
    validIp(match[1] ?? match[2]) &&
    (!match[1] || match[1].includes(":")) &&
    Number(match[3]) > 0 &&
    Number(match[3]) <= 65535
  );
}

function operationAlert(value: unknown): OperationAlert {
  shape(value, [
    "id",
    "kind",
    "origin_node_id",
    "resource_id",
    "check",
    "target",
    "status",
    "code",
    "first_observed_at_unix_ms",
    "last_observed_at_unix_ms",
    "ended_at_unix_ms",
    "age_millis",
    "evidence_sequence",
    "evidence_fresh",
  ]);
  if (
    !alertDecimal(value.id) ||
    value.id === "0" ||
    !alertKinds.includes(value.kind as AlertKind) ||
    !canonicalId(value.origin_node_id) ||
    !(value.resource_id === null || canonicalId(value.resource_id)) ||
    (["management_https", "node_tls", "remote_observation"].includes(
      value.kind as string,
    ) &&
      value.resource_id !== null) ||
    (value.kind === "proxy_tls" && !canonicalId(value.resource_id)) ||
    (value.kind === "egress_check"
      ? !canonicalId(value.resource_id) ||
        !(value.check === "bind"
          ? value.target === null
          : value.check === "tcp" && alertSocket(value.target))
      : value.check !== null || value.target !== null) ||
    !alertStatuses.includes(value.status as AlertStatus) ||
    typeof value.code !== "string" ||
    !/^[a-z][a-z0-9_]{0,63}$/.test(value.code) ||
    !nullableDecimal(value.first_observed_at_unix_ms) ||
    !nullableDecimal(value.last_observed_at_unix_ms) ||
    !nullableDecimal(value.ended_at_unix_ms) ||
    !alertDecimal(value.age_millis) ||
    !nullableDecimal(value.evidence_sequence) ||
    typeof value.evidence_fresh !== "boolean" ||
    (value.status === "active" && value.ended_at_unix_ms !== null) ||
    (value.status === "unmonitored" && value.evidence_fresh !== false)
  )
    throw new ApiError("format");
  return value as unknown as OperationAlert;
}

/** Totals describe the complete bounded collection, never just this page. */
export function alertPage(
  value: unknown,
  options: AlertOptions = {},
): AlertPage {
  alertQuery(options);
  shape(value, [
    "boot_id",
    "revision",
    "observed_at_unix_ms",
    "age_millis",
    "collection_error",
    "active_count",
    "recent_count",
    "dropped",
    "coverage",
    "items",
    "next_cursor",
  ]);
  if (
    typeof value.coverage !== "object" ||
    value.coverage === null ||
    Array.isArray(value.coverage)
  )
    throw new ApiError("format");
  const coverage: Record<string, unknown> = { ...value.coverage };
  // Older servers omit this source. A supplied null/undefined is not omission.
  for (const source of [
    "local_management_https",
    "local_node_tls",
    "local_proxy_tls",
    "remote_observation",
  ])
    if (!Object.hasOwn(coverage, source)) coverage[source] = false;
  shape(coverage, [
    "local_egress",
    "local_traffic",
    "local_proxy_expected",
    "local_management_https",
    "local_node_tls",
    "local_proxy_tls",
    "remote_cached",
    "remote_egress",
    "remote_observation",
  ]);
  if (
    !canonicalId(value.boot_id) ||
    !alertDecimal(value.revision) ||
    value.revision === "0" ||
    !nullableDecimal(value.observed_at_unix_ms) ||
    !nullableDecimal(value.age_millis) ||
    typeof value.collection_error !== "boolean" ||
    !count(value.active_count, 12288) ||
    !count(value.recent_count, 256) ||
    !alertDecimal(value.dropped) ||
    Object.values(coverage).some((flag) => typeof flag !== "boolean") ||
    coverage.remote_egress !== false ||
    (value.observed_at_unix_ms !== null && value.age_millis === null) ||
    !Array.isArray(value.items) ||
    value.items.length > (options.limit ?? 10) ||
    !(value.next_cursor === null || alertCursor(value.next_cursor))
  )
    throw new ApiError("format");
  const items = value.items.map(operationAlert);
  const active = (options.state ?? "active") === "active";
  if (
    new Set(items.map((item) => item.id)).size !== items.length ||
    items.some((item) =>
      active ? item.status !== "active" : item.status === "active",
    ) ||
    items.length > (active ? value.active_count : value.recent_count) ||
    (value.next_cursor !== null &&
      (items.length !== (options.limit ?? 10) ||
        value.next_cursor === options.after))
  )
    throw new ApiError("format");
  return { ...value, coverage, items } as unknown as AlertPage;
}

function egressCursor(value: unknown, state: AlertState) {
  if (!alertCursor(value)) throw new ApiError("format");
  const [boot, revision, scope, offset, extra] = value.split(":");
  if (
    extra !== undefined ||
    !canonicalId(boot) ||
    !alertDecimal(revision) ||
    revision === "0" ||
    scope !== `egress-${state}` ||
    !alertDecimal(offset) ||
    BigInt(offset) > BigInt(state === "active" ? 6144 : 256)
  )
    throw new ApiError("format");
  return { boot, revision, offset: Number(offset) };
}

/** A remote egress cursor cannot select another observation source or list. */
export function egressAlertQuery(options: EgressAlertListOptions) {
  const query = alertQuery(options);
  if (options.after !== undefined)
    egressCursor(options.after, options.state ?? "active");
  return query;
}

/** Every episode and cursor belongs to this exact node and egress snapshot. */
export function egressAlertPage(
  value: unknown,
  node: string,
  options: EgressAlertListOptions = {},
): EgressAlertPage {
  egressAlertQuery(options);
  shape(value, [
    "node_id",
    "boot_id",
    "revision",
    "observed_at_unix_ms",
    "age_millis",
    "collection_error",
    "monitored",
    "active_count",
    "recent_count",
    "dropped",
    "items",
    "next_cursor",
  ]);
  if (
    !canonicalId(node) ||
    value.node_id !== node ||
    !canonicalId(value.boot_id) ||
    !alertDecimal(value.revision) ||
    value.revision === "0" ||
    !nullableDecimal(value.observed_at_unix_ms) ||
    !nullableDecimal(value.age_millis) ||
    (value.observed_at_unix_ms !== null && value.age_millis === null) ||
    typeof value.collection_error !== "boolean" ||
    typeof value.monitored !== "boolean" ||
    !count(value.active_count, 6144) ||
    !count(value.recent_count, 256) ||
    !alertDecimal(value.dropped) ||
    (!value.monitored &&
      (value.active_count !== 0 ||
        value.recent_count !== 0 ||
        value.age_millis !== null ||
        value.dropped !== "0")) ||
    !Array.isArray(value.items)
  )
    throw new ApiError("format");
  const state = options.state ?? "active";
  const after =
    options.after === undefined ? null : egressCursor(options.after, state);
  const offset = after?.offset ?? 0;
  const total = state === "active" ? value.active_count : value.recent_count;
  const items = value.items.map(operationAlert);
  const next = offset + items.length;
  const expectedCursor =
    next < total
      ? `${value.boot_id}:${value.revision}:egress-${state}:${next}`
      : null;
  if (
    (after !== null &&
      (after.boot !== value.boot_id || after.revision !== value.revision)) ||
    offset > total ||
    items.length !== Math.min(options.limit ?? 10, total - offset) ||
    new Set(items.map((item) => item.id)).size !== items.length ||
    items.some(
      (item) =>
        item.origin_node_id !== node ||
        (state === "active"
          ? item.status !== "active"
          : item.status === "active") ||
        (item.status === "recovered" && !item.evidence_fresh) ||
        (item.kind === "egress_check"
          ? ![
              "egress_address_unavailable",
              "egress_connection_refused",
              "egress_timed_out",
              "egress_permission_denied",
              "egress_network_unreachable",
              "egress_failed",
              "egress_family_mismatch",
            ].includes(item.code)
          : item.kind !== "health_catalog" ||
            item.resource_id !== null ||
            !["health_catalog_unavailable", "health_catalog_stale"].includes(
              item.code,
            )),
    ) ||
    value.next_cursor !== expectedCursor
  )
    throw new ApiError("format");
  return { ...value, items } as unknown as EgressAlertPage;
}
