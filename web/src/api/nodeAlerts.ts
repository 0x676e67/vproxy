import {
  alertDecimal,
  alertPage,
  alertQuery,
  type AlertOptions,
  type AlertPage,
  type AlertState,
  type AlertKind,
  type AlertCoverage,
} from "./alerts";
import { ApiError } from "./error";
import { canonicalId, shape } from "./proxy";

export type NodeAlertCoverage = Pick<
  AlertCoverage,
  | "local_egress"
  | "local_traffic"
  | "local_proxy_expected"
  | "local_management_https"
  | "local_node_tls"
  | "local_proxy_tls"
>;
export interface NodeAlertPage extends Omit<AlertPage, "coverage"> {
  node_id: string;
  coverage: NodeAlertCoverage;
}
const codes: Partial<Record<AlertKind, readonly string[]>> = {
  egress_check: [
    "egress_address_unavailable",
    "egress_connection_refused",
    "egress_timed_out",
    "egress_permission_denied",
    "egress_network_unreachable",
    "egress_failed",
    "egress_family_mismatch",
  ],
  health_catalog: ["health_catalog_unavailable", "health_catalog_stale"],
  policy: [
    "proxy_not_running",
    "proxy_drain_failed",
    "proxy_drain_interrupted",
    "policy_publication_unavailable",
    "policy_not_applied",
  ],
  traffic_checkpoint: ["traffic_checkpoint_failed", "traffic_checkpoint_stale"],
  traffic_continuity: [
    "traffic_loss_possible",
    "traffic_history_gap",
    "traffic_time_uncertain",
  ],
  management_https: [
    "https_identity_unavailable",
    "https_identity_expiring",
    "https_identity_expired",
    "https_identity_not_yet_valid",
    "https_identity_metadata_unavailable",
    "acme_attempt_unavailable",
    "acme_review_required",
    "acme_worker_stopped",
  ],
  node_tls: [
    "node_tls_identity_unavailable",
    "node_tls_identity_expiring",
    "node_tls_identity_expired",
    "node_tls_identity_not_yet_valid",
    "node_tls_identity_metadata_unavailable",
  ],
  proxy_tls: [
    "proxy_tls_identity_unavailable",
    "proxy_tls_identity_expiring",
    "proxy_tls_identity_expired",
    "proxy_tls_identity_not_yet_valid",
    "proxy_tls_identity_metadata_unavailable",
  ],
};
function cursor(value: string, state: AlertState) {
  const [boot, revision, domain, offset, extra] = value.split(":");
  if (
    extra !== undefined ||
    !canonicalId(boot) ||
    !alertDecimal(revision) ||
    revision === "0" ||
    domain !== `node-${state}` ||
    !alertDecimal(offset) ||
    BigInt(offset) > BigInt(state === "active" ? 6144 : 256)
  )
    throw new ApiError("format");
  return { boot, revision, offset: Number(offset) };
}
/** This namespace cannot select local all-source or legacy egress snapshots. */
export function nodeAlertQuery(options: AlertOptions): "" | `?${string}` {
  const query = alertQuery(options);
  if (options.after !== undefined)
    cursor(options.after, options.state ?? "active");
  return query;
}
/** All counts and entries describe only this exact node's own observations. */
export function nodeAlertPage(
  value: unknown,
  node: string | undefined,
  options: AlertOptions = {},
): NodeAlertPage {
  nodeAlertQuery(options);
  shape(value, [
    "node_id",
    "boot_id",
    "revision",
    "observed_at_unix_ms",
    "age_millis",
    "collection_error",
    "coverage",
    "active_count",
    "recent_count",
    "dropped",
    "items",
    "next_cursor",
  ]);
  shape(value.coverage, [
    "local_egress",
    "local_traffic",
    "local_proxy_expected",
    "local_management_https",
    "local_node_tls",
    "local_proxy_tls",
  ]);
  if (
    !canonicalId(value.node_id) ||
    (node !== undefined && value.node_id !== node) ||
    Object.values(value.coverage).some((flag) => typeof flag !== "boolean")
  )
    throw new ApiError("format");
  const { node_id, coverage, ...rest } = value;
  const page = alertPage(
    {
      ...rest,
      coverage: {
        ...coverage,
        remote_cached: false,
        remote_egress: false,
        remote_observation: false,
      },
    },
    options,
  );
  const state = options.state ?? "active",
    after = options.after === undefined ? null : cursor(options.after, state),
    offset = after?.offset ?? 0;
  const total = state === "active" ? page.active_count : page.recent_count,
    next = offset + page.items.length;
  if (
    page.active_count > 6144 ||
    (after &&
      (after.boot !== page.boot_id || after.revision !== page.revision)) ||
    offset > total ||
    page.items.length !== Math.min(options.limit ?? 10, total - offset) ||
    page.items.some(
      (item) =>
        item.origin_node_id !== node_id ||
        !codes[item.kind]?.includes(item.code) ||
        (!["egress_check", "proxy_tls"].includes(item.kind) &&
          item.resource_id !== null) ||
        (item.status === "recovered" && !item.evidence_fresh),
    ) ||
    page.next_cursor !==
      (next < total
        ? `${page.boot_id}:${page.revision}:node-${state}:${next}`
        : null)
  )
    throw new ApiError("format");
  return { ...page, node_id, coverage } as NodeAlertPage;
}
