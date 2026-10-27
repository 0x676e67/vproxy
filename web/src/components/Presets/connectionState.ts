import type { ConnectionRoute } from "../../api/connection";
import type { RoutePermission } from "../../api/routing";
import type { PolicyStatus } from "../../api/proxy";

/** Only this observation's live state counts. A durable receipt can describe a
 * previous process and must not turn stopped or unavailable admission green. */
export function connectionPolicyState(policy: PolicyStatus) {
  if (!policy.proxy_running) return "users.apiOnly";
  if (policy.applied_revision === null) return "users.degraded";
  return policy.applied_revision === policy.saved_revision
    ? "users.running"
    : "users.pending";
}

export function connectionRoutes(
  permission: RoutePermission,
): ConnectionRoute["kind"][] {
  return [
    ...(permission.legacy_allowed
      ? (["default", "session", "range", "ttl"] as const)
      : []),
    ...(permission.exits.length ? (["exit"] as const) : []),
    ...(permission.pools.length ? (["pool"] as const) : []),
  ];
}

/** Refresh may remove authorization, but must not silently select another
 * exit or pool. Clear invalid selections so the user makes that choice. */
export function reconcileConnectionRoute(
  permission: RoutePermission,
  kind: ConnectionRoute["kind"] | undefined,
  value: string | undefined,
): { route_kind: ConnectionRoute["kind"] | undefined; route_value: string } {
  if (kind === undefined || !connectionRoutes(permission).includes(kind))
    return { route_kind: undefined, route_value: "" };
  const allowed =
    kind === "exit"
      ? permission.exits
      : kind === "pool"
        ? permission.pools
        : null;
  return {
    route_kind: kind,
    route_value: !allowed || allowed.includes(value ?? "") ? (value ?? "") : "",
  };
}
