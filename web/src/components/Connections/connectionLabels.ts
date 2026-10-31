import type { ManagementClient } from "../../api/client";
import { ApiError } from "../../api/error";
import type { Address, PermissionView, Pool } from "../../api/routing";

export interface ConnectionLabels {
  revision: string;
  addresses: Address[];
  pools: Pool[];
}

/** Optional display data, not authorization. One page per granted resource kind
 * bounds remote work; authorized IDs outside those pages remain selectable. */
export async function readConnectionLabels(
  client: ManagementClient,
  peer: string | null,
  permission: PermissionView,
  signal: AbortSignal,
): Promise<ConnectionLabels> {
  if (signal.aborted) throw new DOMException("Aborted", "AbortError");
  const result: ConnectionLabels = {
    revision: permission.revision,
    addresses: [],
    pools: [],
  };
  for (const kind of ["addresses", "pools"] as const) {
    const allowed =
      kind === "addresses"
        ? permission.permission.exits
        : permission.permission.pools;
    if (!allowed.length) continue;
    const page = await (peer === null
      ? client.routingCatalog(kind, { limit: 50 }, signal)
      : client.targetRoutingCatalog(peer, kind, { limit: 50 }, signal));
    // A late, abort-ignoring response must not start the next remote read.
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    if (page.revision !== permission.revision)
      throw new ApiError("server", "policy_conflict", 409);
    // Keep only the grant IDs from the same policy observation. Resource state
    // is a label, never a health check or a replacement for fresh generation.
    for (const item of page.items) {
      if (!allowed.includes(item.id)) continue;
      if (kind === "addresses" && "ip" in item) result.addresses.push(item);
      if (kind === "pools" && "family" in item) result.pools.push(item);
    }
  }
  return result;
}
