import { ApiError, type ManagementClient } from "../../api/client";
import { endpointCatalog, type EndpointCatalog } from "../../api/endpoints";
import type { EndpointSettings } from "../../api/endpointSettings";
import {
  readRoutingView,
  routingWritable,
  type RoutingContext,
} from "../../api/remoteRouting";

export interface EndpointView {
  catalog: EndpointCatalog;
  settings: EndpointSettings | null;
  context: RoutingContext;
}
const cancelled = (signal: AbortSignal) => {
  if (signal.aborted) throw new DOMException("Aborted", "AbortError");
};
export function effectiveEndpoints(
  settings: EndpointSettings,
): EndpointCatalog {
  return endpointCatalog({
    node_id: settings.node_id,
    proxy_running: settings.proxy_running,
    listeners: settings.listeners.map(({ protocol, bind, public_address }) => ({
      protocol,
      bind,
      public_address,
    })),
  });
}

/** One serial selected-node observation. Only the explicitly unsupported new
 * settings route falls back to that same node's legacy read-only catalog. */
export async function readEndpointView(
  client: ManagementClient,
  peer: string | null,
  nodeId: string | undefined,
  signal: AbortSignal,
): Promise<EndpointView> {
  const result = await readRoutingView(
    client,
    peer,
    async () => {
      cancelled(signal);
      try {
        const settings = await (peer === null
          ? client.endpointSettings(signal)
          : client.targetEndpointSettings(peer, signal));
        cancelled(signal);
        return { settings, catalog: effectiveEndpoints(settings) };
      } catch (error) {
        cancelled(signal);
        if (
          !(error instanceof ApiError) ||
          !(
            (peer === null
              ? error.status === 404 && error.code === "not_found"
              : error.status === 502 &&
                error.code === "remote_endpoint_management_unsupported") ||
            (error.code === "management_upgrade_required" &&
              (error.status === 503 || (peer !== null && error.status === 502)))
          )
        )
          throw error;
        const catalog = await (peer === null
          ? client.proxyEndpoints(signal)
          : client.targetEndpoints(peer, signal));
        cancelled(signal);
        return { settings: null, catalog };
      }
    },
    null,
    signal,
  );
  cancelled(signal);
  if (nodeId !== undefined && result.data.catalog.node_id !== nodeId)
    throw new ApiError("format");
  if (!result.data.settings) result.context.supported = false;
  return { ...result.data, context: result.context };
}

/** Do not refresh a dirty form's metadata CAS or remote command sequence behind
 * the operator's back. A changed snapshot requires an explicit new review. */
export function sameEndpointWriteView(
  before: EndpointView,
  fresh: EndpointView,
): void {
  if (!before.settings || !fresh.settings || !routingWritable(fresh.context))
    throw new ApiError("server", "node_control_denied", 403);
  if (
    before.settings.node_id !== fresh.settings.node_id ||
    before.settings.revision !== fresh.settings.revision
  )
    throw new ApiError("server", "endpoint_revision_changed", 409);
  if (before.settings.generation !== fresh.settings.generation)
    throw new ApiError("server", "endpoint_configuration_changed", 409);
  if (before.context.scope.kind === "target") {
    if (
      fresh.context.scope.kind !== "target" ||
      before.context.scope.target.revision !==
        fresh.context.scope.target.revision ||
      before.context.scope.policy.controller_epoch !==
        fresh.context.scope.policy.controller_epoch ||
      before.context.scope.policy.last_terminal_command !==
        fresh.context.scope.policy.last_terminal_command
    )
      throw new ApiError("server", "endpoint_configuration_changed", 409);
  }
}
