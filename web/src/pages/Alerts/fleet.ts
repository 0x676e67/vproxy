import type { ManagementClient } from "../../api/client";
import { ApiError, apiError, authenticationRequired } from "../../api/client";
import type { NodeAlertPage } from "../../api/nodeAlerts";
import type { Target } from "../../api/targets";
import { observationDeadline } from "./useObservationExpiry";

export const FLEET_POLL_MS = 30_000;
export const NODE_ALERT_STALE_MS = 30_000;
export const MAX_FLEET_TARGETS = 128;
export interface Registry {
  targets: Target[];
  available: boolean;
  fingerprint: string;
}
export interface FleetRow {
  target: Target | null;
  nodeId: string;
  page: NodeAlertPage | null;
  received: number | null;
  outcome:
    | "read"
    | "waiting"
    | "paused"
    | "retired"
    | "unavailable"
    | "rollback"
    | "failed"
    | "unsupported";
  error: ApiError | null;
}
const cancelled = () => new DOMException("Aborted", "AbortError");
const changed = () => new ApiError("server", "fleet_registry_changed");
/** At most six fixed local pages. A changed or malformed registry is not a
 * partially complete target inventory and never triggers an unbounded rescan. */
export async function readRegistry(
  client: ManagementClient,
  signal: AbortSignal,
  current: () => boolean,
): Promise<Registry> {
  const targets: Target[] = [];
  let after: string | undefined, available: boolean | undefined;
  for (let page = 0; page < 6; page++) {
    if (signal.aborted || !current()) throw cancelled();
    const result = await client.targets(
      { after, limit: 25, include_retired: true },
      signal,
    );
    if (signal.aborted || !current()) throw cancelled();
    if (available !== undefined && result.controller_available !== available)
      throw changed();
    available = result.controller_available;
    for (const target of result.items) {
      if (
        (after !== undefined && target.node_id <= after) ||
        (targets.length > 0 &&
          target.node_id <= targets[targets.length - 1].node_id) ||
        targets.length >= MAX_FLEET_TARGETS
      )
        throw changed();
      targets.push(target);
    }
    if (result.next_cursor === null) {
      const fingerprint = JSON.stringify({
        available,
        targets: targets.map(
          ({
            node_id,
            name,
            revision,
            active,
            retired,
            origin,
            rollback_detected,
          }) => ({
            node_id,
            name,
            revision,
            active,
            retired,
            origin,
            rollback_detected,
          }),
        ),
      });
      return { targets, available, fingerprint };
    }
    if (
      result.items.length !== 25 ||
      result.next_cursor !== targets.at(-1)?.node_id ||
      result.next_cursor === after
    )
      throw changed();
    after = result.next_cursor;
  }
  throw changed();
}
export function waitingRows(registry: Registry, node: string): FleetRow[] {
  return [
    {
      target: null,
      nodeId: node,
      page: null,
      received: null,
      outcome: "waiting",
      error: null,
    },
    ...registry.targets.map((target) => ({
      target,
      nodeId: target.node_id,
      page: null,
      received: null,
      outcome: target.retired
        ? ("retired" as const)
        : !target.active
          ? ("paused" as const)
          : target.rollback_detected
            ? ("rollback" as const)
            : !registry.available
              ? ("unavailable" as const)
              : ("waiting" as const),
      error: null,
    })),
  ];
}
/** Two workers own the only remote reads. Counts come from limit=1 pages, not
 * from a concatenated incident list. The two registry reads are not atomic. */
export async function readFleet(
  client: ManagementClient,
  signal: AbortSignal,
  current: () => boolean,
  roster: (rows: FleetRow[]) => void,
): Promise<FleetRow[]> {
  const check = () => {
    if (signal.aborted || !current()) throw cancelled();
  };
  const node = await client.node(signal);
  check();
  const registry = await readRegistry(client, signal, current);
  check();
  const rows = waitingRows(registry, node.node_id);
  roster(rows);
  const read = async (row: FleetRow) => {
    check();
    try {
      const page =
        row.target === null
          ? await client.operationsAlerts({ state: "active", limit: 1 }, signal)
          : await client.targetOperationsAlerts(
              row.target.node_id,
              { state: "active", limit: 1 },
              signal,
            );
      check();
      if (page.node_id !== row.nodeId) throw new ApiError("format");
      row.page = page;
      row.received = performance.now();
      row.outcome = "read";
    } catch (failure) {
      check();
      row.error = apiError(failure);
      if (authenticationRequired(row.error)) throw row.error;
      row.outcome =
        row.error.code === "operations_alerts_unsupported"
          ? "unsupported"
          : "failed";
    }
  };
  await read(rows[0]);
  check();
  const candidates = rows.filter(
    (row) => row.target !== null && row.outcome === "waiting",
  );
  let next = 0;
  const worker = async () => {
    while (next < candidates.length) {
      check();
      const row = candidates[next++];
      await read(row);
    }
  };
  await Promise.all([worker(), worker()]);
  check();
  const final = await readRegistry(client, signal, current);
  check();
  if (final.fingerprint !== registry.fingerprint) throw changed();
  return rows;
}
export function freshRow(row: FleetRow, now = performance.now()): boolean {
  const deadline = row.page
    ? observationDeadline(
        row.page.age_millis,
        row.received,
        NODE_ALERT_STALE_MS,
      )
    : null;
  return (
    row.outcome === "read" &&
    row.page !== null &&
    !row.page.collection_error &&
    deadline !== null &&
    now <= deadline
  );
}
