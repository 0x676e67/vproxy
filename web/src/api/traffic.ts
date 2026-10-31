import { ApiError, apiError, authenticationRequired } from "./error";
import {
  canonicalId,
  canonicalRevision,
  count,
  endpointStatus,
  shape,
} from "./proxy";
import type { ManagementClient } from "./client";

export type TrafficScope =
  | { kind: "node"; id: null }
  | { kind: "user"; id: string }
  | { kind: "credential"; id: string }
  | { kind: "pool"; id: string };
export type HistoryScope = Exclude<
  TrafficScope,
  { kind: "credential"; id: string }
>;
export type Resolution = "minute" | "hour" | "day";
/** Accounting vocabulary, separate from the compatible HTTP-family grant. */
export type TrafficProtocol =
  "http" | "https" | "socks5" | "masque" | "http_legacy";
export interface TrafficOptions {
  protocol?: TrafficProtocol;
  resolution?: Resolution;
  after?: string;
  limit?: number;
}
export interface TrafficMetadata {
  /** Absent in v1 reads; false means the source cannot separate HTTP and HTTPS. */
  http_split?: boolean;
  definition: "accepted_effective_payload_v1";
  origin_node_id: string;
  meter_epoch: string;
  meter_started_at_unix_ms: number | null;
  checkpoint_cursor: string;
  last_checkpoint_at_unix_ms: number | null;
  last_run_clean: boolean;
  loss_possible: boolean;
  history_gap: boolean;
  time_uncertain: boolean;
  observed_at_unix_ms: number | null;
  scope: TrafficScope;
}
export interface TrafficTotal {
  protocol: TrafficProtocol;
  durable_upload_bytes: string;
  durable_download_bytes: string;
  durable_saturated: boolean;
  live_upload_bytes: string | null;
  live_download_bytes: string | null;
  live_saturated: boolean | null;
}
export const checkpointStages = [
  "sample",
  "write_admission",
  "update_gate",
  "store",
  "worker",
  "observation",
] as const;
export type CheckpointStage = (typeof checkpointStages)[number];
export interface TrafficTotals extends TrafficMetadata {
  active_run_id: string | null;
  checkpoint_error: boolean;
  /** Last failed local cycle; older servers and remote snapshots omit it. */
  checkpoint_failure_stage?: CheckpointStage | null;
  last_completed_cycle_at_unix_ms: number | null;
  last_completed_cycle_age_millis: number | null;
  items: TrafficTotal[];
}
export interface BucketTotal {
  protocol: TrafficProtocol;
  upload_bytes: string;
  download_bytes: string;
  saturated: boolean;
}
export interface TrafficBucket {
  window_id: string;
  items: BucketTotal[];
}
export interface TrafficHistory extends TrafficMetadata {
  resolution: Resolution;
  next_cursor: string | null;
  retention_floor: string | null;
  retention_gap: boolean;
  items: TrafficBucket[];
}
export const trafficSourceStates = [
  "pending",
  "ready",
  "stale",
  "unsupported",
  "unavailable",
  "not_authorized",
  "continuity_error",
  "paused",
] as const;
export interface TrafficSource {
  origin_node_id: string;
  cached: boolean;
  collector_available: boolean;
  state: (typeof trafficSourceStates)[number];
  last_success_at_unix_ms: number | null;
  age_millis: number | null;
  target_revision: string;
}
export interface RemoteTraffic<T> {
  source: TrafficSource;
  data: T | null;
}
export interface TrafficView {
  totals: TrafficTotals | null;
  history: TrafficHistory | null;
  totalsSource: TrafficSource | null;
  historySource: TrafficSource | null;
  historyError: ApiError | null;
}

export const trafficProtocols = [
  "http",
  "https",
  "socks5",
  "masque",
  "http_legacy",
] as const;
const legacyProtocols = ["http", "socks5", "masque"] as const;
const splitProtocols = [
  "http_legacy",
  "socks5",
  "masque",
  "http",
  "https",
] as const;
const metadataKeys = [
  "definition",
  "origin_node_id",
  "meter_epoch",
  "meter_started_at_unix_ms",
  "checkpoint_cursor",
  "last_checkpoint_at_unix_ms",
  "last_run_clean",
  "loss_possible",
  "history_gap",
  "time_uncertain",
  "observed_at_unix_ms",
  "scope",
];
export const unsignedBytes = (value: unknown): value is string =>
  typeof value === "string" &&
  /^(0|[1-9][0-9]{0,19})$/.test(value) &&
  BigInt(value) <= 18446744073709551615n;
const timestamp = (value: unknown): value is number | null =>
  value === null || count(value, Number.MAX_SAFE_INTEGER);
const windowId = (value: unknown): value is string =>
  unsignedBytes(value) && BigInt(value) <= BigInt(Number.MAX_SAFE_INTEGER);
const protocol = (value: unknown): value is TrafficProtocol =>
  trafficProtocols.some((item) => item === value);
const width = (resolution: Resolution) =>
  ({ minute: 60_000n, hour: 3_600_000n, day: 86_400_000n })[resolution];

export function trafficScope(value: unknown): TrafficScope {
  shape(value, ["kind", "id"]);
  if (value.kind === "node" && value.id === null)
    return { kind: "node", id: null };
  if (
    ["user", "credential", "pool"].includes(value.kind as string) &&
    canonicalId(value.id)
  )
    return { kind: value.kind, id: value.id } as TrafficScope;
  throw new ApiError("format");
}
function metadata(
  value: Record<string, unknown>,
  scope: TrafficScope,
  split: boolean,
): void {
  const actual = trafficScope(value.scope);
  if (
    (split && typeof value.http_split !== "boolean") ||
    value.definition !== "accepted_effective_payload_v1" ||
    !canonicalId(value.origin_node_id) ||
    !canonicalId(value.meter_epoch) ||
    !timestamp(value.meter_started_at_unix_ms) ||
    !unsignedBytes(value.checkpoint_cursor) ||
    !timestamp(value.last_checkpoint_at_unix_ms) ||
    !timestamp(value.observed_at_unix_ms) ||
    !["last_run_clean", "loss_possible", "history_gap", "time_uncertain"].every(
      (key) => typeof value[key] === "boolean",
    ) ||
    actual.kind !== scope.kind ||
    actual.id !== scope.id
  )
    throw new ApiError("format");
}

/** Fixed local reads only. A remote selection never produces a local endpoint. */
export function trafficQuery(
  scope: TrafficScope,
  options: TrafficOptions = {},
  history = false,
  split = false,
): string {
  const selected = trafficScope(scope);
  const keys = history
    ? ["protocol", "resolution", "after", "limit"]
    : ["protocol"];
  if (Object.keys(options).some((key) => !keys.includes(key)))
    throw new ApiError("format");
  const query = new URLSearchParams({ scope: selected.kind });
  if (split) query.set("protocol_format", "split");
  if (selected.id !== null) query.set("id", selected.id);
  for (const key of keys) {
    const value = options[key as keyof TrafficOptions];
    if (value !== undefined) {
      if (key === "limit" ? !count(value, 50, 1) : typeof value !== "string")
        throw new ApiError("format");
      query.set(key, String(value));
    }
  }
  const suffix = `?${query}`;
  endpointStatus(`/proxy/traffic${history ? "/buckets" : ""}${suffix}`, "GET");
  return suffix;
}

export function trafficTotals(
  value: unknown,
  scope: TrafficScope,
  selected?: TrafficProtocol,
  split = false,
): TrafficTotals {
  const hasStage =
    typeof value === "object" &&
    value !== null &&
    Object.hasOwn(value, "checkpoint_failure_stage");
  shape(value, [
    ...metadataKeys,
    ...(split ? ["http_split"] : []),
    "active_run_id",
    "checkpoint_error",
    "last_completed_cycle_at_unix_ms",
    "last_completed_cycle_age_millis",
    "items",
    ...(hasStage ? ["checkpoint_failure_stage"] : []),
  ]);
  metadata(value, scope, split);
  if (
    !(value.active_run_id === null || canonicalId(value.active_run_id)) ||
    typeof value.checkpoint_error !== "boolean" ||
    (hasStage &&
      value.checkpoint_failure_stage !== null &&
      (value.checkpoint_error !== true ||
        !checkpointStages.some(
          (stage) => stage === value.checkpoint_failure_stage,
        ))) ||
    !timestamp(value.last_completed_cycle_at_unix_ms) ||
    !timestamp(value.last_completed_cycle_age_millis) ||
    !Array.isArray(value.items)
  )
    throw new ApiError("format");
  const available = split
    ? splitProtocols.slice(0, value.http_split ? 5 : 3)
    : legacyProtocols;
  const expected = selected
    ? available.filter((item) => item === selected)
    : available;
  if (value.items.length !== expected.length) throw new ApiError("format");
  const items = value.items.map((item, index): TrafficTotal => {
    shape(item, [
      "protocol",
      "durable_upload_bytes",
      "durable_download_bytes",
      "durable_saturated",
      "live_upload_bytes",
      "live_download_bytes",
      "live_saturated",
    ]);
    if (
      item.protocol !== expected[index] ||
      !unsignedBytes(item.durable_upload_bytes) ||
      !unsignedBytes(item.durable_download_bytes) ||
      typeof item.durable_saturated !== "boolean"
    )
      throw new ApiError("format");
    if (value.active_run_id === null) {
      if (
        item.live_upload_bytes !== null ||
        item.live_download_bytes !== null ||
        item.live_saturated !== null
      )
        throw new ApiError("format");
    } else if (
      !unsignedBytes(item.live_upload_bytes) ||
      !unsignedBytes(item.live_download_bytes) ||
      typeof item.live_saturated !== "boolean" ||
      BigInt(item.live_upload_bytes) < BigInt(item.durable_upload_bytes) ||
      BigInt(item.live_download_bytes) < BigInt(item.durable_download_bytes) ||
      (item.durable_saturated && !item.live_saturated)
    )
      throw new ApiError("format");
    return item as unknown as TrafficTotal;
  });
  if (split)
    items.sort(
      (a, b) =>
        trafficProtocols.indexOf(a.protocol) -
        trafficProtocols.indexOf(b.protocol),
    );
  return { ...value, items } as unknown as TrafficTotals;
}

export function trafficHistory(
  value: unknown,
  scope: TrafficScope,
  options: TrafficOptions,
  split = false,
): TrafficHistory {
  shape(value, [
    ...metadataKeys,
    ...(split ? ["http_split"] : []),
    "resolution",
    "next_cursor",
    "retention_floor",
    "retention_gap",
    "items",
  ]);
  metadata(value, scope, split);
  const available: readonly TrafficProtocol[] = split
    ? splitProtocols.slice(0, value.http_split ? 5 : 3)
    : legacyProtocols;
  const resolution = options.resolution ?? "hour";
  if (
    scope.kind === "credential" ||
    value.resolution !== resolution ||
    !(value.next_cursor === null || windowId(value.next_cursor)) ||
    !(value.retention_floor === null || windowId(value.retention_floor)) ||
    typeof value.retention_gap !== "boolean" ||
    !Array.isArray(value.items) ||
    value.items.length > (options.limit ?? 25)
  )
    throw new ApiError("format");
  let previous = options.after === undefined ? -1n : BigInt(options.after);
  const items = value.items.map((bucket): TrafficBucket => {
    shape(bucket, ["window_id", "items"]);
    if (
      !windowId(bucket.window_id) ||
      BigInt(bucket.window_id) % width(resolution) !== 0n ||
      BigInt(bucket.window_id) <= previous ||
      !Array.isArray(bucket.items) ||
      bucket.items.length > available.length
    )
      throw new ApiError("format");
    previous = BigInt(bucket.window_id);
    const seen = new Set<TrafficProtocol>();
    const rows = bucket.items.map((row): BucketTotal => {
      shape(row, ["protocol", "upload_bytes", "download_bytes", "saturated"]);
      if (
        !protocol(row.protocol) ||
        !available.includes(row.protocol) ||
        seen.has(row.protocol) ||
        (options.protocol !== undefined && row.protocol !== options.protocol) ||
        !unsignedBytes(row.upload_bytes) ||
        !unsignedBytes(row.download_bytes) ||
        typeof row.saturated !== "boolean"
      )
        throw new ApiError("format");
      seen.add(row.protocol);
      return row as unknown as BucketTotal;
    });
    return { window_id: bucket.window_id, items: rows };
  });
  if (
    (value.next_cursor !== null &&
      (items.length !== (options.limit ?? 25) ||
        value.next_cursor !== items.at(-1)?.window_id)) ||
    (value.retention_floor !== null &&
      (BigInt(value.retention_floor) % width(resolution) !== 0n ||
        (items.length > 0 &&
          BigInt(value.retention_floor) > BigInt(items[0].window_id)))) ||
    value.retention_gap !==
      (options.after !== undefined &&
        value.retention_floor !== null &&
        BigInt(options.after) < BigInt(value.retention_floor))
  )
    throw new ApiError("format");
  return { ...value, items } as unknown as TrafficHistory;
}

export function remoteTraffic<T extends TrafficMetadata>(
  value: unknown,
  peer: string,
  scope: TrafficScope,
  parse: (value: unknown) => T,
): RemoteTraffic<T> {
  shape(value, ["source", "data"]);
  shape(value.source, [
    "origin_node_id",
    "cached",
    "collector_available",
    "state",
    "last_success_at_unix_ms",
    "age_millis",
    "target_revision",
  ]);
  const source = value.source;
  if (
    !canonicalId(peer) ||
    source.origin_node_id !== peer ||
    source.cached !== (scope.kind === "node") ||
    typeof source.collector_available !== "boolean" ||
    !trafficSourceStates.includes(source.state as TrafficSource["state"]) ||
    !timestamp(source.last_success_at_unix_ms) ||
    !timestamp(source.age_millis) ||
    !canonicalRevision(source.target_revision)
  )
    throw new ApiError("format");
  const data = value.data === null ? null : parse(value.data);
  if (
    data &&
    (data.origin_node_id !== peer ||
      ("active_run_id" in data && data.active_run_id !== null) ||
      ("checkpoint_failure_stage" in data &&
        data.checkpoint_failure_stage != null))
  )
    throw new ApiError("format");
  return { source: source as unknown as TrafficSource, data };
}

/** Formatting never rounds a counter through Number; the tooltip keeps exact bytes. */
export function exactBytes(value: string | null, locale: string): string {
  if (value === null) return "—";
  if (!unsignedBytes(value)) throw new ApiError("format");
  return `${BigInt(value).toLocaleString(locale)} B`;
}
export function compactBytes(value: string | null, locale: string): string {
  if (value === null) return "—";
  if (!unsignedBytes(value)) throw new ApiError("format");
  const bytes = BigInt(value);
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
  let unit = 0,
    divisor = 1n;
  while (unit < units.length - 1 && bytes >= divisor * 1024n) {
    divisor *= 1024n;
    unit++;
  }
  if (unit === 0) return exactBytes(value, locale);
  const hundredths = (bytes * 100n) / divisor;
  const separator =
    new Intl.NumberFormat(locale)
      .formatToParts(1.1)
      .find((part) => part.type === "decimal")?.value ?? ".";
  return `${bytes % divisor === 0n ? "" : "≈ "}${(hundredths / 100n).toLocaleString(locale)}${separator}${(hundredths % 100n).toString().padStart(2, "0")} ${units[unit]}`;
}

export function trafficHref(
  scope: TrafficScope,
  peer: string | null = null,
  options: Pick<TrafficOptions, "protocol" | "resolution"> = {},
): string {
  const selected = trafficScope(scope);
  if (!(peer === null || canonicalId(peer))) throw new ApiError("format");
  if (
    (options.protocol !== undefined && !protocol(options.protocol)) ||
    (options.resolution !== undefined &&
      !["minute", "hour", "day"].includes(options.resolution))
  )
    throw new ApiError("format");
  const query = new URLSearchParams({ scope: selected.kind });
  if (selected.id !== null) query.set("id", selected.id);
  if (peer !== null) query.set("target", peer);
  if (options.protocol !== undefined) query.set("protocol", options.protocol);
  if (options.resolution !== undefined)
    query.set("resolution", options.resolution);
  return `/traffic?${query}`;
}

export function trafficLocation(search: string): {
  peer: string | null;
  scope: TrafficScope;
  protocol?: TrafficProtocol;
  resolution: Resolution;
} {
  if (search.length > 1024) throw new ApiError("format");
  const query = new URLSearchParams(search);
  const seen = new Set<string>();
  for (const [key] of query) {
    if (
      !["target", "scope", "id", "protocol", "resolution"].includes(key) ||
      seen.has(key)
    )
      throw new ApiError("format");
    seen.add(key);
  }
  const peer = query.get("target");
  if (!(peer === null || canonicalId(peer))) throw new ApiError("format");
  const scope = trafficScope({
    kind: query.get("scope") ?? "node",
    id: query.get("id"),
  });
  const selected = query.get("protocol");
  const resolution = query.get("resolution") ?? "hour";
  if (
    (selected !== null && !protocol(selected)) ||
    !["minute", "hour", "day"].includes(resolution)
  )
    throw new ApiError("format");
  return {
    peer,
    scope,
    protocol: selected ?? undefined,
    resolution: resolution as Resolution,
  };
}

/** One explicit node scope. Remote support is not inferred from IPAM support. */
export async function readTrafficView(
  client: Pick<
    ManagementClient,
    "traffic" | "trafficBuckets" | "targetTraffic" | "targetTrafficBuckets"
  >,
  peer: string | null,
  scope: TrafficScope,
  options: TrafficOptions,
  signal: AbortSignal,
): Promise<TrafficView> {
  if (signal.aborted) throw new DOMException("Aborted", "AbortError");
  const first =
    peer === null
      ? {
          source: null,
          data: await client.traffic(
            scope,
            { protocol: options.protocol },
            signal,
          ),
        }
      : await client.targetTraffic(
          peer,
          scope,
          { protocol: options.protocol },
          signal,
        );
  if (signal.aborted) throw new DOMException("Aborted", "AbortError");
  let history: TrafficHistory | null = null;
  let historySource: TrafficSource | null = null;
  let historyError: ApiError | null = null;
  if (scope.kind !== "credential") {
    try {
      const result =
        peer === null
          ? {
              source: null,
              data: await client.trafficBuckets(scope, options, signal),
            }
          : await client.targetTrafficBuckets(peer, scope, options, signal);
      history = result.data;
      historySource = result.source;
      if (
        history &&
        first.data &&
        (history.origin_node_id !== first.data.origin_node_id ||
          history.meter_epoch !== first.data.meter_epoch)
      ) {
        history = null;
        historyError = new ApiError("server", "traffic_changed", 409);
      }
    } catch (error) {
      if (signal.aborted || authenticationRequired(error)) throw error;
      historyError = apiError(error);
    }
  }
  if (signal.aborted) throw new DOMException("Aborted", "AbortError");
  return {
    totals: first.data,
    totalsSource: first.source,
    history,
    historySource,
    historyError,
  };
}
