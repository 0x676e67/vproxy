import { ApiError } from "./error";
import {
  canonicalId,
  canonicalRevision,
  count,
  shape,
  type Pagination,
} from "./proxy";
import { routingQuery, validIp } from "./routing";

export const healthOutcomes = [
  "unknown",
  "success",
  "address_unavailable",
  "connection_refused",
  "timed_out",
  "permission_denied",
  "network_unreachable",
  "failed",
  "family_mismatch",
  "cancelled",
] as const;
export type HealthOutcome = (typeof healthOutcomes)[number];
export interface HealthCheck {
  kind: "bind" | "tcp";
  target: string | null;
  outcome: HealthOutcome;
  sequence: string | null;
  observed_at_unix_ms: number | null;
  age_millis: number | null;
  latency_millis: number | null;
}
export interface HealthEntry {
  address_id: string;
  address_revision: string;
  ip: string;
  checks: HealthCheck[];
}
export interface HealthSnapshot {
  boot_id: string;
  sequence: string;
  catalog_revision: string | null;
  catalog_loaded: boolean;
  catalog_error: "catalog_unavailable" | null;
  catalog_observed_at_unix_ms: number | null;
  catalog_age_millis: number | null;
  in_flight: number;
  entries: HealthEntry[];
  next_cursor: string | null;
}
const u64 = (value: unknown): value is string =>
  typeof value === "string" &&
  /^(0|[1-9][0-9]{0,19})$/.test(value) &&
  BigInt(value) <= 18446744073709551615n;
const millis = (value: unknown): value is number | null =>
  value === null || count(value, Number.MAX_SAFE_INTEGER);
function socket(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 54) return false;
  const match = /^(?:\[([0-9a-fA-F:.]+)\]|([0-9.]+)):([1-9][0-9]{0,4})$/.exec(
    value,
  );
  return (
    !!match &&
    validIp(match[1] ?? match[2]) &&
    (!match[1] || match[1].includes(":")) &&
    Number(match[3]) <= 65535
  );
}
function healthCheck(value: unknown, sequence: string): HealthCheck {
  shape(value, [
    "kind",
    "target",
    "outcome",
    "sequence",
    "observed_at_unix_ms",
    "age_millis",
    "latency_millis",
  ]);
  if (
    !(value.kind === "bind"
      ? value.target === null
      : value.kind === "tcp" && socket(value.target)) ||
    !healthOutcomes.includes(value.outcome as HealthOutcome) ||
    !(
      value.sequence === null ||
      (u64(value.sequence) &&
        value.sequence !== "0" &&
        BigInt(value.sequence) <= BigInt(sequence))
    ) ||
    !millis(value.observed_at_unix_ms) ||
    !millis(value.age_millis) ||
    !millis(value.latency_millis)
  )
    throw new ApiError("format");
  if (
    value.sequence === null
      ? value.outcome !== "unknown" ||
        value.observed_at_unix_ms !== null ||
        value.age_millis !== null ||
        value.latency_millis !== null
      : value.age_millis === null || value.latency_millis === null
  )
    throw new ApiError("format");
  return value as unknown as HealthCheck;
}
/** A paged observation is not an inventory or global healthy/unhealthy verdict. */
export function healthSnapshot(value: unknown): HealthSnapshot {
  shape(value, [
    "boot_id",
    "sequence",
    "catalog_revision",
    "catalog_loaded",
    "catalog_error",
    "catalog_observed_at_unix_ms",
    "catalog_age_millis",
    "in_flight",
    "entries",
    "next_cursor",
  ]);
  if (
    !canonicalId(value.boot_id) ||
    !u64(value.sequence) ||
    !(
      value.catalog_revision === null ||
      canonicalRevision(value.catalog_revision)
    ) ||
    typeof value.catalog_loaded !== "boolean" ||
    !(
      value.catalog_error === null ||
      value.catalog_error === "catalog_unavailable"
    ) ||
    !millis(value.catalog_observed_at_unix_ms) ||
    !millis(value.catalog_age_millis) ||
    !count(value.in_flight, 4) ||
    !Array.isArray(value.entries) ||
    value.entries.length > 16 ||
    !(value.next_cursor === null || canonicalId(value.next_cursor))
  )
    throw new ApiError("format");
  const sequence = value.sequence;
  const entries = value.entries.map((entry): HealthEntry => {
    shape(entry, ["address_id", "address_revision", "ip", "checks"]);
    if (
      !canonicalId(entry.address_id) ||
      !canonicalRevision(entry.address_revision) ||
      !validIp(entry.ip) ||
      !Array.isArray(entry.checks) ||
      entry.checks.length < 1 ||
      entry.checks.length > 5
    )
      throw new ApiError("format");
    const checks = entry.checks.map((check) => healthCheck(check, sequence));
    if (
      checks.filter((check) => check.kind === "bind").length !== 1 ||
      new Set(checks.map((check) => `${check.kind}:${check.target ?? ""}`))
        .size !== checks.length
    )
      throw new ApiError("format");
    return {
      address_id: entry.address_id,
      address_revision: entry.address_revision,
      ip: entry.ip,
      checks,
    };
  });
  if (
    entries.some(
      (entry, index) =>
        (index > 0 && entries[index - 1].address_id >= entry.address_id) ||
        value.catalog_revision === null ||
        BigInt(entry.address_revision) >
          BigInt(value.catalog_revision as string),
    ) ||
    (value.next_cursor !== null &&
      entries.at(-1)?.address_id !== value.next_cursor) ||
    (value.catalog_loaded
      ? value.catalog_revision === null || value.catalog_age_millis === null
      : value.catalog_revision !== null ||
        value.catalog_observed_at_unix_ms !== null ||
        value.catalog_age_millis !== null ||
        entries.length !== 0)
  )
    throw new ApiError("format");
  return { ...value, entries } as unknown as HealthSnapshot;
}
export function healthQuery(options: Pagination): string {
  if (options.limit !== undefined && !count(options.limit, 16, 1))
    throw new ApiError("format");
  return routingQuery(options);
}
