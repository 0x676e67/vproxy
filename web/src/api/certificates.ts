import { ApiError } from "./error";
import { canonicalId, shape } from "./proxy";

export const certificateRoles = ["management", "node", "proxy"] as const;
export const certificateStates = [
  "disabled",
  "pending",
  "unavailable",
  "loaded",
] as const;
export type CertificateRole = (typeof certificateRoles)[number];
export type CertificateState = (typeof certificateStates)[number];
export type CertificateCondition =
  | CertificateState
  | "time_unknown"
  | "not_yet_valid"
  | "expired"
  | "expiring"
  | "within_validity";
export type CertificateProtocol =
  "http" | "https" | "socks5" | "masque" | "auto";
export interface Certificate {
  sha256: string;
  not_before_unix_s: string;
  not_after_unix_s: string;
}
export interface CertificateEntry {
  role: CertificateRole;
  source: "manual" | "acme";
  id: string | null;
  protocol: CertificateProtocol | null;
  state: CertificateState;
  certificate: Certificate | null;
  valid_now: boolean | null;
}
export interface CertificateStatus {
  node_id: string;
  observed_at_unix_s: string | null;
  entries: CertificateEntry[];
}

/** Signed i64 seconds preserve pre-epoch certificates without float narrowing. */
export function certificateSeconds(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^(?:0|-?[1-9][0-9]{0,18})$/.test(value) &&
    BigInt(value) >= -9223372036854775808n &&
    BigInt(value) <= 9223372036854775807n
  );
}

/** One local, bounded, actual-loaded identity snapshot, not a TLS probe. */
export function certificateStatus(value: unknown): CertificateStatus {
  shape(value, ["node_id", "observed_at_unix_s", "entries"]);
  if (
    !canonicalId(value.node_id) ||
    !(
      value.observed_at_unix_s === null ||
      certificateSeconds(value.observed_at_unix_s)
    ) ||
    !Array.isArray(value.entries) ||
    value.entries.length < 2 ||
    value.entries.length > 18
  )
    throw new ApiError("format");
  const now =
    value.observed_at_unix_s === null ? null : BigInt(value.observed_at_unix_s);
  const ids = new Set<string>();
  value.entries.forEach((entry, index) => {
    shape(entry, [
      "role",
      "source",
      "id",
      "protocol",
      "state",
      "certificate",
      "valid_now",
    ]);
    if (
      entry.role !==
        (index === 0 ? "management" : index === 1 ? "node" : "proxy") ||
      !["manual", "acme"].includes(entry.source as string) ||
      !certificateStates.includes(entry.state as CertificateState) ||
      (entry.role === "proxy"
        ? !canonicalId(entry.id) ||
          ids.has(entry.id) ||
          !["http", "https", "socks5", "masque", "auto"].includes(
            entry.protocol as string,
          ) ||
          entry.state === "pending"
        : entry.id !== null || entry.protocol !== null) ||
      (entry.role === "node" && entry.source !== "manual") ||
      (entry.role === "proxy" &&
        ["http", "socks5"].includes(entry.protocol as string) &&
        entry.source !== "manual") ||
      (entry.role === "management" &&
        (entry.state === "disabled" ||
          (entry.state === "pending" && entry.source !== "acme"))) ||
      (entry.role === "node" && entry.state === "pending") ||
      (entry.role === "proxy" &&
        ["http", "socks5"].includes(entry.protocol as string) !==
          (entry.state === "disabled"))
    )
      throw new ApiError("format");
    if (entry.role === "proxy") ids.add(entry.id as string);
    if (entry.state !== "loaded") {
      if (entry.certificate !== null || entry.valid_now !== null)
        throw new ApiError("format");
      return;
    }
    shape(entry.certificate, [
      "sha256",
      "not_before_unix_s",
      "not_after_unix_s",
    ]);
    const leaf = entry.certificate;
    if (
      typeof leaf.sha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(leaf.sha256) ||
      !certificateSeconds(leaf.not_before_unix_s) ||
      !certificateSeconds(leaf.not_after_unix_s) ||
      BigInt(leaf.not_before_unix_s) > BigInt(leaf.not_after_unix_s) ||
      entry.valid_now !==
        (now === null
          ? null
          : BigInt(leaf.not_before_unix_s) <= now &&
            now <= BigInt(leaf.not_after_unix_s))
    )
      throw new ApiError("format");
  });
  return value as unknown as CertificateStatus;
}

/** Rendering may be unavailable even when the exact signed timestamp is valid. */
export function certificateDate(value: string): Date | null {
  if (
    !certificateSeconds(value) ||
    BigInt(value) < -8640000000000n ||
    BigInt(value) > 8640000000000n
  )
    return null;
  return new Date(Number(value) * 1000);
}

export function certificateCondition(
  entry: CertificateEntry,
  observed: string | null,
): CertificateCondition {
  if (entry.state !== "loaded") return entry.state;
  if (observed === null || entry.certificate === null) return "time_unknown";
  const now = BigInt(observed);
  if (now < BigInt(entry.certificate.not_before_unix_s)) return "not_yet_valid";
  if (now > BigInt(entry.certificate.not_after_unix_s)) return "expired";
  return BigInt(entry.certificate.not_after_unix_s) - now <= 604800n
    ? "expiring"
    : "within_validity";
}
