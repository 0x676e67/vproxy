import { ApiError } from "./error";
import { shape } from "./proxy";

export const acmeActivities = ["waiting", "working", "stopped"] as const;
export const acmeFailures = ["attempt_unavailable", "review_required"] as const;
export type AcmeActivity = (typeof acmeActivities)[number];
export type AcmeFailure = (typeof acmeFailures)[number];
export interface AcmeCertificate {
  not_before_unix_s: string;
  not_after_unix_s: string;
  available: boolean;
}
export type AcmeStatus =
  | { mode: "manual" }
  | {
      mode: "acme";
      environment: "staging" | "production";
      challenge: "tls-alpn-01" | "http-01";
      certificate: AcmeCertificate | null;
      activity: AcmeActivity;
      next_attempt_at_unix_s: string | null;
      last_failure: AcmeFailure | null;
      observed_at_unix_s: string;
    };

const seconds = (value: unknown): value is string =>
  typeof value === "string" &&
  /^(0|[1-9][0-9]{0,19})$/.test(value) &&
  BigInt(value) <= 18446744073709551615n;

/** Facts from this process, not a cache inventory or public TLS probe. */
export function acmeStatus(value: unknown): AcmeStatus {
  if (
    typeof value === "object" &&
    value !== null &&
    "mode" in value &&
    value.mode === "manual"
  ) {
    shape(value, ["mode"]);
    return { mode: "manual" };
  }
  shape(value, [
    "mode",
    "environment",
    "challenge",
    "certificate",
    "activity",
    "next_attempt_at_unix_s",
    "last_failure",
    "observed_at_unix_s",
  ]);
  if (
    value.mode !== "acme" ||
    !["staging", "production"].includes(value.environment as string) ||
    !["tls-alpn-01", "http-01"].includes(value.challenge as string) ||
    !acmeActivities.includes(value.activity as AcmeActivity) ||
    !(
      value.last_failure === null ||
      acmeFailures.includes(value.last_failure as AcmeFailure)
    ) ||
    !seconds(value.observed_at_unix_s) ||
    !(value.activity === "waiting"
      ? seconds(value.next_attempt_at_unix_s)
      : value.next_attempt_at_unix_s === null)
  )
    throw new ApiError("format");
  if (value.certificate !== null) {
    shape(value.certificate, [
      "not_before_unix_s",
      "not_after_unix_s",
      "available",
    ]);
    const certificate = value.certificate;
    if (
      !seconds(certificate.not_before_unix_s) ||
      !seconds(certificate.not_after_unix_s) ||
      BigInt(certificate.not_before_unix_s) >=
        BigInt(certificate.not_after_unix_s) ||
      typeof certificate.available !== "boolean" ||
      certificate.available !==
        (BigInt(certificate.not_before_unix_s) <=
          BigInt(value.observed_at_unix_s) &&
          BigInt(value.observed_at_unix_s) <=
            BigInt(certificate.not_after_unix_s))
    )
      throw new ApiError("format");
  }
  return value as unknown as AcmeStatus;
}

/** Date display is optional: exact u64 facts can exceed JavaScript's Date range. */
export function acmeDate(value: string): Date | null {
  if (!seconds(value) || BigInt(value) > 8640000000000n) return null;
  return new Date(Number(value) * 1000);
}
