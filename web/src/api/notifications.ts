import { ApiError } from "./error";
import { canonicalId, canonicalRevision, count, shape } from "./proxy";

export const deliveryOutcomes = [
  "ready",
  "sending",
  "rejected",
  "deferred",
  "unknown",
  "destination_blocked",
] as const;
export interface Delivery {
  id: string;
  attempts: number;
  outcome: (typeof deliveryOutcomes)[number];
  http_status: number | null;
  after_sequence: string;
  through_sequence: string;
  history_trimmed_through: string;
  event_count: number;
  automatic_retry_eligible: boolean;
}
export interface WebhookView {
  node_id: string;
  revision: string;
  enabled: boolean;
  automatic_retry: boolean;
  configured: boolean;
  has_bearer: boolean;
  operation_id: string | null;
  cursor: string;
  skipped_through: string;
  last_accepted_delivery_id: string | null;
  discarded_delivery_id: string | null;
  pending: Delivery | null;
}
export interface WebhookChange {
  expected_node_id: string;
  expected_revision: string;
  operation_id: string;
  enabled: boolean;
  automatic_retry: boolean;
  url: string | null;
  bearer: string | null;
  clear_bearer: boolean;
  clear_destination: boolean;
  discard_pending: boolean;
}
export interface WebhookRetry {
  expected_node_id: string;
  expected_revision: string;
  delivery_id: string;
  expected_attempts: number;
}
export const counter = (value: unknown): value is string =>
  value === "0" || canonicalRevision(value);
const nullableId = (value: unknown) => value === null || canonicalId(value);
const invalid = (): never => {
  throw new ApiError("format");
};

/** Exact public shape rejects secret-bearing responses instead of retaining
 * accidental URL/token fields in UI state, history or browser-local notes. */
export function webhookView(value: unknown, nodeId: string): WebhookView {
  shape(value, [
    "node_id",
    "revision",
    "enabled",
    "automatic_retry",
    "configured",
    "has_bearer",
    "operation_id",
    "cursor",
    "skipped_through",
    "last_accepted_delivery_id",
    "discarded_delivery_id",
    "pending",
  ]);
  if (
    !canonicalId(nodeId) ||
    value.node_id !== nodeId ||
    !counter(value.revision) ||
    !counter(value.cursor) ||
    !counter(value.skipped_through) ||
    BigInt(value.skipped_through) > BigInt(value.cursor) ||
    ![
      value.enabled,
      value.automatic_retry,
      value.configured,
      value.has_bearer,
    ].every((v) => typeof v === "boolean") ||
    (value.enabled && !value.configured) ||
    (value.has_bearer && !value.configured) ||
    ![
      value.operation_id,
      value.last_accepted_delivery_id,
      value.discarded_delivery_id,
    ].every(nullableId) ||
    (value.revision === "0") !== (value.operation_id === null)
  )
    return invalid();
  if (value.pending !== null) {
    const p = value.pending;
    shape(p, [
      "id",
      "attempts",
      "outcome",
      "http_status",
      "after_sequence",
      "through_sequence",
      "history_trimmed_through",
      "event_count",
      "automatic_retry_eligible",
    ]);
    if (
      !value.enabled ||
      !canonicalId(p.id) ||
      !count(p.attempts, 4_294_967_295, 1) ||
      !deliveryOutcomes.includes(p.outcome as Delivery["outcome"]) ||
      !counter(p.after_sequence) ||
      !canonicalRevision(p.through_sequence) ||
      !counter(p.history_trimmed_through) ||
      p.after_sequence !== value.cursor ||
      BigInt(p.through_sequence) <= BigInt(p.after_sequence) ||
      BigInt(p.history_trimmed_through) > BigInt(p.through_sequence) ||
      !count(p.event_count, 16) ||
      typeof p.automatic_retry_eligible !== "boolean" ||
      (p.outcome === "rejected" || p.outcome === "deferred"
        ? !count(p.http_status, 599, 100) ||
          (p.http_status >= 200 && p.http_status <= 299)
        : p.http_status !== null) ||
      (p.automatic_retry_eligible &&
        (!value.automatic_retry ||
          p.attempts >= 6 ||
          !(
            p.outcome === "unknown" ||
            (p.outcome === "rejected" &&
              typeof p.http_status === "number" &&
              (p.http_status === 408 ||
                p.http_status === 429 ||
                p.http_status >= 500))
          )))
    )
      return invalid();
  }
  return value as unknown as WebhookView;
}

/** Syntax preflight only. The server separately rejects special/private
 * addresses and pins every admitted DNS answer before opening a connection. */
export function webhookChange(input: WebhookChange): WebhookChange {
  shape(input, [
    "expected_node_id",
    "expected_revision",
    "operation_id",
    "enabled",
    "automatic_retry",
    "url",
    "bearer",
    "clear_bearer",
    "clear_destination",
    "discard_pending",
  ]);
  if (
    !canonicalId(input.expected_node_id) ||
    !canonicalId(input.operation_id) ||
    !counter(input.expected_revision) ||
    ![
      input.enabled,
      input.automatic_retry,
      input.clear_bearer,
      input.clear_destination,
      input.discard_pending,
    ].every((v) => typeof v === "boolean") ||
    (input.bearer !== null &&
      (typeof input.bearer !== "string" ||
        input.bearer.length > 1024 ||
        !/^[A-Za-z0-9\-._~+/]+=*$/.test(input.bearer))) ||
    (input.bearer !== null && input.clear_bearer) ||
    (input.clear_destination &&
      (input.enabled ||
        input.url !== null ||
        input.bearer !== null ||
        input.clear_bearer))
  )
    return invalid();
  if (input.url !== null) {
    if (
      typeof input.url !== "string" ||
      !input.url ||
      !/^https:\/\//i.test(input.url) ||
      new TextEncoder().encode(input.url).length > 2048 ||
      /[\u0000-\u001f\u007f-\u009f]/.test(input.url)
    )
      return invalid();
    let url: URL;
    try {
      url = new URL(input.url);
    } catch {
      return invalid();
    }
    if (
      url.protocol !== "https:" ||
      !url.hostname ||
      url.username ||
      url.password ||
      input.url
        .split("://")[1]
        ?.split(/[/?#\\]/)[0]
        .includes("@") ||
      url.hash ||
      input.url.includes("#") ||
      url.port === "0"
    )
      return invalid();
  }
  if (new TextEncoder().encode(JSON.stringify(input)).length > 4096)
    return invalid();
  return input;
}
export function webhookRetry(input: WebhookRetry): WebhookRetry {
  shape(input, [
    "expected_node_id",
    "expected_revision",
    "delivery_id",
    "expected_attempts",
  ]);
  if (
    !canonicalId(input.expected_node_id) ||
    !canonicalId(input.delivery_id) ||
    !canonicalRevision(input.expected_revision) ||
    !count(input.expected_attempts, 4_294_967_294, 1)
  )
    return invalid();
  return input;
}
