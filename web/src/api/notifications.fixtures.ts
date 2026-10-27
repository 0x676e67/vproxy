import type { Delivery, WebhookChange, WebhookView } from "./notifications";
export const WEBHOOK_NODE = "N".repeat(21) + "Q";
export const WEBHOOK_OPERATION = "O".repeat(21) + "A";
export const WEBHOOK_DELIVERY = "D".repeat(21) + "A";
export const webhookFixture = (): WebhookView => ({
  node_id: WEBHOOK_NODE,
  revision: "0",
  enabled: false,
  automatic_retry: false,
  configured: false,
  has_bearer: false,
  operation_id: null,
  cursor: "0",
  skipped_through: "0",
  last_accepted_delivery_id: null,
  discarded_delivery_id: null,
  pending: null,
});
export const deliveryFixture = (): Delivery => ({
  id: WEBHOOK_DELIVERY,
  attempts: 1,
  outcome: "unknown",
  http_status: null,
  after_sequence: "0",
  through_sequence: "1",
  history_trimmed_through: "0",
  event_count: 1,
  automatic_retry_eligible: false,
});
export const webhookChangeFixture = (): WebhookChange => ({
  expected_node_id: WEBHOOK_NODE,
  expected_revision: "0",
  operation_id: WEBHOOK_OPERATION,
  enabled: true,
  automatic_retry: false,
  url: "https://hooks.example/test-private?key=fixture",
  bearer: "fixture-token",
  clear_bearer: false,
  clear_destination: false,
  discard_pending: false,
});
