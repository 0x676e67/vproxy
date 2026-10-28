import {
  alertDecimal,
  alertKinds,
  alertSocket,
  type AlertKind,
  type AlertStatus,
} from "./alerts";
import { ApiError } from "./error";
import { canonicalId, canonicalRevision, count, shape } from "./proxy";

export const eventTransitions = [
  "opened",
  "reason_changed",
  "recovered",
  "unmonitored",
  "acknowledged",
] as const;
export type EventTransition = (typeof eventTransitions)[number];
type EndReason = null | "source_unmonitored" | "monitor_restarted";
interface Observation {
  node_id: string;
  boot_id: string;
  incident_id: string;
  kind: AlertKind;
  origin_node_id: string;
  resource_id: string | null;
  check: "bind" | "tcp" | null;
  target: string | null;
  code: string;
  first_observed_at_unix_ms: string | null;
  last_observed_at_unix_ms: string | null;
  evidence_sequence: string | null;
  end_reason: EndReason;
}
export interface AlertEvent extends Observation {
  sequence: string;
  episode_id: string;
  transition: EventTransition;
  observed_at_unix_ms: string | null;
  recorded_at_unix_ms: string | null;
  administrator_id: string | null;
  acknowledged_transition_sequence: string | null;
}
export interface AlertEpisode extends Observation {
  id: string;
  status: AlertStatus;
  ended_at_unix_ms: string | null;
  latest_transition_sequence: string;
  acknowledged_transition_sequence: string | null;
  acknowledged_by: string | null;
  acknowledged_at_unix_ms: string | null;
  acknowledgement_event_sequence: string | null;
  is_acknowledged: boolean;
}
export interface AlertEventOptions {
  before?: string;
  limit?: number;
  origin_node_id?: string;
  episode_id?: string;
}
export interface AlertEventPage {
  node_id: string;
  items: AlertEvent[];
  next_cursor: string | null;
  oldest_sequence: string | null;
  trimmed: string;
}
export interface AlertSummary {
  node_id: string;
  retained_episode_count: number;
  retained_event_count: number;
  unacknowledged_count: number;
  oldest_sequence: string | null;
  trimmed: string;
}
export interface AlertAcknowledgementInput {
  expected_node_id: string;
  expected_transition_sequence: string;
}
export interface UnreadAlertOptions {
  before?: string;
  through?: string;
}
export interface UnreadAlertPage {
  node_id: string;
  items: AlertEpisode[];
  next_cursor: string | null;
  through_sequence: string;
}
export interface AlertAcknowledgementBatch {
  expected_node_id: string;
  items: { episode_id: string; expected_transition_sequence: string }[];
}
const invalid = (): never => {
  throw new ApiError("format");
};
const nullableCounter = (value: unknown) =>
  value === null || alertDecimal(value);
const nullableRevision = (value: unknown) =>
  value === null || canonicalRevision(value);
const observationKeys = [
  "node_id",
  "boot_id",
  "incident_id",
  "kind",
  "origin_node_id",
  "resource_id",
  "check",
  "target",
  "code",
  "first_observed_at_unix_ms",
  "last_observed_at_unix_ms",
  "evidence_sequence",
  "end_reason",
];
function observation(value: Record<string, unknown>, node: string): void {
  if (
    !canonicalId(node) ||
    value.node_id !== node ||
    !canonicalId(value.boot_id) ||
    !alertDecimal(value.incident_id) ||
    value.incident_id === "0" ||
    !alertKinds.includes(value.kind as AlertKind) ||
    !canonicalId(value.origin_node_id) ||
    (value.kind === "remote_observation" && value.origin_node_id === node) ||
    !(value.resource_id === null || canonicalId(value.resource_id)) ||
    (["management_https", "node_tls", "remote_observation"].includes(
      value.kind as string,
    ) &&
      value.resource_id !== null) ||
    (value.kind === "proxy_tls" && !canonicalId(value.resource_id)) ||
    (value.kind === "egress_check"
      ? !canonicalId(value.resource_id) ||
        !(value.check === "bind"
          ? value.target === null
          : value.check === "tcp" && alertSocket(value.target))
      : value.check !== null || value.target !== null) ||
    typeof value.code !== "string" ||
    !/^[a-z][a-z0-9_]{0,63}$/.test(value.code) ||
    !nullableCounter(value.first_observed_at_unix_ms) ||
    !nullableCounter(value.last_observed_at_unix_ms) ||
    !nullableCounter(value.evidence_sequence) ||
    !(
      value.end_reason === null ||
      value.end_reason === "source_unmonitored" ||
      value.end_reason === "monitor_restarted"
    )
  )
    invalid();
}
/** Immutable recorded facts. No age/freshness is synthesized across process boots. */
export function alertEvent(
  value: unknown,
  node: string,
  exact?: string,
): AlertEvent {
  shape(value, [
    ...observationKeys,
    "sequence",
    "episode_id",
    "transition",
    "observed_at_unix_ms",
    "recorded_at_unix_ms",
    "administrator_id",
    "acknowledged_transition_sequence",
  ]);
  observation(value, node);
  if (
    !canonicalRevision(value.sequence) ||
    !canonicalRevision(value.episode_id) ||
    BigInt(value.episode_id) > BigInt(value.sequence) ||
    (value.transition === "opened" && value.episode_id !== value.sequence) ||
    (exact !== undefined &&
      (!canonicalRevision(exact) || value.sequence !== exact)) ||
    !eventTransitions.includes(value.transition as EventTransition) ||
    !nullableCounter(value.observed_at_unix_ms) ||
    !nullableCounter(value.recorded_at_unix_ms) ||
    (value.transition === "unmonitored") !== (value.end_reason !== null) ||
    (value.transition === "acknowledged"
      ? !canonicalId(value.administrator_id) ||
        !canonicalRevision(value.acknowledged_transition_sequence) ||
        BigInt(value.acknowledged_transition_sequence) <
          BigInt(value.episode_id) ||
        BigInt(value.acknowledged_transition_sequence) >= BigInt(value.sequence)
      : value.administrator_id !== null ||
        value.acknowledged_transition_sequence !== null)
  )
    return invalid();
  return { ...value } as unknown as AlertEvent;
}
/** The latest retained projection remains historical, even for an active episode. */
export function alertEpisode(
  value: unknown,
  node: string,
  exact: string,
): AlertEpisode {
  shape(value, [
    ...observationKeys,
    "id",
    "status",
    "ended_at_unix_ms",
    "latest_transition_sequence",
    "acknowledged_transition_sequence",
    "acknowledged_by",
    "acknowledged_at_unix_ms",
    "acknowledgement_event_sequence",
    "is_acknowledged",
  ]);
  observation(value, node);
  if (
    !canonicalRevision(exact) ||
    value.id !== exact ||
    !["active", "recovered", "unmonitored"].includes(value.status as string) ||
    !nullableCounter(value.ended_at_unix_ms) ||
    !canonicalRevision(value.latest_transition_sequence) ||
    BigInt(exact) > BigInt(value.latest_transition_sequence) ||
    typeof value.is_acknowledged !== "boolean" ||
    (value.status === "active" &&
      (value.ended_at_unix_ms !== null || value.end_reason !== null)) ||
    (value.status === "unmonitored" && value.end_reason === null) ||
    (value.status === "recovered" && value.end_reason !== null)
  )
    return invalid();
  const acknowledged = value.acknowledged_transition_sequence;
  if (
    acknowledged === null
      ? value.acknowledged_by !== null ||
        value.acknowledged_at_unix_ms !== null ||
        value.acknowledgement_event_sequence !== null ||
        value.is_acknowledged
      : !canonicalRevision(acknowledged) ||
        BigInt(acknowledged) < BigInt(exact) ||
        !canonicalId(value.acknowledged_by) ||
        !nullableCounter(value.acknowledged_at_unix_ms) ||
        !canonicalRevision(value.acknowledgement_event_sequence) ||
        BigInt(acknowledged) > BigInt(value.latest_transition_sequence) ||
        BigInt(value.acknowledgement_event_sequence) <= BigInt(acknowledged) ||
        value.is_acknowledged !==
          (acknowledged === value.latest_transition_sequence)
  )
    return invalid();
  return { ...value } as unknown as AlertEpisode;
}
export function alertEventQuery(options: AlertEventOptions): string {
  if (
    typeof options !== "object" ||
    options === null ||
    Array.isArray(options) ||
    Object.keys(options).some(
      (key) =>
        !["before", "limit", "origin_node_id", "episode_id"].includes(key),
    ) ||
    (options.before !== undefined && !canonicalRevision(options.before)) ||
    (options.limit !== undefined && !count(options.limit, 50, 1)) ||
    (options.origin_node_id !== undefined &&
      !canonicalId(options.origin_node_id)) ||
    (options.episode_id !== undefined && !canonicalRevision(options.episode_id))
  )
    return invalid();
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(options))
    if (value !== undefined) query.set(key, String(value));
  return query.size ? `?${query}` : "";
}
export function alertEventPage(
  value: unknown,
  node: string,
  options: AlertEventOptions,
): AlertEventPage {
  alertEventQuery(options);
  shape(value, [
    "node_id",
    "items",
    "next_cursor",
    "oldest_sequence",
    "trimmed",
  ]);
  if (
    !canonicalId(node) ||
    value.node_id !== node ||
    !Array.isArray(value.items) ||
    value.items.length > (options.limit ?? 25) ||
    !nullableRevision(value.next_cursor) ||
    !nullableRevision(value.oldest_sequence) ||
    !alertDecimal(value.trimmed)
  )
    return invalid();
  const items = value.items.map((item) => alertEvent(item, node)),
    last = items.at(-1);
  if (
    items.some(
      (item, index) =>
        (index > 0 &&
          BigInt(item.sequence) >= BigInt(items[index - 1].sequence)) ||
        (options.before !== undefined &&
          BigInt(item.sequence) >= BigInt(options.before)) ||
        (options.origin_node_id !== undefined &&
          item.origin_node_id !== options.origin_node_id) ||
        (options.episode_id !== undefined &&
          item.episode_id !== options.episode_id),
    ) ||
    (last &&
      (value.oldest_sequence === null ||
        BigInt(last.sequence) < BigInt(value.oldest_sequence))) ||
    (value.next_cursor !== null &&
      (items.length !== (options.limit ?? 25) ||
        last?.sequence !== value.next_cursor))
  )
    return invalid();
  return {
    node_id: node,
    items,
    next_cursor: value.next_cursor,
    oldest_sequence: value.oldest_sequence,
    trimmed: value.trimmed,
  };
}
export function alertSummary(value: unknown, node?: string): AlertSummary {
  shape(value, [
    "node_id",
    "retained_episode_count",
    "retained_event_count",
    "unacknowledged_count",
    "oldest_sequence",
    "trimmed",
  ]);
  if (
    !canonicalId(value.node_id) ||
    (node !== undefined && value.node_id !== node) ||
    !count(value.retained_episode_count, 16_384) ||
    !count(value.retained_event_count, 16_384) ||
    !count(value.unacknowledged_count, value.retained_episode_count) ||
    !nullableRevision(value.oldest_sequence) ||
    !alertDecimal(value.trimmed) ||
    (value.retained_event_count === 0) !== (value.oldest_sequence === null)
  )
    return invalid();
  return { ...value } as unknown as AlertSummary;
}
export function alertAcknowledgementInput(
  value: AlertAcknowledgementInput,
): AlertAcknowledgementInput {
  shape(value, ["expected_node_id", "expected_transition_sequence"]);
  if (
    !canonicalId(value.expected_node_id) ||
    !canonicalRevision(value.expected_transition_sequence)
  )
    return invalid();
  return { ...value };
}

/** The inbox only returns unread retained projections up to one fixed fence. */
export function unreadAlertQuery(options: UnreadAlertOptions): string {
  const query = new URLSearchParams();
  if (options.before !== undefined) {
    if (!canonicalRevision(options.before)) return invalid();
    query.set("before", options.before);
  }
  if (options.through !== undefined) {
    if (
      !alertDecimal(options.through) ||
      BigInt(options.through) > 9_223_372_036_854_775_807n
    )
      return invalid();
    query.set("through", options.through);
  }
  return query.size ? `?${query}` : "";
}
export function unreadAlertPage(
  value: unknown,
  node: string,
  options: UnreadAlertOptions,
): UnreadAlertPage {
  unreadAlertQuery(options);
  shape(value, ["node_id", "items", "next_cursor", "through_sequence"]);
  if (
    !canonicalId(node) ||
    value.node_id !== node ||
    !Array.isArray(value.items) ||
    value.items.length > 32 ||
    !nullableRevision(value.next_cursor) ||
    !alertDecimal(value.through_sequence) ||
    BigInt(value.through_sequence) > 9_223_372_036_854_775_807n ||
    (options.through !== undefined &&
      value.through_sequence !== options.through)
  )
    return invalid();
  const items = value.items.map((item) => {
    if (
      typeof item !== "object" ||
      item === null ||
      !canonicalRevision(item.id)
    )
      return invalid();
    return alertEpisode(item, node, item.id);
  });
  if (
    items.some(
      (item, index) =>
        item.is_acknowledged ||
        BigInt(item.latest_transition_sequence) >
          BigInt(value.through_sequence as string) ||
        (options.before !== undefined &&
          BigInt(item.id) >= BigInt(options.before)) ||
        (index > 0 && BigInt(item.id) >= BigInt(items[index - 1].id)),
    ) ||
    (value.next_cursor !== null &&
      (items.length !== 32 || value.next_cursor !== items.at(-1)?.id))
  )
    return invalid();
  return {
    node_id: node,
    items,
    next_cursor: value.next_cursor,
    through_sequence: value.through_sequence,
  };
}
export function alertAcknowledgementBatch(
  value: AlertAcknowledgementBatch,
): AlertAcknowledgementBatch {
  shape(value, ["expected_node_id", "items"]);
  if (
    !canonicalId(value.expected_node_id) ||
    !Array.isArray(value.items) ||
    !value.items.length ||
    value.items.length > 32
  )
    return invalid();
  const seen = new Set<string>();
  const items = value.items.map((item) => {
    shape(item, ["episode_id", "expected_transition_sequence"]);
    alertAcknowledgementInput({
      expected_node_id: value.expected_node_id,
      expected_transition_sequence: item.expected_transition_sequence,
    });
    if (
      !canonicalRevision(item.episode_id) ||
      seen.has(item.episode_id) ||
      BigInt(item.episode_id) > BigInt(item.expected_transition_sequence)
    )
      return invalid();
    seen.add(item.episode_id);
    return { ...item };
  });
  return { expected_node_id: value.expected_node_id, items };
}
export function alertAcknowledgementResult(
  value: unknown,
  input: AlertAcknowledgementBatch,
): AlertEpisode[] {
  shape(value, ["node_id", "items"]);
  if (
    value.node_id !== input.expected_node_id ||
    !Array.isArray(value.items) ||
    value.items.length !== input.items.length
  )
    return invalid();
  return value.items.map((item, index) => {
    const intent = input.items[index];
    const result = alertEpisode(
      item,
      input.expected_node_id,
      intent.episode_id,
    );
    if (
      !result.is_acknowledged ||
      result.latest_transition_sequence !==
        intent.expected_transition_sequence ||
      result.acknowledged_transition_sequence !==
        intent.expected_transition_sequence
    )
      return invalid();
    return result;
  });
}
