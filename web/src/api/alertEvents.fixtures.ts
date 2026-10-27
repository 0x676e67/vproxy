import type {
  AlertEvent,
  AlertEpisode,
  AlertEventPage,
  AlertSummary,
} from "./alertEvents";
export const EVENT_NODE = "AAECAwQFBgcICQoLDA0ODw",
  EVENT_BOOT = "EBESExQVFhcYGRobHB0eHw",
  EVENT_ACTOR = "A".repeat(22),
  EVENT_OTHER = "ICEiIyQlJicoKSorLC0uLw";
const observation = () => ({
  node_id: EVENT_NODE,
  boot_id: EVENT_BOOT,
  incident_id: "1",
  kind: "policy" as const,
  origin_node_id: EVENT_NODE,
  resource_id: null,
  check: null,
  target: null,
  code: "policy_not_applied",
  first_observed_at_unix_ms: "1780000000000",
  last_observed_at_unix_ms: "1780000001000",
  evidence_sequence: "2",
  end_reason: null,
});
export const eventFixture = (): AlertEvent => ({
  ...observation(),
  sequence: "1",
  episode_id: "1",
  transition: "opened",
  observed_at_unix_ms: "1780000001000",
  recorded_at_unix_ms: "1780000001001",
  administrator_id: null,
  acknowledged_transition_sequence: null,
});
export const episodeFixture = (acknowledged = false): AlertEpisode => ({
  ...observation(),
  id: "1",
  status: "active",
  ended_at_unix_ms: null,
  latest_transition_sequence: "1",
  acknowledged_transition_sequence: acknowledged ? "1" : null,
  acknowledged_by: acknowledged ? EVENT_ACTOR : null,
  acknowledged_at_unix_ms: acknowledged ? "1780000002000" : null,
  acknowledgement_event_sequence: acknowledged ? "2" : null,
  is_acknowledged: acknowledged,
});
export const eventPageFixture = (): AlertEventPage => ({
  node_id: EVENT_NODE,
  items: [eventFixture()],
  next_cursor: null,
  oldest_sequence: "1",
  trimmed: "0",
});
export const summaryFixture = (): AlertSummary => ({
  node_id: EVENT_NODE,
  retained_episode_count: 1,
  retained_event_count: 1,
  unacknowledged_count: 1,
  oldest_sequence: "1",
  trimmed: "0",
});
