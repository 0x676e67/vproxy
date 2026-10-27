import type { CommandHistoryEntry, CommandHistoryPage } from "./commandHistory";

export const HISTORY_LOCAL = "AAECAwQFBgcICQoLDA0ODw";
export const HISTORY_PEER = "EBESExQVFhcYGRobHB0eHw";
export const HISTORY_JOB = "ICEiIyQlJicoKSorLC0uLw";
export const HISTORY_USER = "MDEyMzQ1Njc4OTo7PD0-Pw";
export const HISTORY_CREDENTIAL = "QEFCQ0RFRkdISUpLTE1OTw";
export function historyEntry(): CommandHistoryEntry {
  return {
    sequence: "7",
    controller_node_id: HISTORY_LOCAL,
    administrator_id: HISTORY_USER,
    protocol_version: 1,
    action: "create_user",
    job: {
      node_id: HISTORY_PEER,
      job_id: HISTORY_JOB,
      controller_epoch: "2",
      command_id: "4",
      expected_policy_revision: "9",
      state: "applied",
      policy_revision: "10",
      outcome_code: null,
      attempts: 1,
      next_attempt: "0",
      user_creation: true,
    },
    user_id: HISTORY_USER,
    credential_id: null,
    imported: false,
    recorded_at_unix_s: "1700000000",
    updated_at_unix_s: "1700000001",
  };
}
export function historyPage(): CommandHistoryPage {
  return {
    items: [historyEntry()],
    next_cursor: null,
    oldest_sequence: "7",
    trimmed: false,
  };
}
