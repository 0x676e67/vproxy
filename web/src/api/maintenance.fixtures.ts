import type { MaintenanceCommand, MaintenanceStatus } from "./maintenance";
import type { PolicyJob, Target } from "./targets";

export const LOCAL = "AAECAwQFBgcICQoLDA0ODw";
export const PEER = "EBESExQVFhcYGRobHB0eHw";
export const JOB = "ICEiIyQlJicoKSorLC0uLw";
export const maintenanceFixture = (remote = false): MaintenanceStatus => ({
  node_id: remote ? PEER : LOCAL,
  ownership: {
    controller_node_id: remote ? LOCAL : null,
    epoch: "2",
    last_terminal_command: "7",
  },
  saved_revision: "9",
  durable_applied_revision: "9",
  running: true,
  saved_accepting: true,
  applied_revision: "9",
  runtime_accepting: true,
  active_operations: "3",
});
export const targetFixture = (): Target => ({
  node_id: PEER,
  name: "Child",
  origin: "https://child.example",
  server_ip: null,
  active: true,
  retired: false,
  revision: "4",
  observed_epoch: null,
  observed_command: null,
  observed_policy_revision: null,
  rollback_detected: false,
});
export const maintenanceCommandFixture = (): MaintenanceCommand => ({
  expected_target_revision: "4",
  controller_epoch: "2",
  command_id: "8",
  expected_policy_revision: "9",
  mutation: { action: "set_admission", accepting: false },
});
export const maintenanceJobFixture = (): PolicyJob => ({
  node_id: PEER,
  job_id: JOB,
  controller_epoch: "2",
  command_id: "8",
  expected_policy_revision: "9",
  state: "pending",
  policy_revision: null,
  outcome_code: null,
  attempts: 0,
  next_attempt: "0",
  maintenance: { accepting: false },
});
export const maintenanceReplyFixture = () => ({
  job: { ...maintenanceJobFixture(), state: "applied", policy_revision: "10" },
  response: {
    receipt: {
      controller_epoch: "2",
      command_id: "8",
      status: "applied",
      policy_revision: "10",
      rejection: null,
      user_id: null,
      credential_id: null,
    },
    replayed: false,
    user: null,
    credential: null,
    secret: null,
    secret_available: false,
  },
});
