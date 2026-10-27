/** Test-only declarations and durable metadata tickets. Never client credentials. */
export const LOCAL = "A".repeat(22);
export const PEER = "AQEBAQEBAQEBAQEBAQEBAQ";
export const LISTENER = "AgICAgICAgICAgICAgICAg";
export const JOB = "AwMDAwMDAwMDAwMDAwMDAw";
export const GENERATION = "ab".repeat(32);
export const settingsFixture = (node = LOCAL) => ({
  node_id: node,
  proxy_running: false,
  revision: "4",
  generation: GENERATION,
  listeners: [
    {
      id: LISTENER,
      protocol: "auto",
      bind: "0.0.0.0:1080",
      configured_public_address: "startup.example:1080",
      selection: { mode: "inherit" },
      public_address: "startup.example:1080",
    },
  ],
  detached: [] as unknown[],
});
export const metadataJobFixture = () => ({
  resource: "proxy_endpoints",
  node_id: PEER,
  job_id: JOB,
  controller_epoch: "2",
  command_id: "8",
  expected_policy_revision: null,
  policy_revision: null,
  expected_metadata_revision: "4",
  metadata_revision: null as string | null,
  state: "pending",
  outcome_code: null,
  attempts: 0,
  next_attempt: "0",
  endpoint: { listener_id: LISTENER, generation: GENERATION },
});
export const endpointCommandFixture = () => ({
  expected_target_revision: "3",
  controller_epoch: "2",
  command_id: "8",
  expected_metadata_revision: "4",
  mutation: {
    listener_id: LISTENER,
    generation: GENERATION,
    selection: { mode: "hidden" as const },
  },
});
export const targetFixture = () => ({
  node_id: PEER,
  name: "Endpoint fixture node",
  origin: "https://node.example:9443",
  active: true,
  retired: false,
  revision: "3",
  observed_epoch: "2",
  observed_command: "7",
  observed_policy_revision: "9",
  rollback_detected: false,
});
export const endpointPolicyFixture = () => ({
  saved_revision: "9",
  applied_revision: null,
  durable_applied_revision: null,
  proxy_running: false,
  user_count: 0,
  credential_count: 0,
});
export const endpointRemotePolicyFixture = () => ({
  ...endpointPolicyFixture(),
  controller_node_id: LOCAL,
  controller_epoch: "2",
  last_terminal_command: "7",
});
