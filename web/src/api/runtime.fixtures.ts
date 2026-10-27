import type { DrainRequest, RuntimePhase, RuntimeStatus } from "./runtime";
import { LOCAL, PEER, JOB } from "./maintenance.fixtures";
export const RUNTIME = "MDEyMzQ1Njc4OTo7PD0-Pw";
export const drainFixture = (remote = false): DrainRequest => ({
  expected_node_id: remote ? PEER : LOCAL,
  expected_epoch: "2",
  expected_revision: "9",
  runtime_id: RUNTIME,
  request_id: JOB,
});
export const runtimeFixture = (
  remote = false,
  phase: RuntimePhase = "serving",
): RuntimeStatus => ({
  node_id: remote ? PEER : LOCAL,
  ownership: {
    controller_node_id: remote ? LOCAL : null,
    epoch: "2",
    last_terminal_command: "7",
  },
  saved_revision: "9",
  saved_accepting: false,
  runtime: {
    runtime_id: RUNTIME,
    phase,
    request: phase === "serving" ? null : drainFixture(remote),
    active_operations: "3",
  },
});
