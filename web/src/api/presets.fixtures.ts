import type { PresetCapability, UserPreset, PoolPreset } from "./presets";
import type { PresetCommandInput } from "./remotePresets";
export const NODE = "A".repeat(22),
  USER = "AQEBAQEBAQEBAQEBAQEBAQ",
  POOL = "AgICAgICAgICAgICAgICAg";
export const capabilityFixture = (): PresetCapability => ({
  node_id: NODE,
  capability_version: 1,
  backend_state: "ready",
  reason_code: null,
  preset_revision: "1",
  abi_version: 1,
  available_presets: ["windows", "linux", "android", "macos", "ios"],
  operations: ["http_forward", "http_connect", "socks5_connect"],
  observed_at_unix_ms: 1,
});
export const userPresetFixture = (): UserPreset => ({
  user_id: USER,
  default_preset: "linux",
  allowed_presets: ["windows", "linux"],
});
export const poolPresetFixture = (): PoolPreset => ({
  pool_id: POOL,
  default_preset: "windows",
});
export const presetCommandFixture = (): PresetCommandInput => ({
  expected_target_revision: "2",
  controller_epoch: "3",
  command_id: "4",
  expected_policy_revision: "5",
  mutation: { action: "set_user_presets", presets: userPresetFixture() },
});
export const presetTicketFixture = () => ({
  node_id: NODE,
  job_id: POOL,
  controller_epoch: "3",
  command_id: "4",
  expected_policy_revision: "5",
  state: "pending",
  policy_revision: null,
  outcome_code: null,
  attempts: 0,
  next_attempt: "0",
});
export const presetReplyFixture = () => ({
  job: presetTicketFixture(),
  response: {
    receipt: {
      controller_epoch: "3",
      command_id: "4",
      status: "applied",
      policy_revision: "6",
      rejection: null,
      user_id: null,
      credential_id: null,
      preset: { kind: "user", id: USER },
    },
    replayed: false,
    user: null,
    credential: null,
    secret: null,
    secret_available: false,
    presets: { kind: "user", value: userPresetFixture() },
  },
});
