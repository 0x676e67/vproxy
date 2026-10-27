import { ApiError } from "./error";
import { canonicalId, canonicalRevision, count, shape } from "./proxy";

export const presetNames = [
  "windows",
  "linux",
  "android",
  "macos",
  "ios",
] as const;
export type Preset = (typeof presetNames)[number];
export const presetOperations = [
  "http_forward",
  "http_connect",
  "socks5_connect",
] as const;
export type PresetOperation = (typeof presetOperations)[number];
export const presetBackendStates = [
  "ready",
  "disabled",
  "unsupported",
  "unavailable",
] as const;
export interface PresetCapability {
  node_id: string;
  capability_version: 1;
  backend_state: (typeof presetBackendStates)[number];
  reason_code:
    | null
    | "not_configured"
    | "feature_disabled"
    | "platform_unsupported"
    | "proxy_unavailable";
  preset_revision: "1";
  abi_version: 1 | null;
  available_presets: Preset[];
  operations: PresetOperation[];
  observed_at_unix_ms: number | null;
}
export interface UserPreset {
  user_id: string;
  default_preset: Preset | null;
  allowed_presets: Preset[];
}
export interface PoolPreset {
  pool_id: string;
  default_preset: Preset | null;
}
export interface UserPresetView {
  revision: string;
  presets: UserPreset;
}
export interface PoolPresetView {
  revision: string;
  preset: PoolPreset;
}
export interface PresetReference {
  kind: "user" | "pool";
  id: string;
}
export type PresetEntity =
  { kind: "user"; data: UserPreset } | { kind: "pool"; data: PoolPreset };
export type PresetWireEntity =
  { kind: "user"; value: UserPreset } | { kind: "pool"; value: PoolPreset };
export function presetEntity(value: unknown): PresetWireEntity {
  shape(value, ["kind", "value"]);
  if (value.kind === "user")
    return { kind: "user", value: userPreset(value.value) };
  if (value.kind === "pool")
    return { kind: "pool", value: poolPreset(value.value) };
  throw new ApiError("format");
}
export function isPreset(value: unknown): value is Preset {
  return presetNames.includes(value as Preset);
}
const list = <T extends string>(
  value: unknown,
  allowed: readonly T[],
): value is T[] =>
  Array.isArray(value) &&
  value.length <= allowed.length &&
  new Set(value).size === value.length &&
  value.every((item) => allowed.includes(item));
export function presetCapability(
  value: unknown,
  node?: string,
): PresetCapability {
  shape(value, [
    "node_id",
    "capability_version",
    "backend_state",
    "reason_code",
    "preset_revision",
    "abi_version",
    "available_presets",
    "operations",
    "observed_at_unix_ms",
  ]);
  if (
    !canonicalId(value.node_id) ||
    (node !== undefined && value.node_id !== node) ||
    value.capability_version !== 1 ||
    !presetBackendStates.includes(
      value.backend_state as PresetCapability["backend_state"],
    ) ||
    value.preset_revision !== "1" ||
    !(value.abi_version === null || value.abi_version === 1) ||
    !(
      value.observed_at_unix_ms === null ||
      count(value.observed_at_unix_ms, Number.MAX_SAFE_INTEGER)
    ) ||
    !list(value.available_presets, presetNames) ||
    !list(value.operations, presetOperations) ||
    !(
      value.reason_code === null ||
      [
        "not_configured",
        "feature_disabled",
        "platform_unsupported",
        "proxy_unavailable",
      ].includes(value.reason_code as string)
    )
  )
    throw new ApiError("format");
  const ready = value.backend_state === "ready";
  const reasons = {
    disabled: ["not_configured", "feature_disabled"],
    unsupported: ["platform_unsupported"],
    unavailable: ["proxy_unavailable"],
  };
  if (
    ready
      ? value.reason_code !== null ||
        value.abi_version !== 1 ||
        value.available_presets.length !== 5 ||
        value.operations.length !== 3
      : value.abi_version !== null ||
        value.reason_code === null ||
        !reasons[value.backend_state as keyof typeof reasons]?.includes(
          value.reason_code as string,
        ) ||
        value.available_presets.length !== 0 ||
        value.operations.length !== 0
  )
    throw new ApiError("format");
  return value as unknown as PresetCapability;
}
export function userPreset(value: unknown, id?: string): UserPreset {
  shape(value, ["user_id", "default_preset", "allowed_presets"]);
  if (
    !canonicalId(value.user_id) ||
    (id !== undefined && value.user_id !== id) ||
    !(value.default_preset === null || isPreset(value.default_preset)) ||
    !list(value.allowed_presets, presetNames) ||
    (value.default_preset !== null &&
      !value.allowed_presets.includes(value.default_preset))
  )
    throw new ApiError("format");
  return {
    user_id: value.user_id,
    default_preset: value.default_preset,
    allowed_presets: [...value.allowed_presets],
  };
}
export function poolPreset(value: unknown, id?: string): PoolPreset {
  shape(value, ["pool_id", "default_preset"]);
  if (
    !canonicalId(value.pool_id) ||
    (id !== undefined && value.pool_id !== id) ||
    !(value.default_preset === null || isPreset(value.default_preset))
  )
    throw new ApiError("format");
  return value as unknown as PoolPreset;
}
export function userPresetView(value: unknown, id: string): UserPresetView {
  shape(value, ["revision", "presets"]);
  if (!canonicalRevision(value.revision)) throw new ApiError("format");
  return { revision: value.revision, presets: userPreset(value.presets, id) };
}
export function poolPresetView(value: unknown, id: string): PoolPresetView {
  shape(value, ["revision", "preset"]);
  if (!canonicalRevision(value.revision)) throw new ApiError("format");
  return { revision: value.revision, preset: poolPreset(value.preset, id) };
}
export function presetReference(value: unknown): PresetReference {
  shape(value, ["kind", "id"]);
  if (
    !["user", "pool"].includes(value.kind as string) ||
    !canonicalId(value.id)
  )
    throw new ApiError("format");
  return value as unknown as PresetReference;
}
export function sameUserPreset(left: UserPreset, right: UserPreset): boolean {
  return (
    left.user_id === right.user_id &&
    left.default_preset === right.default_preset &&
    left.allowed_presets.length === right.allowed_presets.length &&
    left.allowed_presets.every((name) => right.allowed_presets.includes(name))
  );
}
