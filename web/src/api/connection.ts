import { ApiError } from "./error";
import { shape, type ProxyProtocol } from "./proxy";
import {
  permissionInput,
  routingToken,
  validIp,
  type RoutePermission,
} from "./routing";
import {
  isPreset,
  userPreset,
  poolPreset,
  type Preset,
  type UserPreset,
  type PoolPreset,
  type PresetCapability,
} from "./presets";

export type ConnectionOperation =
  | "http_forward"
  | "http_connect"
  | "socks5_connect"
  | "socks5_bind"
  | "socks5_udp"
  | "masque_udp";
export type ConnectionRoute =
  | { kind: "default" }
  | { kind: "exit" | "pool"; id: string }
  | { kind: "session" | "range" | "ttl"; value: string };
export interface ConnectionInput {
  login: string;
  protocol: ProxyProtocol | "https";
  operation: ConnectionOperation;
  host: string;
  port: string;
  route: ConnectionRoute;
  device: Preset | null;
}
export function connectionHost(value: string): string {
  if (typeof value !== "string") throw new ApiError("format");
  const host =
    value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1) : value;
  if (validIp(host as unknown)) {
    if (
      host === "0.0.0.0" ||
      (host.includes(":") && new URL(`http://[${host}]/`).hostname === "[::]")
    )
      throw new ApiError("format");
    return host;
  }
  if (/^[0-9.]+$/.test(host)) throw new ApiError("format");
  if (
    host.length > 253 ||
    !host.length ||
    !host
      .split(".")
      .every((label) =>
        /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label),
      )
  )
    throw new ApiError("format");
  return host.toLowerCase();
}
/** Only leading device selection is new. Routing values never contain '-'. */
export function connectionUsername(
  login: string,
  route: ConnectionRoute,
  device: Preset | null,
): string {
  shape(
    route,
    route.kind === "default"
      ? ["kind"]
      : route.kind === "exit" || route.kind === "pool"
        ? ["kind", "id"]
        : ["kind", "value"],
  );
  if (
    typeof login !== "string" ||
    !/^vp2_[0-9a-f]{32}$/.test(login) ||
    !(device === null || isPreset(device))
  )
    throw new ApiError("format");
  let suffix = "";
  if (route.kind === "exit" || route.kind === "pool")
    suffix = `-${route.kind}-${routingToken(route.id)}`;
  else if (route.kind === "session" || route.kind === "range") {
    if (!/^[A-Za-z0-9_]{1,128}$/.test(route.value))
      throw new ApiError("format");
    suffix = `-${route.kind}-${route.value}`;
  } else if (route.kind === "ttl") {
    if (
      !/^[1-9][0-9]{0,19}$/.test(route.value) ||
      BigInt(route.value) > 18446744073709551615n
    )
      throw new ApiError("format");
    suffix = `-ttl-${route.value}`;
  } else if (route.kind !== "default") throw new ApiError("format");
  const result = `${login}${device === null ? "" : `-device-${device}`}${suffix}`;
  if (result.length > 255) throw new ApiError("format");
  return result;
}

/** This is a preview of a verified policy snapshot, not a promise of admission.
 * No password enters this pure builder, a URL, or a command line. */
export function connectionPreview(
  input: ConnectionInput,
  policy: {
    protocols: ProxyProtocol[];
    permission: RoutePermission;
    user: UserPreset;
    pool: PoolPreset | null;
    capability: PresetCapability;
  },
): {
  username: string;
  host: string;
  port: number;
  protocol: ConnectionInput["protocol"];
  effective_preset: Preset | null;
} {
  const permission = permissionInput(policy.permission);
  const user = userPreset(policy.user, permission.user_id);
  const protocol = input.protocol === "https" ? "http" : input.protocol;
  const operations =
    input.protocol === "http" || input.protocol === "https"
      ? ["http_forward", "http_connect"]
      : input.protocol === "socks5"
        ? ["socks5_connect", "socks5_bind", "socks5_udp"]
        : input.protocol === "masque"
          ? ["masque_udp"]
          : [];
  if (
    !policy.protocols.includes(protocol) ||
    !operations.includes(input.operation) ||
    typeof input.port !== "string" ||
    !/^[1-9][0-9]{0,4}$/.test(input.port) ||
    Number(input.port) > 65535
  )
    throw new ApiError("format");
  if (input.route.kind === "exit" || input.route.kind === "pool") {
    if (
      !permission[input.route.kind === "exit" ? "exits" : "pools"].includes(
        input.route.id,
      )
    )
      throw new ApiError("server", "policy_denied", 403);
  } else if (!permission.legacy_allowed)
    throw new ApiError("server", "policy_denied", 403);
  const pool =
    input.route.kind === "pool"
      ? poolPreset(policy.pool, input.route.id)
      : null;
  const activeTCP = ["http_forward", "http_connect", "socks5_connect"].includes(
    input.operation,
  );
  if (!activeTCP && input.device !== null)
    throw new ApiError("server", "preset_operation_unsupported", 403);
  const effective = activeTCP
    ? (input.device ?? pool?.default_preset ?? user.default_preset)
    : null;
  if (effective !== null && !user.allowed_presets.includes(effective))
    throw new ApiError("server", "policy_denied", 403);
  if (
    effective !== null &&
    (policy.capability.backend_state !== "ready" ||
      !policy.capability.available_presets.includes(effective) ||
      !policy.capability.operations.includes(
        input.operation as "http_forward" | "http_connect" | "socks5_connect",
      ))
  )
    throw new ApiError("server", "preset_unavailable", 503);
  return {
    username: connectionUsername(input.login, input.route, input.device),
    host: connectionHost(input.host),
    port: Number(input.port),
    protocol: input.protocol,
    effective_preset: effective,
  };
}
