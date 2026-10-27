import { ApiError } from "./error";
import { endpointCatalog, type EndpointListener } from "./endpoints";
import { canonicalId, canonicalRevision, shape } from "./proxy";
import { nextCommand } from "./targets";

export interface ServiceConfiguration {
  listeners: EndpointListener[];
  workers: number;
  concurrent: number;
  connect_timeout: number;
}
export interface ServiceRuntime {
  generation: string | null;
  configuration_revision: string | null;
  state: "stopped" | "starting" | "running" | "stopping" | "failed";
  error:
    | null
    | "address_in_use"
    | "address_unavailable"
    | "permission_denied"
    | "timed_out"
    | "not_ready"
    | "service_failed";
  listeners: EndpointListener[];
}
export interface ServiceStatus {
  node_id: string;
  mode: "web" | "startup" | "upgrade_required";
  saved: null | {
    revision: string;
    enabled: boolean;
    configuration: ServiceConfiguration | null;
  };
  runtime: ServiceRuntime;
}
/** Identity only: safe to retain for an exact receipt query, never a replay. */
export interface ServiceOperation {
  expected_node_id: string;
  expected_revision: string;
  controller_epoch: string;
  request_id: string;
  enabled: boolean;
}
export interface ServiceChange extends ServiceOperation {
  configuration: ServiceConfiguration;
}
export interface ServiceReceipt {
  node_id: string;
  revision: string;
  controller_epoch: string;
  request_id: string;
  enabled: boolean;
  state: "pending" | "applied" | "failed" | "interrupted";
}
export interface ServiceSubmission {
  operation: ServiceReceipt;
  runtime: ServiceRuntime;
}
const invalid = (): never => {
  throw new ApiError("format");
};
const integer = (value: unknown, min: number, max: number): value is number =>
  Number.isInteger(value) &&
  (value as number) >= min &&
  (value as number) <= max;
const revision = (value: unknown): boolean =>
  value === null || canonicalRevision(value);

export function serviceConfiguration(
  value: unknown,
  node: string,
): ServiceConfiguration {
  shape(value, ["listeners", "workers", "concurrent", "connect_timeout"]);
  const listeners = endpointCatalog({
    node_id: node,
    proxy_running: true,
    listeners: value.listeners,
  }).listeners;
  if (
    !integer(value.workers, 1, 256) ||
    !integer(value.concurrent, 1, 2147483647) ||
    !integer(value.connect_timeout, 1, 300)
  )
    return invalid();
  const binds = new Set<string>();
  for (const item of listeners) {
    const bind = `${item.protocol === "masque" ? "udp" : "tcp"}:${item.bind}`;
    if (binds.has(bind)) return invalid();
    binds.add(bind);
  }
  return {
    listeners,
    workers: value.workers,
    concurrent: value.concurrent,
    connect_timeout: value.connect_timeout,
  };
}

function runtime(value: unknown, node: string): ServiceRuntime {
  shape(value, [
    "generation",
    "configuration_revision",
    "state",
    "error",
    "listeners",
  ]);
  if (
    !(
      value.generation === null ||
      (typeof value.generation === "string" &&
        /^(0|[1-9][0-9]{0,19})$/.test(value.generation) &&
        BigInt(value.generation) <= 18446744073709551615n)
    ) ||
    !revision(value.configuration_revision) ||
    !["stopped", "starting", "running", "stopping", "failed"].includes(
      value.state as string,
    ) ||
    !(
      value.error === null ||
      [
        "address_in_use",
        "address_unavailable",
        "permission_denied",
        "timed_out",
        "not_ready",
        "service_failed",
      ].includes(value.error as string)
    )
  )
    return invalid();
  const listeners = endpointCatalog({
    node_id: node,
    proxy_running: value.state === "running",
    listeners: value.listeners,
  }).listeners;
  return { ...value, listeners } as unknown as ServiceRuntime;
}

/** Saved enabled/revision and live listeners may intentionally disagree. */
export function serviceStatus(value: unknown, node: string): ServiceStatus {
  shape(value, ["node_id", "mode", "saved", "runtime"]);
  if (
    !canonicalId(node) ||
    value.node_id !== node ||
    !["web", "startup", "upgrade_required"].includes(value.mode as string)
  )
    return invalid();
  let saved: ServiceStatus["saved"] = null;
  if (value.saved !== null) {
    shape(value.saved, ["revision", "enabled", "configuration"]);
    if (
      !canonicalRevision(value.saved.revision) ||
      typeof value.saved.enabled !== "boolean" ||
      (value.saved.configuration === null &&
        (value.saved.enabled || value.saved.revision !== "1"))
    )
      return invalid();
    saved = {
      revision: value.saved.revision,
      enabled: value.saved.enabled,
      configuration:
        value.saved.configuration === null
          ? null
          : serviceConfiguration(value.saved.configuration, node),
    };
  }
  if (value.mode === "web" && saved === null) return invalid();
  return {
    node_id: node,
    mode: value.mode as ServiceStatus["mode"],
    saved,
    runtime: runtime(value.runtime, node),
  };
}

export function serviceOperation(value: unknown): ServiceOperation {
  shape(value, [
    "expected_node_id",
    "expected_revision",
    "controller_epoch",
    "request_id",
    "enabled",
  ]);
  if (
    !canonicalId(value.expected_node_id) ||
    !canonicalId(value.request_id) ||
    !canonicalRevision(value.expected_revision) ||
    !canonicalRevision(value.controller_epoch) ||
    typeof value.enabled !== "boolean"
  )
    return invalid();
  nextCommand(value.expected_revision);
  return { ...value } as unknown as ServiceOperation;
}
export function serviceChange(input: ServiceChange): ServiceChange {
  shape(input, [
    "expected_node_id",
    "expected_revision",
    "controller_epoch",
    "request_id",
    "enabled",
    "configuration",
  ]);
  const { configuration, ...operation } = input;
  return {
    ...serviceOperation(operation),
    configuration: serviceConfiguration(configuration, input.expected_node_id),
  };
}
export function serviceReceipt(
  value: unknown,
  original: ServiceOperation,
): ServiceReceipt {
  const checked = serviceOperation(original);
  shape(value, [
    "node_id",
    "revision",
    "controller_epoch",
    "request_id",
    "enabled",
    "state",
  ]);
  if (
    value.node_id !== checked.expected_node_id ||
    value.revision !== nextCommand(checked.expected_revision) ||
    value.controller_epoch !== checked.controller_epoch ||
    value.request_id !== checked.request_id ||
    value.enabled !== checked.enabled ||
    !["pending", "applied", "failed", "interrupted"].includes(
      value.state as string,
    )
  )
    return invalid();
  return { ...value } as unknown as ServiceReceipt;
}
export function serviceSubmission(
  value: unknown,
  input: ServiceChange,
): ServiceSubmission {
  shape(value, ["operation", "runtime"]);
  const { configuration: _, ...original } = serviceChange(input);
  return {
    operation: serviceReceipt(value.operation, original),
    runtime: runtime(value.runtime, original.expected_node_id),
  };
}
