import { ApiError } from "./error";
import { canonicalId, canonicalRevision, shape } from "./proxy";
import { owner, type Owner } from "./targets";

export interface DrainRequest {
  expected_node_id: string;
  expected_epoch: string;
  expected_revision: string;
  runtime_id: string;
  request_id: string;
}
export type RuntimePhase =
  "serving" | "draining" | "drained" | "interrupted" | "failed";
export interface RuntimeStatus {
  node_id: string;
  ownership: Owner;
  saved_revision: string;
  saved_accepting: boolean;
  runtime: null | {
    runtime_id: string;
    phase: RuntimePhase;
    request: DrainRequest | null;
    active_operations: string | null;
  };
}
const invalid = (): never => {
  throw new ApiError("format");
};

export function drainRequest(value: unknown): DrainRequest {
  shape(value, [
    "expected_node_id",
    "expected_epoch",
    "expected_revision",
    "runtime_id",
    "request_id",
  ]);
  if (
    !canonicalId(value.expected_node_id) ||
    !canonicalRevision(value.expected_epoch) ||
    !canonicalRevision(value.expected_revision) ||
    !canonicalId(value.runtime_id) ||
    !canonicalId(value.request_id)
  )
    return invalid();
  return { ...value } as unknown as DrainRequest;
}
export const sameDrain = (left: DrainRequest, right: DrainRequest): boolean =>
  left.expected_node_id === right.expected_node_id &&
  left.expected_epoch === right.expected_epoch &&
  left.expected_revision === right.expected_revision &&
  left.runtime_id === right.runtime_id &&
  left.request_id === right.request_id;

/** Current state is not an exact result unless the caller supplies its original request. */
export function runtimeStatus(
  value: unknown,
  node: string,
  original?: DrainRequest,
): RuntimeStatus {
  shape(value, [
    "node_id",
    "ownership",
    "saved_revision",
    "saved_accepting",
    "runtime",
  ]);
  const ownership = owner(value.ownership);
  if (
    !canonicalId(node) ||
    value.node_id !== node ||
    ownership.controller_node_id === node ||
    !canonicalRevision(value.saved_revision) ||
    typeof value.saved_accepting !== "boolean"
  )
    return invalid();
  let runtime: RuntimeStatus["runtime"] = null;
  if (value.runtime !== null) {
    const entry = value.runtime;
    shape(entry, ["runtime_id", "phase", "request", "active_operations"]);
    if (
      !canonicalId(entry.runtime_id) ||
      !["serving", "draining", "drained", "interrupted", "failed"].includes(
        entry.phase as string,
      ) ||
      !(
        entry.active_operations === null ||
        (typeof entry.active_operations === "string" &&
          /^(0|[1-9][0-9]{0,19})$/.test(entry.active_operations) &&
          BigInt(entry.active_operations) <= 18446744073709551615n)
      )
    )
      return invalid();
    const request = entry.request === null ? null : drainRequest(entry.request);
    if (
      (entry.phase === "serving") !== (request === null) ||
      (request &&
        (request.expected_node_id !== node ||
          request.runtime_id !== entry.runtime_id ||
          BigInt(request.expected_epoch) > BigInt(ownership.epoch) ||
          BigInt(request.expected_revision) > BigInt(value.saved_revision)))
    )
      return invalid();
    runtime = {
      runtime_id: entry.runtime_id,
      phase: entry.phase as RuntimePhase,
      request,
      active_operations: entry.active_operations as string | null,
    };
    if (runtime.phase !== "serving" && value.saved_accepting) return invalid();
  }
  if (
    original &&
    (!runtime?.request || !sameDrain(runtime.request, drainRequest(original)))
  )
    return invalid();
  return {
    node_id: node,
    ownership,
    saved_revision: value.saved_revision,
    saved_accepting: value.saved_accepting,
    runtime,
  };
}

/** A non-secret, canonical 128-bit request identity. No weak random fallback. */
export function drainNonce(): string {
  if (!globalThis.crypto?.getRandomValues) return invalid();
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const value = btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  if (!canonicalId(value)) return invalid();
  return value;
}
