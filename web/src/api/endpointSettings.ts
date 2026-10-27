import { ApiError } from "./error";
import {
  endpointCatalog,
  publicEndpointAddress,
  publicEndpointInput,
  type ListenerProtocol,
} from "./endpoints";
import { canonicalId, canonicalRevision, shape } from "./proxy";
import { job, nextCommand, type MetadataJob } from "./targets";

/** Persisted metadata only. Hidden is an explicit decision, not removal of an
 * override: returning to startup configuration always requires inherit. */
export type EndpointSelection =
  { mode: "inherit" | "hidden" } | { mode: "custom"; public_address: string };

export interface EndpointSetting {
  id: string;
  protocol: ListenerProtocol;
  bind: string;
  configured_public_address: string | null;
  selection: EndpointSelection;
  public_address: string | null;
}
export type DetachedEndpoint = Pick<
  EndpointSetting,
  "id" | "protocol" | "bind" | "selection"
>;
export interface EndpointSettings {
  node_id: string;
  proxy_running: boolean;
  revision: string;
  generation: string;
  listeners: EndpointSetting[];
  detached: DetachedEndpoint[];
}
export const endpointGeneration = (value: unknown): value is string =>
  typeof value === "string" && /^[0-9a-f]{64}$/.test(value);

export interface EndpointCommand {
  expected_target_revision: string;
  controller_epoch: string;
  command_id: string;
  expected_metadata_revision: string;
  mutation: {
    listener_id: string;
    generation: string;
    selection: EndpointSelection;
  };
}
export interface EndpointReceipt {
  controller_epoch: string;
  command_id: string;
  status: "saved" | "rejected";
  metadata_revision: string | null;
  rejection: string | null;
  listener_id: string | null;
  generation: string | null;
}
export interface EndpointSubmission {
  job: MetadataJob;
  response: { receipt: EndpointReceipt; replayed: boolean } | null;
}

export function shapeEndpointCommand(input: EndpointCommand): void {
  shape(input, [
    "expected_target_revision",
    "controller_epoch",
    "command_id",
    "expected_metadata_revision",
    "mutation",
  ]);
  if (
    ![
      input.expected_target_revision,
      input.controller_epoch,
      input.command_id,
      input.expected_metadata_revision,
    ].every(canonicalRevision)
  )
    throw new ApiError("format");
  nextCommand(input.expected_metadata_revision);
  shape(input.mutation, ["listener_id", "generation", "selection"]);
  if (
    !canonicalId(input.mutation.listener_id) ||
    !endpointGeneration(input.mutation.generation)
  )
    throw new ApiError("format");
  endpointSelection(input.mutation.selection);
}

/** A metadata ticket shares peer serialization, never a policy version or
 * credential payload. Match every returned reference to this exact request. */
export function endpointSubmission(
  value: unknown,
  node: string,
  input: EndpointCommand,
  status: number,
): EndpointSubmission {
  shapeEndpointCommand(input);
  shape(value, ["job", "response"]);
  const ticket = job(value.job, node);
  if (
    !ticket ||
    ticket.resource !== "proxy_endpoints" ||
    ticket.controller_epoch !== input.controller_epoch ||
    ticket.command_id !== input.command_id ||
    ticket.expected_metadata_revision !== input.expected_metadata_revision ||
    ticket.endpoint.listener_id !== input.mutation.listener_id ||
    ticket.endpoint.generation !== input.mutation.generation ||
    (status === 202
      ? value.response !== null
      : status !== 200 || value.response === null)
  )
    throw new ApiError("format");
  if (value.response === null) return { job: ticket, response: null };
  shape(value.response, ["receipt", "replayed"]);
  const response = value.response;
  shape(response.receipt, [
    "controller_epoch",
    "command_id",
    "status",
    "metadata_revision",
    "rejection",
    "listener_id",
    "generation",
  ]);
  const receipt = response.receipt;
  if (
    typeof response.replayed !== "boolean" ||
    receipt.controller_epoch !== input.controller_epoch ||
    receipt.command_id !== input.command_id ||
    receipt.status !== ticket.state ||
    (receipt.status === "saved"
      ? receipt.metadata_revision !==
          nextCommand(input.expected_metadata_revision) ||
        receipt.rejection !== null ||
        receipt.listener_id !== input.mutation.listener_id ||
        receipt.generation !== input.mutation.generation
      : receipt.status !== "rejected" ||
        receipt.metadata_revision !== null ||
        receipt.listener_id !== null ||
        receipt.generation !== null ||
        ![
          "invalid_endpoint",
          "endpoint_revision_changed",
          "endpoint_configuration_changed",
          "endpoint_capacity",
        ].includes(receipt.rejection as string))
  )
    throw new ApiError("format");
  return {
    job: ticket,
    response: response as unknown as NonNullable<
      EndpointSubmission["response"]
    >,
  };
}

/** A finite metadata snapshot, separate from the v1 effective URL catalog and
 * proxy-policy publication. Detached records never become live listeners. */
export function endpointSettings(
  value: unknown,
  expectedNode?: string,
): EndpointSettings {
  shape(value, [
    "node_id",
    "proxy_running",
    "revision",
    "generation",
    "listeners",
    "detached",
  ]);
  if (
    !canonicalId(value.node_id) ||
    (expectedNode !== undefined && value.node_id !== expectedNode) ||
    typeof value.proxy_running !== "boolean" ||
    !canonicalRevision(value.revision) ||
    !endpointGeneration(value.generation) ||
    !Array.isArray(value.listeners) ||
    value.listeners.length > 16 ||
    !Array.isArray(value.detached) ||
    value.detached.length > 256
  )
    throw new ApiError("format");
  const ids = new Set<string>();
  const identity = (entry: Record<string, unknown>) => {
    if (!canonicalId(entry.id) || ids.has(entry.id))
      throw new ApiError("format");
    ids.add(entry.id);
    endpointCatalog({
      node_id: value.node_id,
      proxy_running: false,
      listeners: [
        { protocol: entry.protocol, bind: entry.bind, public_address: null },
      ],
    });
  };
  const listeners = value.listeners.map((entry) => {
    shape(entry, [
      "id",
      "protocol",
      "bind",
      "configured_public_address",
      "selection",
      "public_address",
    ]);
    identity(entry);
    if (entry.configured_public_address !== null)
      publicEndpointAddress(entry.configured_public_address);
    const selection = endpointSelection(entry.selection);
    if (
      selectedPublicAddress(
        selection,
        entry.configured_public_address as string | null,
      ) !== entry.public_address
    )
      throw new ApiError("format");
    return { ...entry, selection } as unknown as EndpointSetting;
  });
  const detached = value.detached.map((entry) => {
    shape(entry, ["id", "protocol", "bind", "selection"]);
    identity(entry);
    const selection = endpointSelection(entry.selection);
    if (selection.mode === "inherit") throw new ApiError("format");
    return { ...entry, selection } as unknown as DetachedEndpoint;
  });
  if (value.proxy_running && listeners.length === 0)
    throw new ApiError("format");
  return {
    node_id: value.node_id,
    proxy_running: value.proxy_running,
    revision: value.revision,
    generation: value.generation,
    listeners,
    detached,
  };
}

export function endpointSelection(value: unknown): EndpointSelection {
  if (typeof value !== "object" || value === null) throw new ApiError("format");
  const mode = (value as Record<string, unknown>).mode;
  if (mode === "inherit" || mode === "hidden") {
    shape(value, ["mode"]);
    return { mode };
  }
  if (mode !== "custom") throw new ApiError("format");
  shape(value, ["mode", "public_address"]);
  const { host, port } = publicEndpointAddress(value.public_address);
  if (publicEndpointInput(host, String(port)) !== value.public_address)
    throw new ApiError("format");
  return { mode, public_address: value.public_address as string };
}

/** A display preview is computed from this same listener's declaration only;
 * it says nothing about a live socket, DNS, TLS, authentication or egress. */
export function selectedPublicAddress(
  selection: EndpointSelection,
  configured: string | null,
): string | null {
  const checked = endpointSelection(selection);
  if (configured !== null) publicEndpointAddress(configured);
  return checked.mode === "custom"
    ? checked.public_address
    : checked.mode === "hidden"
      ? null
      : configured;
}
