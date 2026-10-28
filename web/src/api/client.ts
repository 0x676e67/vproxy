import { ApiError, apiError } from "./error";
import {
  webhookView,
  webhookChange,
  webhookRetry,
  type WebhookView,
  type WebhookChange,
  type WebhookRetry,
} from "./notifications";
import {
  nodeAlertPage,
  nodeAlertQuery,
  type NodeAlertPage,
} from "./nodeAlerts";
import {
  alertEvent,
  alertEpisode,
  alertEventPage,
  alertEventQuery,
  alertSummary,
  alertAcknowledgementInput,
  unreadAlertQuery,
  unreadAlertPage,
  alertAcknowledgementBatch,
  alertAcknowledgementResult,
  type UnreadAlertOptions,
  type UnreadAlertPage,
  type AlertAcknowledgementBatch,
  type AlertEvent,
  type AlertEpisode,
  type AlertEventPage,
  type AlertEventOptions,
  type AlertSummary,
  type AlertAcknowledgementInput,
} from "./alertEvents";
import {
  commandHistoryEntry,
  commandHistoryPage,
  commandHistoryQuery,
  type CommandHistoryEntry,
  type CommandHistoryOptions,
  type CommandHistoryPage,
} from "./commandHistory";
import { acmeStatus, type AcmeStatus } from "./acme";
import {
  credentialSecret,
  credentialSecretInput,
  targetCredentialSecretInput,
  type CredentialSecret,
  type CredentialSecretInput,
  type TargetCredentialSecretInput,
} from "./credentialSecret";
import { certificateStatus, type CertificateStatus } from "./certificates";
import {
  serviceStatus,
  serviceChange,
  serviceOperation,
  serviceReceipt,
  serviceSubmission,
  type ServiceStatus,
  type ServiceChange,
  type ServiceOperation,
  type ServiceReceipt,
  type ServiceSubmission,
} from "./proxyService";
import {
  drainRequest,
  runtimeStatus,
  type DrainRequest,
  type RuntimeStatus,
} from "./runtime";
import {
  maintenanceStatus,
  maintenanceInput,
  maintenanceChange,
  maintenanceCommand,
  maintenanceSubmission,
  maintenanceJob,
  type MaintenanceStatus,
  type MaintenanceInput,
  type MaintenanceChange,
  type MaintenanceCommand,
  type MaintenanceSubmission,
  type MaintenanceJob,
} from "./maintenance";
import { validCurrentPassword, validNewPassword } from "./password";
import {
  canonicalId,
  canonicalRevision,
  changeResult,
  endpointStatus,
  idPath,
  listQuery,
  page,
  policyStatus,
  proxyCredential,
  proxyUser,
  revisionInput,
  userInput,
  userSearchPage,
  userSearchQuery,
  validUserName,
  type ApiMethod,
  type ChangeResult,
  type Page,
  type Pagination,
  type PolicyStatus,
  type ProxyCredential,
  type ProxyUser,
  type UserInput,
  type UserSearchOptions,
} from "./proxy";
import {
  canonicalOrigin,
  job,
  nextCommand,
  owner,
  remotePolicy,
  shapeCommandInput,
  submission,
  target,
  targetListQuery,
  targetPage,
  userResult,
  validServerIp,
  type CommandInput,
  type Job,
  type Owner,
  type PolicyJob,
  type RemotePolicy,
  type Submission,
  type Target,
  type TargetPage,
  type UserResult,
} from "./targets";
import {
  address,
  addressView,
  addressFamily,
  memberId,
  nextRoutingRevision,
  permissionInput,
  permissionView,
  pool,
  prefix,
  resourceState,
  routingChange,
  routingPage,
  routingQuery,
  validCidr,
  validIp,
  type AddressInput,
  type AddressView,
  type PermissionView,
  type PoolInput,
  type PrefixInput,
  type Resource,
  type ResourceKind,
  type ResourceState,
  type RoutePermission,
  type RoutingChange,
  type RoutingPage,
} from "./routing";
import { healthQuery, healthSnapshot, type HealthSnapshot } from "./health";
import {
  alertPage,
  alertQuery,
  egressAlertPage,
  egressAlertQuery,
  type AlertOptions,
  type AlertPage,
  type EgressAlertListOptions,
  type EgressAlertPage,
} from "./alerts";
import {
  userOperation,
  userOperationInput,
  userOperationPage,
  userOperationQuery,
  type UserOperation,
  type UserOperationInput,
  type UserOperationOptions,
  type UserOperationPage,
} from "./userOperations";
import { endpointCatalog, type EndpointCatalog } from "./endpoints";
import {
  endpointGeneration,
  endpointSelection,
  endpointSettings,
  endpointSubmission,
  shapeEndpointCommand,
  type EndpointCommand,
  type EndpointSelection,
  type EndpointSettings,
  type EndpointSubmission,
} from "./endpointSettings";
import {
  trafficQuery,
  trafficTotals,
  trafficHistory,
  remoteTraffic,
  type TrafficScope,
  type HistoryScope,
  type TrafficOptions,
  type TrafficTotals,
  type TrafficHistory,
  type RemoteTraffic,
} from "./traffic";
import {
  routingSubmission,
  shapeRoutingCommand,
  type RoutingCommandInput,
  type RoutingSubmission,
} from "./remoteRouting";
import {
  presetCapability,
  userPreset,
  poolPreset,
  userPresetView,
  poolPresetView,
  sameUserPreset,
  type PresetCapability,
  type UserPreset,
  type PoolPreset,
  type UserPresetView,
  type PoolPresetView,
} from "./presets";
import {
  shapePresetCommand,
  presetSubmission,
  type PresetCommandInput,
  type PresetSubmission,
} from "./remotePresets";
export { ApiError, apiError, authenticationRequired } from "./error";

/** The browser never reads the HttpOnly session cookie or persists CSRF tokens. */
export interface SessionView {
  readonly administrator: { readonly id: string; readonly username: string };
  readonly csrf_token: string;
  readonly expires_at: number;
}

/** Only these node facts exist in the current management API. */
export interface NodeView {
  node_id: string;
  name: string;
  version: string;
  os: string;
  arch: string;
  capabilities: string[];
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown, max: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= max &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

const identity = canonicalId;

export function sessionView(value: unknown): SessionView {
  if (
    !object(value) ||
    !object(value.administrator) ||
    !identity(value.administrator.id) ||
    typeof value.administrator.username !== "string" ||
    !/^[A-Za-z0-9._-]{1,64}$/.test(value.administrator.username) ||
    typeof value.csrf_token !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.csrf_token) ||
    typeof value.expires_at !== "number" ||
    !Number.isSafeInteger(value.expires_at) ||
    value.expires_at < 0
  ) {
    throw new ApiError("format");
  }
  return {
    administrator: {
      id: value.administrator.id,
      username: value.administrator.username,
    },
    csrf_token: value.csrf_token,
    expires_at: value.expires_at,
  };
}

export function nodeView(value: unknown): NodeView {
  if (
    !object(value) ||
    !identity(value.node_id) ||
    !text(value.name, 128) ||
    !text(value.version, 128) ||
    !text(value.os, 64) ||
    !text(value.arch, 64) ||
    !Array.isArray(value.capabilities) ||
    value.capabilities.length > 32 ||
    !value.capabilities.every((capability) => text(capability, 128))
  ) {
    throw new ApiError("format");
  }
  return {
    node_id: value.node_id,
    name: value.name,
    version: value.version,
    os: value.os,
    arch: value.arch,
    capabilities: value.capabilities,
  };
}

/** Small fixed endpoint set: no caller-supplied host, path, redirect or credentials. */
type Endpoint =
  | "/auth/session"
  | "/auth/login"
  | "/auth/logout"
  | "/auth/password"
  | "/node"
  | "/tls/acme"
  | "/tls/status"
  | "/alerts"
  | `/operations-alerts${string}`
  | `/alert-events${string}`
  | `/alert-episodes${string}`
  | `/alert-episodes/${string}`
  | "/alert-summary"
  | "/notifications/webhook"
  | "/notifications/webhook/retry"
  | `/alerts?${string}`
  | `/proxy/${string}`
  | "/targets"
  | `/targets${string}`;
type Mutation = { body: string; csrf?: string; method?: "POST" | "PUT" };

const REQUEST_TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 32_768;

/** Bound bytes before decoding/concatenation; an HTML fallback is never JSON. */
async function jsonBody(
  response: Response,
  signal: AbortSignal,
  maximum = MAX_RESPONSE_BYTES,
): Promise<unknown> {
  if (!response.body) throw new ApiError("format");
  const reader = response.body.getReader();
  const cancel = () => {
    void reader.cancel().catch(() => {});
  };
  if (signal.aborted) cancel();
  else signal.addEventListener("abort", cancel, { once: true });
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let bytes = 0;
  let body = "";
  try {
    while (true) {
      let chunk: ReadableStreamReadResult<Uint8Array>;
      try {
        chunk = await reader.read();
      } catch (error) {
        if (signal.aborted) throw error;
        throw new ApiError("network");
      }
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > maximum) throw new ApiError("format");
      try {
        body += decoder.decode(chunk.value, { stream: true });
      } catch {
        throw new ApiError("format");
      }
    }
    try {
      body += decoder.decode();
      return JSON.parse(body);
    } catch {
      throw new ApiError("format");
    }
  } finally {
    // Also cancels an oversized/invalid/aborted stream, without masking its error.
    signal.removeEventListener("abort", cancel);
    cancel();
    reader.releaseLock();
  }
}

export class ManagementClient {
  constructor(
    private readonly fetcher: typeof fetch = (...args) => fetch(...args),
    private readonly secure: () => boolean = () =>
      globalThis.location?.protocol === "https:",
  ) {}

  async acmeStatus(signal: AbortSignal): Promise<AcmeStatus> {
    return acmeStatus(await this.request("/tls/acme", signal));
  }

  /** The selected local node is checked against the returned identity. */
  async certificateStatus(
    nodeId: string,
    signal: AbortSignal,
  ): Promise<CertificateStatus> {
    if (!canonicalId(nodeId)) throw new ApiError("format");
    const value = certificateStatus(await this.request("/tls/status", signal));
    if (value.node_id !== nodeId) throw new ApiError("format");
    return value;
  }

  async proxyRuntime(
    node: string,
    peer: string | null,
    signal: AbortSignal,
  ): Promise<RuntimeStatus> {
    idPath(node);
    if (peer !== null && idPath(peer) !== node) throw new ApiError("format");
    return runtimeStatus(
      await this.request(
        peer === null ? "/proxy/runtime" : `/targets/${peer}/proxy/runtime`,
        signal,
      ),
      node,
    );
  }

  async drainRuntime(
    peer: string | null,
    input: DrainRequest,
    targetRevision: string | null,
    csrf: string,
    signal: AbortSignal,
  ): Promise<RuntimeStatus> {
    const checked = drainRequest(input);
    if (
      peer === null
        ? targetRevision !== null
        : idPath(peer) !== checked.expected_node_id ||
          !canonicalRevision(targetRevision)
    )
      throw new ApiError("format");
    const reply = await this.requestResponse(
      peer === null
        ? "/proxy/runtime/drain"
        : `/targets/${peer}/proxy/runtime/drain`,
      signal,
      {
        csrf,
        body: JSON.stringify(
          peer === null
            ? checked
            : { expected_target_revision: targetRevision, request: checked },
        ),
      },
    );
    if (reply.status !== 202) throw new ApiError("format");
    return runtimeStatus(reply.value, checked.expected_node_id, checked);
  }

  /** Read only the retained runtime/request pair. Never falls back to current state. */
  async runtimeDrain(
    peer: string | null,
    input: DrainRequest,
    signal: AbortSignal,
  ): Promise<RuntimeStatus> {
    const checked = drainRequest(input);
    if (peer !== null && idPath(peer) !== checked.expected_node_id)
      throw new ApiError("format");
    const endpoint: Endpoint =
      peer === null
        ? `/proxy/runtime/drains/${checked.runtime_id}/${checked.request_id}`
        : `/targets/${peer}/proxy/runtime/drains/${checked.runtime_id}/${checked.request_id}`;
    return runtimeStatus(
      await this.request(endpoint, signal),
      checked.expected_node_id,
      checked,
    );
  }

  async maintenance(
    node: string,
    peer: string | null,
    signal: AbortSignal,
  ): Promise<MaintenanceStatus> {
    idPath(node);
    if (peer !== null && idPath(peer) !== node) throw new ApiError("format");
    return maintenanceStatus(
      await this.request(
        peer === null
          ? "/proxy/maintenance"
          : `/targets/${peer}/proxy/maintenance`,
        signal,
      ),
      node,
    );
  }

  async setMaintenance(
    input: MaintenanceInput,
    csrf: string,
    signal: AbortSignal,
  ): Promise<MaintenanceChange> {
    const checked = maintenanceInput(input);
    return maintenanceChange(
      await this.request("/proxy/maintenance", signal, {
        csrf,
        body: JSON.stringify(checked),
      }),
      checked,
    );
  }

  async targetMaintenanceCommand(
    peer: string,
    input: MaintenanceCommand,
    csrf: string,
    signal: AbortSignal,
  ): Promise<MaintenanceSubmission> {
    idPath(peer);
    const checked = maintenanceCommand(input);
    const result = await this.requestResponse(
      `/targets/${peer}/maintenance/commands`,
      signal,
      { csrf, body: JSON.stringify(checked) },
    );
    return maintenanceSubmission(result.value, peer, checked, result.status);
  }

  /** Receipt-only lookup addressed by the retained job, never the current slot. */
  async maintenanceRefresh(
    peer: string,
    jobId: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<MaintenanceJob> {
    idPath(peer);
    idPath(jobId);
    const result = maintenanceJob(
      await this.request(
        `/targets/${peer}/maintenance/commands/refresh`,
        signal,
        {
          csrf,
          body: JSON.stringify({ job_id: jobId }),
        },
      ),
      peer,
    );
    if (result.job_id !== jobId) throw new ApiError("format");
    return result;
  }

  private async request(
    endpoint: Endpoint,
    signal: AbortSignal,
    mutation?: Mutation,
  ): Promise<unknown> {
    return (await this.requestResponse(endpoint, signal, mutation)).value;
  }

  private async requestResponse(
    endpoint: Endpoint,
    signal: AbortSignal,
    mutation?: Mutation,
  ): Promise<{ value: unknown; status: number }> {
    if (!this.secure()) throw new ApiError("https");
    const bounded = new AbortController();
    const abort = () => bounded.abort();
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(abort, REQUEST_TIMEOUT_MS);
    // The deadline includes both response headers and the entire response body.
    let rejectAbort = () => {};
    const cancelled = new Promise<never>((_, reject) => {
      rejectAbort = () => reject(new DOMException("Aborted", "AbortError"));
      if (bounded.signal.aborted) rejectAbort();
      else
        bounded.signal.addEventListener("abort", rejectAbort, { once: true });
    });
    try {
      return await Promise.race([
        this.exchange(endpoint, bounded.signal, mutation),
        cancelled,
      ]);
    } catch (error) {
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");
      throw apiError(error);
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      bounded.signal.removeEventListener("abort", rejectAbort);
    }
  }

  private async exchange(
    endpoint: Endpoint,
    signal: AbortSignal,
    mutation?: Mutation,
  ): Promise<{ value: unknown; status: number }> {
    const method: ApiMethod = mutation?.method ?? (mutation ? "POST" : "GET");
    const status = endpointStatus(endpoint, method);
    let response: Response;
    try {
      response = await this.fetcher(`/api/v1${endpoint}`, {
        method,
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        signal,
        headers: {
          Accept: "application/json",
          ...(mutation ? { "Content-Type": "application/json" } : {}),
          ...(mutation?.csrf ? { "X-CSRF-Token": mutation.csrf } : {}),
        },
        ...(mutation ? { body: mutation.body } : {}),
      });
    } catch (error) {
      if (signal.aborted) throw error;
      throw new ApiError("network");
    }
    if (signal.aborted) {
      if (response.body) void response.body.cancel().catch(() => {});
      throw new DOMException("Aborted", "AbortError");
    }
    if (status === 204 && response.status === 204)
      return { value: undefined, status: 204 };
    if (
      !/^application\/json(?:\s*;|$)/i.test(
        response.headers.get("Content-Type") ?? "",
      )
    ) {
      if (response.body) void response.body.cancel().catch(() => {});
      throw new ApiError("format");
    }
    // These two bounded local catalogs have larger rows. Other endpoints keep
    // their existing 32-KiB limit; history never includes mutation payloads.
    const settingsResponse =
      /^\/(?:proxy\/endpoint-settings(?:\/[A-Za-z0-9_-]{22})?|targets\/[A-Za-z0-9_-]{22}\/proxy\/endpoint-settings)$/.test(
        endpoint,
      );
    const historyResponse =
      /^\/targets\/[A-Za-z0-9_-]{21}[AQgw]\/commands\/history(?:\/[A-Za-z0-9_-]{21}[AQgw])?(?:\?[^?]*)?$/.test(
        endpoint,
      );
    const eventResponse = /^\/alert-events(?:\?[^?]*)?$/.test(endpoint);
    const inboxResponse = /^\/alert-episodes(?:\?[^?]*|\/acknowledge)?$/.test(
      endpoint,
    );
    const value = await jsonBody(
      response,
      signal,
      settingsResponse
        ? 262_144
        : historyResponse || eventResponse || inboxResponse
          ? 131_072
          : MAX_RESPONSE_BYTES,
    );
    if (
      !(typeof status === "number"
        ? response.status === status
        : status.includes(response.status as 200 | 202))
    ) {
      if (response.status >= 200 && response.status < 300)
        throw new ApiError("format");
      if (
        !object(value) ||
        !object(value.error) ||
        typeof value.error.code !== "string" ||
        !/^[a-z_]{1,64}$/.test(value.error.code)
      ) {
        throw new ApiError("format");
      }
      throw new ApiError("server", value.error.code, response.status);
    }
    return { value, status: response.status };
  }

  async session(signal: AbortSignal): Promise<SessionView> {
    return sessionView(await this.request("/auth/session", signal));
  }

  async login(
    username: string,
    password: string,
    signal: AbortSignal,
  ): Promise<SessionView> {
    return sessionView(
      await this.request("/auth/login", signal, {
        body: JSON.stringify({ username, password }),
      }),
    );
  }

  async logout(csrf: string, signal: AbortSignal): Promise<void> {
    await this.request("/auth/logout", signal, { body: "{}", csrf });
  }

  /** Self-service only; passwords are JSON input, never URL/target state. */
  async changePassword(
    currentPassword: string,
    newPassword: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<void> {
    if (
      !validCurrentPassword(currentPassword) ||
      !validNewPassword(newPassword)
    )
      throw new ApiError("server", "invalid_password_input", 400);
    await this.request("/auth/password", signal, {
      csrf,
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    });
  }

  async node(signal: AbortSignal): Promise<NodeView> {
    return nodeView(await this.request("/node", signal));
  }

  async webhook(nodeId: string, signal: AbortSignal): Promise<WebhookView> {
    return webhookView(
      await this.request("/notifications/webhook", signal),
      nodeId,
    );
  }
  async configureWebhook(
    input: WebhookChange,
    csrf: string,
    signal: AbortSignal,
  ): Promise<WebhookView> {
    const checked = webhookChange(input);
    const value = webhookView(
      await this.request("/notifications/webhook", signal, {
        csrf,
        body: JSON.stringify(checked),
      }),
      checked.expected_node_id,
    );
    if (
      value.operation_id !== checked.operation_id ||
      BigInt(value.revision) !== BigInt(checked.expected_revision) + 1n ||
      value.enabled !== checked.enabled ||
      value.automatic_retry !== checked.automatic_retry
    )
      throw new ApiError("format");
    return value;
  }
  async retryWebhook(
    input: WebhookRetry,
    csrf: string,
    signal: AbortSignal,
  ): Promise<WebhookView> {
    const checked = webhookRetry(input);
    const value = webhookView(
      await this.request("/notifications/webhook/retry", signal, {
        csrf,
        body: JSON.stringify(checked),
      }),
      checked.expected_node_id,
    );
    if (
      value.revision !== checked.expected_revision ||
      value.pending?.id !== checked.delivery_id ||
      value.pending.outcome !== "ready" ||
      value.pending.attempts !== checked.expected_attempts
    )
      throw new ApiError("format");
    return value;
  }

  async alerts(options: AlertOptions, signal: AbortSignal): Promise<AlertPage> {
    return alertPage(
      await this.request(`/alerts${alertQuery(options)}`, signal),
      options,
    );
  }
  async alertEvents(
    nodeId: string,
    options: AlertEventOptions,
    signal: AbortSignal,
  ): Promise<AlertEventPage> {
    idPath(nodeId);
    return alertEventPage(
      await this.request(`/alert-events${alertEventQuery(options)}`, signal),
      nodeId,
      options,
    );
  }
  async alertEvent(
    nodeId: string,
    sequence: string,
    signal: AbortSignal,
  ): Promise<AlertEvent> {
    idPath(nodeId);
    revisionInput(sequence);
    return alertEvent(
      await this.request(`/alert-events/${sequence}`, signal),
      nodeId,
      sequence,
    );
  }
  async alertEpisode(
    nodeId: string,
    id: string,
    signal: AbortSignal,
  ): Promise<AlertEpisode> {
    idPath(nodeId);
    revisionInput(id);
    return alertEpisode(
      await this.request(`/alert-episodes/${id}`, signal),
      nodeId,
      id,
    );
  }
  async alertSummary(
    signal: AbortSignal,
    nodeId?: string,
  ): Promise<AlertSummary> {
    if (nodeId !== undefined) idPath(nodeId);
    return alertSummary(await this.request("/alert-summary", signal), nodeId);
  }
  async unreadAlerts(
    nodeId: string,
    options: UnreadAlertOptions,
    signal: AbortSignal,
  ): Promise<UnreadAlertPage> {
    idPath(nodeId);
    return unreadAlertPage(
      await this.request(`/alert-episodes${unreadAlertQuery(options)}`, signal),
      nodeId,
      options,
    );
  }
  async acknowledgeAlertBatch(
    input: AlertAcknowledgementBatch,
    csrf: string,
    signal: AbortSignal,
  ): Promise<AlertEpisode[]> {
    const checked = alertAcknowledgementBatch(input);
    return alertAcknowledgementResult(
      await this.request("/alert-episodes/acknowledge", signal, {
        csrf,
        body: JSON.stringify(checked),
      }),
      checked,
    );
  }
  async acknowledgeAlertEpisode(
    id: string,
    input: AlertAcknowledgementInput,
    csrf: string,
    signal: AbortSignal,
  ): Promise<AlertEpisode> {
    revisionInput(id);
    const checked = alertAcknowledgementInput(input);
    if (BigInt(id) > BigInt(checked.expected_transition_sequence))
      throw new ApiError("format");
    const result = alertEpisode(
      await this.request(`/alert-episodes/${id}/acknowledge`, signal, {
        csrf,
        body: JSON.stringify(checked),
      }),
      checked.expected_node_id,
      id,
    );
    if (
      result.latest_transition_sequence !==
        checked.expected_transition_sequence ||
      result.acknowledged_transition_sequence !==
        checked.expected_transition_sequence ||
      !result.is_acknowledged
    )
      throw new ApiError("format");
    return result;
  }

  async targetEgressAlerts(
    peer: string,
    options: EgressAlertListOptions,
    signal: AbortSignal,
  ): Promise<EgressAlertPage> {
    const query = egressAlertQuery(options);
    const checked = { ...options };
    return egressAlertPage(
      await this.request(
        `/targets/${idPath(peer)}/egress-alerts${query}`,
        signal,
      ),
      peer,
      checked,
    );
  }

  async operationsAlerts(
    options: AlertOptions,
    signal: AbortSignal,
  ): Promise<NodeAlertPage> {
    return nodeAlertPage(
      await this.request(
        `/operations-alerts${nodeAlertQuery(options)}`,
        signal,
      ),
      undefined,
      options,
    );
  }
  async targetOperationsAlerts(
    peer: string,
    options: AlertOptions,
    signal: AbortSignal,
  ): Promise<NodeAlertPage> {
    return nodeAlertPage(
      await this.request(
        `/targets/${idPath(peer)}/operations-alerts${nodeAlertQuery(options)}`,
        signal,
      ),
      peer,
      options,
    );
  }

  async owner(signal: AbortSignal): Promise<Owner> {
    return owner(await this.request("/proxy/owner", signal));
  }
  async setOwner(
    controller: string | null,
    epoch: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<Owner> {
    if (controller !== null) idPath(controller);
    return owner(
      await this.request("/proxy/owner", signal, {
        method: "PUT",
        csrf,
        body: JSON.stringify({
          expected_epoch: revisionInput(epoch),
          controller_node_id: controller,
        }),
      }),
    );
  }
  async targets(
    options: {
      after?: string;
      limit?: number;
      include_retired?: boolean;
      q?: string;
    },
    signal: AbortSignal,
  ): Promise<TargetPage> {
    return targetPage(
      await this.request(`/targets${targetListQuery(options)}`, signal),
    );
  }
  async target(id: string, signal: AbortSignal): Promise<Target> {
    const result = target(await this.request(`/targets/${idPath(id)}`, signal));
    if (result.node_id !== id) throw new ApiError("format");
    return result;
  }
  async configureTarget(
    id: string,
    origin: string,
    active: boolean,
    revision: string | null,
    csrf: string,
    signal: AbortSignal,
    serverIp?: string | null,
  ): Promise<Target> {
    idPath(id);
    if (
      !canonicalOrigin(origin) ||
      typeof active !== "boolean" ||
      (serverIp !== undefined && serverIp !== null && !validServerIp(serverIp))
    )
      throw new ApiError("format");
    // Omission preserves metadata on update; null explicitly clears it.
    const metadata = serverIp === undefined ? {} : { server_ip: serverIp };
    const result = target(
      await this.request(
        revision === null ? "/targets" : `/targets/${id}`,
        signal,
        {
          csrf,
          method: revision === null ? "POST" : "PUT",
          body: JSON.stringify(
            revision === null
              ? { node_id: id, origin, active, ...metadata }
              : {
                  expected_revision: revisionInput(revision),
                  origin,
                  active,
                  ...metadata,
                },
          ),
        },
      ),
    );
    if (result.node_id !== id) throw new ApiError("format");
    return result;
  }
  async targetState(
    id: string,
    revision: string,
    active: boolean,
    retire: boolean,
    csrf: string,
    signal: AbortSignal,
  ): Promise<Target> {
    if (
      typeof active !== "boolean" ||
      typeof retire !== "boolean" ||
      (retire && active)
    )
      throw new ApiError("format");
    const result = target(
      await this.request(
        `/targets/${idPath(id)}/${retire ? "retire" : "state"}`,
        signal,
        {
          csrf,
          body: JSON.stringify({
            expected_revision: revisionInput(revision),
            ...(retire ? {} : { active }),
          }),
        },
      ),
    );
    if (result.node_id !== id) throw new ApiError("format");
    return result;
  }
  async targetPolicy(id: string, signal: AbortSignal): Promise<RemotePolicy> {
    return remotePolicy(
      await this.request(`/targets/${idPath(id)}/policy`, signal),
    );
  }

  /** Read only the selected node's effective client endpoint declarations. */
  async targetEndpoints(
    id: string,
    signal: AbortSignal,
  ): Promise<EndpointCatalog> {
    return endpointCatalog(
      await this.request(`/targets/${idPath(id)}/proxy/endpoints`, signal),
      id,
    );
  }

  async proxyEndpoints(signal: AbortSignal): Promise<EndpointCatalog> {
    return endpointCatalog(await this.request("/proxy/endpoints", signal));
  }
  async proxyService(
    node: string,
    signal: AbortSignal,
  ): Promise<ServiceStatus> {
    idPath(node);
    return serviceStatus(await this.request("/proxy/service", signal), node);
  }
  async setProxyService(
    input: ServiceChange,
    csrf: string,
    signal: AbortSignal,
  ): Promise<ServiceSubmission> {
    const checked = serviceChange(input);
    return serviceSubmission(
      await this.request("/proxy/service", signal, {
        method: "PUT",
        csrf,
        body: JSON.stringify(checked),
      }),
      checked,
    );
  }
  async proxyServiceOperation(
    input: ServiceOperation,
    signal: AbortSignal,
  ): Promise<ServiceReceipt> {
    const checked = serviceOperation(input);
    return serviceReceipt(
      await this.request(
        `/proxy/service/operations/${nextCommand(checked.expected_revision)}/${checked.request_id}?controller_epoch=${checked.controller_epoch}`,
        signal,
      ),
      checked,
    );
  }
  async endpointSettings(signal: AbortSignal): Promise<EndpointSettings> {
    return endpointSettings(
      await this.request("/proxy/endpoint-settings", signal),
    );
  }
  async targetEndpointSettings(
    id: string,
    signal: AbortSignal,
  ): Promise<EndpointSettings> {
    return endpointSettings(
      await this.request(
        `/targets/${idPath(id)}/proxy/endpoint-settings`,
        signal,
      ),
      id,
    );
  }
  async setEndpointSelection(
    id: string,
    selection: EndpointSelection,
    revision: string,
    generation: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<EndpointSettings> {
    idPath(id);
    if (!canonicalRevision(revision) || !endpointGeneration(generation))
      throw new ApiError("format");
    const value = endpointSelection(selection);
    const expected = nextCommand(revision);
    const result = endpointSettings(
      await this.request(`/proxy/endpoint-settings/${id}`, signal, {
        method: "PUT",
        csrf,
        body: JSON.stringify({
          expected_revision: revision,
          generation,
          selection: value,
        }),
      }),
    );
    if (result.revision !== expected || result.generation !== generation)
      throw new ApiError("format");
    return result;
  }
  async targetEndpointCommand(
    id: string,
    input: EndpointCommand,
    csrf: string,
    signal: AbortSignal,
  ): Promise<EndpointSubmission> {
    idPath(id);
    shapeEndpointCommand(input);
    const response = await this.requestResponse(
      `/targets/${id}/proxy/endpoint-commands`,
      signal,
      { csrf, body: JSON.stringify(input) },
    );
    return endpointSubmission(response.value, id, input, response.status);
  }
  async refreshEndpointCommand(
    id: string,
    jobId: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<import("./targets").MetadataJob> {
    idPath(jobId);
    const result = job(
      await this.request(
        `/targets/${idPath(id)}/proxy/endpoint-command/refresh`,
        signal,
        { csrf, body: JSON.stringify({ job_id: jobId }) },
      ),
      id,
    );
    if (
      !result ||
      result.resource !== "proxy_endpoints" ||
      result.job_id !== jobId
    )
      throw new ApiError("format");
    return result;
  }
  async targetUsers(
    id: string,
    options: Pagination & { include_deleted?: boolean },
    signal: AbortSignal,
  ): Promise<Page<ProxyUser>> {
    return page(
      await this.request(
        `/targets/${idPath(id)}/users${listQuery(options, false)}`,
        signal,
      ),
      proxyUser,
    );
  }
  async targetUserSearch(
    id: string,
    options: UserSearchOptions,
    signal: AbortSignal,
  ): Promise<Page<ProxyUser>> {
    return userSearchPage(
      await this.request(
        `/targets/${idPath(id)}/users/search${userSearchQuery(options)}`,
        signal,
      ),
      options,
    );
  }
  async targetCredentials(
    id: string,
    options: Pagination & { user_id?: string },
    signal: AbortSignal,
  ): Promise<Page<ProxyCredential>> {
    const result = page(
      await this.request(
        `/targets/${idPath(id)}/credentials${listQuery(options, true)}`,
        signal,
      ),
      proxyCredential,
    );
    if (
      options.user_id &&
      result.items.some((item) => item.user_id !== options.user_id)
    )
      throw new ApiError("format");
    return result;
  }
  async targetJob(id: string, signal: AbortSignal): Promise<Job | null> {
    return job(
      await this.request(`/targets/${idPath(id)}/command`, signal),
      id,
    );
  }
  /** Controller-local metadata only: this does not contact the destination. */
  async targetCommandHistory(
    peer: string,
    localNodeId: string,
    options: CommandHistoryOptions,
    signal: AbortSignal,
  ): Promise<CommandHistoryPage> {
    idPath(localNodeId);
    return commandHistoryPage(
      await this.request(
        `/targets/${idPath(peer)}/commands/history${commandHistoryQuery(options)}`,
        signal,
      ),
      peer,
      localNodeId,
      options,
    );
  }
  async targetCommandHistoryEntry(
    peer: string,
    localNodeId: string,
    jobId: string,
    signal: AbortSignal,
  ): Promise<CommandHistoryEntry> {
    idPath(localNodeId);
    return commandHistoryEntry(
      await this.request(
        `/targets/${idPath(peer)}/commands/history/${idPath(jobId)}`,
        signal,
      ),
      peer,
      localNodeId,
      jobId,
    );
  }
  async targetUserResult(
    id: string,
    expected: PolicyJob,
    csrf: string,
    signal: AbortSignal,
  ): Promise<UserResult> {
    const parsed = job(expected, idPath(id));
    if (
      !parsed ||
      parsed.resource !== undefined ||
      parsed.user_creation !== true ||
      parsed.routing ||
      parsed.maintenance !== undefined ||
      parsed.preset ||
      ["rejected", "superseded"].includes(parsed.state)
    )
      throw new ApiError("format");
    const prior = { ...parsed };
    return userResult(
      await this.request(`/targets/${id}/command/user-result`, signal, {
        csrf,
        body: JSON.stringify({ job_id: prior.job_id }),
      }),
      id,
      prior,
    );
  }
  async jobAction(
    id: string,
    action: "retry" | "supersede" | "refresh",
    jobId: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<Job> {
    if (!["retry", "supersede", "refresh"].includes(action))
      throw new ApiError("format");
    idPath(jobId);
    const result = job(
      await this.request(`/targets/${idPath(id)}/command/${action}`, signal, {
        csrf,
        body: JSON.stringify(action === "refresh" ? {} : { job_id: jobId }),
      }),
      id,
    );
    if (!result || result.job_id !== jobId) throw new ApiError("format");
    return result;
  }
  async targetCommand(
    id: string,
    input: CommandInput,
    csrf: string,
    signal: AbortSignal,
  ): Promise<Submission> {
    idPath(id);
    // The scope adapter constructs this fixed vocabulary; no source actor or
    // destination URL may enter a browser command body.
    shapeCommandInput(input);
    const response = await this.requestResponse(
      `/targets/${id}/commands`,
      signal,
      { csrf, body: JSON.stringify(input) },
    );
    return submission(response.value, id, input, response.status);
  }
  async targetRoutingCommand(
    id: string,
    input: RoutingCommandInput,
    csrf: string,
    signal: AbortSignal,
  ): Promise<RoutingSubmission> {
    shapeRoutingCommand(input);
    const response = await this.requestResponse(
      `/targets/${idPath(id)}/routing/commands`,
      signal,
      { csrf, body: JSON.stringify(input) },
    );
    return routingSubmission(response.value, id, input, response.status);
  }
  async targetRoutingCatalog(
    peer: string,
    kind: ResourceKind,
    options: Pagination,
    signal: AbortSignal,
  ): Promise<RoutingPage<Resource>> {
    if (!["prefixes", "addresses", "pools"].includes(kind))
      throw new ApiError("format");
    const parse =
      kind === "prefixes" ? prefix : kind === "addresses" ? address : pool;
    const result = routingPage<Resource>(
      await this.request(
        `/targets/${idPath(peer)}/proxy/${kind}${routingQuery(options)}`,
        signal,
      ),
      parse,
      (item) => item.id,
      options,
    );
    if (
      result.items.some(
        (item) => BigInt(item.revision) > BigInt(result.revision),
      )
    )
      throw new ApiError("format");
    return result;
  }
  async targetPoolMembers(
    peer: string,
    id: string,
    options: Pagination,
    signal: AbortSignal,
  ): Promise<RoutingPage<string>> {
    return routingPage(
      await this.request(
        `/targets/${idPath(peer)}/proxy/pools/${idPath(id)}/members${routingQuery(options)}`,
        signal,
      ),
      memberId,
      (item) => item,
      options,
    );
  }
  async targetRoutePermission(
    peer: string,
    id: string,
    signal: AbortSignal,
  ): Promise<PermissionView> {
    return permissionView(
      await this.request(
        `/targets/${idPath(peer)}/proxy/users/${idPath(id)}/routing`,
        signal,
      ),
      id,
    );
  }
  async targetHealth(
    peer: string,
    options: Pagination,
    signal: AbortSignal,
  ): Promise<HealthSnapshot> {
    const result = healthSnapshot(
      await this.request(
        `/targets/${idPath(peer)}/proxy/health${healthQuery(options)}`,
        signal,
      ),
    );
    if (
      result.entries.length > (options.limit ?? 10) ||
      (options.after !== undefined &&
        result.entries.some((item) => item.address_id <= options.after!))
    )
      throw new ApiError("format");
    return result;
  }

  async policy(signal: AbortSignal): Promise<PolicyStatus> {
    return policyStatus(await this.request("/proxy/policy", signal));
  }
  async users(
    options: Pagination & { include_deleted?: boolean },
    signal: AbortSignal,
  ): Promise<Page<ProxyUser>> {
    return page(
      await this.request(`/proxy/users${listQuery(options, false)}`, signal),
      proxyUser,
    );
  }
  async userSearch(
    options: UserSearchOptions,
    signal: AbortSignal,
  ): Promise<Page<ProxyUser>> {
    return userSearchPage(
      await this.request(
        `/proxy/users/search${userSearchQuery(options)}`,
        signal,
      ),
      options,
    );
  }
  async credentials(
    options: Pagination & { user_id?: string },
    signal: AbortSignal,
  ): Promise<Page<ProxyCredential>> {
    const result = page(
      await this.request(
        `/proxy/credentials${listQuery(options, true)}`,
        signal,
      ),
      proxyCredential,
    );
    if (
      options.user_id &&
      result.items.some((item) => item.user_id !== options.user_id)
    )
      throw new ApiError("format");
    return result;
  }
  async credentialSecret(
    credential: ProxyCredential,
    input: CredentialSecretInput,
    csrf: string,
    signal: AbortSignal,
  ): Promise<CredentialSecret> {
    const checked = credentialSecretInput(input);
    const expected = {
      id: credential.id,
      user_id: credential.user_id,
      verifier_revision: credential.verifier_revision,
    };
    if (
      checked.verifier_revision !== credential.verifier_revision ||
      credential.revoked
    ) {
      throw new ApiError("format");
    }
    return credentialSecret(
      await this.request(
        `/proxy/credentials/${idPath(credential.id)}/secret`,
        signal,
        {
          csrf,
          body: JSON.stringify(checked),
        },
      ),
      expected,
    );
  }
  async targetCredentialSecret(
    peer: string,
    credential: ProxyCredential,
    input: TargetCredentialSecretInput,
    csrf: string,
    signal: AbortSignal,
  ): Promise<CredentialSecret> {
    const checked = targetCredentialSecretInput(input);
    const expected = {
      id: credential.id,
      user_id: credential.user_id,
      verifier_revision: credential.verifier_revision,
    };
    if (
      checked.expected_node_id !== peer ||
      checked.user_id !== credential.user_id ||
      checked.verifier_revision !== credential.verifier_revision ||
      credential.revoked
    )
      throw new ApiError("format");
    return credentialSecret(
      await this.request(
        `/targets/${idPath(peer)}/proxy/credentials/${idPath(credential.id)}/secret`,
        signal,
        { csrf, body: JSON.stringify(checked) },
      ),
      expected,
    );
  }

  async userOperations(
    options: UserOperationOptions,
    signal: AbortSignal,
  ): Promise<UserOperationPage> {
    const query = userOperationQuery(options);
    const checked = { ...options };
    return userOperationPage(
      await this.request(`/proxy/user-operations${query}`, signal),
      checked,
    );
  }
  async userOperation(id: string, signal: AbortSignal): Promise<UserOperation> {
    return userOperation(
      await this.request(`/proxy/user-operations/${idPath(id)}`, signal),
      { id },
    );
  }
  async reserveUserOperation(
    input: UserOperationInput,
    csrf: string,
    signal: AbortSignal,
  ): Promise<UserOperation> {
    const checked = userOperationInput(input);
    const operation = userOperation(
      await this.request("/proxy/user-operations", signal, {
        csrf,
        body: JSON.stringify(checked),
      }),
      { input: checked },
    );
    if (operation.state !== "reserved") throw new ApiError("format");
    return operation;
  }
  async executeUserOperation(
    id: string,
    input: UserOperationInput,
    csrf: string,
    signal: AbortSignal,
  ): Promise<UserOperation> {
    const checked = userOperationInput(input);
    const operation = userOperation(
      await this.request(
        `/proxy/user-operations/${idPath(id)}/execute`,
        signal,
        {
          csrf,
          body: JSON.stringify(checked),
        },
      ),
      { id, input: checked },
    );
    if (operation.state === "reserved") throw new ApiError("format");
    return operation;
  }
  async createUser(
    input: UserInput,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<ChangeResult> {
    return changeResult(
      await this.request("/proxy/users", signal, {
        csrf,
        body: JSON.stringify({
          ...userInput(input),
          expected_revision: revisionInput(revision),
        }),
      }),
      "user",
    );
  }
  async updateUser(
    id: string,
    input: UserInput,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<ChangeResult> {
    const result = changeResult(
      await this.request(`/proxy/users/${idPath(id)}`, signal, {
        method: "PUT",
        csrf,
        body: JSON.stringify({
          ...userInput(input),
          expected_revision: revisionInput(revision),
        }),
      }),
      "user",
    );
    if (result.user?.id !== id) throw new ApiError("format");
    return result;
  }
  async userState(
    id: string,
    active: boolean,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<ChangeResult> {
    return this.userAction(id, "state", { active }, revision, csrf, signal);
  }
  async deleteUser(
    id: string,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<ChangeResult> {
    return this.userAction(id, "delete", {}, revision, csrf, signal);
  }
  private async userAction(
    id: string,
    action: "state" | "delete",
    body: Record<string, unknown>,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<ChangeResult> {
    const result = changeResult(
      await this.request(`/proxy/users/${idPath(id)}/${action}`, signal, {
        csrf,
        body: JSON.stringify({
          ...body,
          expected_revision: revisionInput(revision),
        }),
      }),
      "user",
    );
    if (result.user?.id !== id) throw new ApiError("format");
    return result;
  }
  async createCredential(
    userId: string,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<ChangeResult> {
    const result = changeResult(
      await this.request(`/proxy/users/${idPath(userId)}/credentials`, signal, {
        csrf,
        body: JSON.stringify({ expected_revision: revisionInput(revision) }),
      }),
      "secret",
    );
    if (result.credential?.user_id !== userId) throw new ApiError("format");
    return result;
  }
  async credentialState(
    id: string,
    active: boolean,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<ChangeResult> {
    return this.credentialAction(
      id,
      "state",
      { active },
      revision,
      csrf,
      signal,
    );
  }
  async revokeCredential(
    id: string,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<ChangeResult> {
    return this.credentialAction(id, "revoke", {}, revision, csrf, signal);
  }
  async rotateCredential(
    id: string,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<ChangeResult> {
    return this.credentialAction(id, "rotate", {}, revision, csrf, signal);
  }
  private async credentialAction(
    id: string,
    action: "state" | "revoke" | "rotate",
    body: Record<string, unknown>,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<ChangeResult> {
    const result = changeResult(
      await this.request(`/proxy/credentials/${idPath(id)}/${action}`, signal, {
        csrf,
        body: JSON.stringify({
          ...body,
          expected_revision: revisionInput(revision),
        }),
      }),
      action === "rotate" ? "secret" : "credential",
    );
    if (result.credential?.id !== id) throw new ApiError("format");
    return result;
  }

  async routingAddress(id: string, signal: AbortSignal): Promise<AddressView> {
    return addressView(
      await this.request(`/proxy/addresses/${idPath(id)}`, signal),
      id,
    );
  }
  async targetRoutingAddress(
    peer: string,
    id: string,
    signal: AbortSignal,
  ): Promise<AddressView> {
    return addressView(
      await this.request(
        `/targets/${idPath(peer)}/proxy/addresses/${idPath(id)}`,
        signal,
      ),
      id,
    );
  }
  async routingCatalog(
    kind: ResourceKind,
    options: Pagination,
    signal: AbortSignal,
  ): Promise<RoutingPage<Resource>> {
    if (!["prefixes", "addresses", "pools"].includes(kind))
      throw new ApiError("format");
    const parse =
      kind === "prefixes" ? prefix : kind === "addresses" ? address : pool;
    const result = routingPage<Resource>(
      await this.request(`/proxy/${kind}${routingQuery(options)}`, signal),
      parse,
      (item) => item.id,
      options,
    );
    if (
      result.items.some(
        (item) => BigInt(item.revision) > BigInt(result.revision),
      )
    )
      throw new ApiError("format");
    return result;
  }
  async health(
    options: Pagination,
    signal: AbortSignal,
  ): Promise<HealthSnapshot> {
    const result = healthSnapshot(
      await this.request(`/proxy/health${healthQuery(options)}`, signal),
    );
    if (
      result.entries.length > (options.limit ?? 10) ||
      (options.after !== undefined &&
        result.entries.some((item) => item.address_id <= options.after!))
    )
      throw new ApiError("format");
    return result;
  }
  async traffic(
    scope: TrafficScope,
    options: Pick<TrafficOptions, "protocol">,
    signal: AbortSignal,
  ): Promise<TrafficTotals> {
    return trafficTotals(
      await this.request(
        `/proxy/traffic${trafficQuery(scope, options)}`,
        signal,
      ),
      scope,
      options.protocol,
    );
  }
  async trafficBuckets(
    scope: HistoryScope,
    options: TrafficOptions,
    signal: AbortSignal,
  ): Promise<TrafficHistory> {
    return trafficHistory(
      await this.request(
        `/proxy/traffic/buckets${trafficQuery(scope, options, true)}`,
        signal,
      ),
      scope,
      options,
    );
  }
  async targetTraffic(
    peer: string,
    scope: TrafficScope,
    options: Pick<TrafficOptions, "protocol">,
    signal: AbortSignal,
  ): Promise<RemoteTraffic<TrafficTotals>> {
    return remoteTraffic(
      await this.request(
        `/targets/${idPath(peer)}/traffic${trafficQuery(scope, options)}`,
        signal,
      ),
      peer,
      scope,
      (value) => trafficTotals(value, scope, options.protocol),
    );
  }
  async targetTrafficBuckets(
    peer: string,
    scope: HistoryScope,
    options: TrafficOptions,
    signal: AbortSignal,
  ): Promise<RemoteTraffic<TrafficHistory>> {
    return remoteTraffic(
      await this.request(
        `/targets/${idPath(peer)}/traffic/buckets${trafficQuery(scope, options, true)}`,
        signal,
      ),
      peer,
      scope,
      (value) => trafficHistory(value, scope, options),
    );
  }
  async poolMembers(
    id: string,
    options: Pagination,
    signal: AbortSignal,
  ): Promise<RoutingPage<string>> {
    return routingPage(
      await this.request(
        `/proxy/pools/${idPath(id)}/members${routingQuery(options)}`,
        signal,
      ),
      memberId,
      (item) => item,
      options,
    );
  }
  async routePermission(
    id: string,
    signal: AbortSignal,
  ): Promise<PermissionView> {
    return permissionView(
      await this.request(`/proxy/users/${idPath(id)}/routing`, signal),
      id,
    );
  }
  async createPrefix(
    input: PrefixInput,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<RoutingChange> {
    if (!validUserName(input.name) || !validCidr(input.cidr))
      throw new ApiError("format");
    nextRoutingRevision(revision);
    return routingChange(
      await this.request("/proxy/prefixes", signal, {
        csrf,
        body: JSON.stringify({
          expected_revision: revision,
          name: input.name,
          cidr: input.cidr,
        }),
      }),
      "prefix",
      revision,
    );
  }
  async createAddress(
    input: AddressInput,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<RoutingChange> {
    if (
      !validUserName(input.name) ||
      !validIp(input.ip) ||
      !(input.prefix_id === null || canonicalId(input.prefix_id))
    )
      throw new ApiError("format");
    nextRoutingRevision(revision);
    return routingChange(
      await this.request("/proxy/addresses", signal, {
        csrf,
        body: JSON.stringify({
          expected_revision: revision,
          name: input.name,
          ip: input.ip,
          prefix_id: input.prefix_id,
        }),
      }),
      "address",
      revision,
    );
  }
  async createPool(
    input: PoolInput,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<RoutingChange> {
    if (!validUserName(input.name) || !addressFamily(input.family))
      throw new ApiError("format");
    nextRoutingRevision(revision);
    return routingChange(
      await this.request("/proxy/pools", signal, {
        csrf,
        body: JSON.stringify({
          expected_revision: revision,
          name: input.name,
          family: input.family,
        }),
      }),
      "pool",
      revision,
    );
  }
  async retirePrefix(
    id: string,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<RoutingChange> {
    nextRoutingRevision(revision);
    const result = routingChange(
      await this.request(`/proxy/prefixes/${idPath(id)}/retire`, signal, {
        csrf,
        body: JSON.stringify({ expected_revision: revision }),
      }),
      "prefix",
      revision,
      id,
    );
    if (result.entity.kind !== "prefix" || !result.entity.data.retired)
      throw new ApiError("format");
    return result;
  }
  async routingState(
    kind: "addresses" | "pools",
    id: string,
    state: ResourceState,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<RoutingChange> {
    if (!["addresses", "pools"].includes(kind) || !resourceState(state))
      throw new ApiError("format");
    nextRoutingRevision(revision);
    const result = routingChange(
      await this.request(`/proxy/${kind}/${idPath(id)}/state`, signal, {
        csrf,
        body: JSON.stringify({ expected_revision: revision, state }),
      }),
      kind === "addresses" ? "address" : "pool",
      revision,
      id,
    );
    if (
      result.entity.kind === "permission" ||
      result.entity.kind === "prefix" ||
      result.entity.data.state !== state
    )
      throw new ApiError("format");
    return result;
  }
  async poolMembership(
    poolId: string,
    addressId: string,
    remove: boolean,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<RoutingChange> {
    if (typeof remove !== "boolean") throw new ApiError("format");
    nextRoutingRevision(revision);
    idPath(addressId);
    return routingChange(
      await this.request(
        `/proxy/pools/${idPath(poolId)}/members${remove ? "/remove" : ""}`,
        signal,
        {
          csrf,
          body: JSON.stringify({
            expected_revision: revision,
            address_id: addressId,
          }),
        },
      ),
      "pool",
      revision,
      poolId,
    );
  }
  async setRoutePermission(
    input: RoutePermission,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<RoutingChange> {
    const grant = permissionInput(input);
    nextRoutingRevision(revision);
    const result = routingChange(
      await this.request(
        `/proxy/users/${idPath(grant.user_id)}/routing`,
        signal,
        {
          method: "PUT",
          csrf,
          body: JSON.stringify({
            expected_revision: revision,
            legacy_allowed: grant.legacy_allowed,
            exits: grant.exits,
            pools: grant.pools,
          }),
        },
      ),
      "permission",
      revision,
      grant.user_id,
    );
    if (
      result.entity.kind !== "permission" ||
      result.entity.data.legacy_allowed !== grant.legacy_allowed ||
      !["exits", "pools"].every((key) => {
        const field = key as "exits" | "pools";
        return (
          result.entity.kind === "permission" &&
          result.entity.data[field].length === grant[field].length &&
          result.entity.data[field].every((id) => grant[field].includes(id))
        );
      })
    )
      throw new ApiError("format");
    return result;
  }
  async presets(signal: AbortSignal): Promise<PresetCapability> {
    return presetCapability(await this.request("/proxy/presets", signal));
  }
  async targetPresets(
    peer: string,
    signal: AbortSignal,
  ): Promise<PresetCapability> {
    return presetCapability(
      await this.request(`/targets/${idPath(peer)}/proxy/presets`, signal),
      peer,
    );
  }
  async userPresets(id: string, signal: AbortSignal): Promise<UserPresetView> {
    return userPresetView(
      await this.request(`/proxy/users/${idPath(id)}/presets`, signal),
      id,
    );
  }
  async targetUserPresets(
    peer: string,
    id: string,
    signal: AbortSignal,
  ): Promise<UserPresetView> {
    return userPresetView(
      await this.request(
        `/targets/${idPath(peer)}/proxy/users/${idPath(id)}/presets`,
        signal,
      ),
      id,
    );
  }
  async poolPreset(id: string, signal: AbortSignal): Promise<PoolPresetView> {
    return poolPresetView(
      await this.request(`/proxy/pools/${idPath(id)}/presets`, signal),
      id,
    );
  }
  async targetPoolPreset(
    peer: string,
    id: string,
    signal: AbortSignal,
  ): Promise<PoolPresetView> {
    return poolPresetView(
      await this.request(
        `/targets/${idPath(peer)}/proxy/pools/${idPath(id)}/presets`,
        signal,
      ),
      id,
    );
  }
  async setUserPresets(
    input: UserPreset,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<UserPresetView> {
    const presets = userPreset(input);
    const expected = nextRoutingRevision(revision);
    const result = userPresetView(
      await this.request(
        `/proxy/users/${idPath(presets.user_id)}/presets`,
        signal,
        {
          method: "PUT",
          csrf,
          body: JSON.stringify({ expected_revision: revision, presets }),
        },
      ),
      presets.user_id,
    );
    if (
      result.revision !== expected ||
      !sameUserPreset(result.presets, presets)
    )
      throw new ApiError("format");
    return result;
  }
  async setPoolPreset(
    input: PoolPreset,
    revision: string,
    csrf: string,
    signal: AbortSignal,
  ): Promise<PoolPresetView> {
    const preset = poolPreset(input);
    const expected = nextRoutingRevision(revision);
    const result = poolPresetView(
      await this.request(
        `/proxy/pools/${idPath(preset.pool_id)}/presets`,
        signal,
        {
          method: "PUT",
          csrf,
          body: JSON.stringify({ expected_revision: revision, preset }),
        },
      ),
      preset.pool_id,
    );
    if (
      result.revision !== expected ||
      result.preset.default_preset !== preset.default_preset
    )
      throw new ApiError("format");
    return result;
  }
  async targetPresetCommand(
    peer: string,
    input: PresetCommandInput,
    csrf: string,
    signal: AbortSignal,
  ): Promise<PresetSubmission> {
    shapePresetCommand(input);
    const response = await this.requestResponse(
      `/targets/${idPath(peer)}/preset/commands`,
      signal,
      { csrf, body: JSON.stringify(input) },
    );
    return presetSubmission(response.value, peer, input, response.status);
  }
}
