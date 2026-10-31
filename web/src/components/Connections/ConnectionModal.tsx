import {
  ProForm,
  ProFormSelect,
  ProFormText,
} from "@ant-design/pro-components";
import { CopyOutlined } from "@ant-design/icons";
import {
  Alert,
  Button,
  Collapse,
  Descriptions,
  Form,
  Input,
  Modal,
  Space,
  Tag,
  Typography,
} from "antd";
import {
  useCallback,
  useEffect,
  useEffectEvent,
  useId,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Link } from "@umijs/max";
import { ApiError, apiError, type ManagementClient } from "../../api/client";
import {
  connectionPreview,
  type ConnectionInput,
  type ConnectionOperation,
  type ConnectionRoute,
} from "../../api/connection";
import { errorMessage } from "../../api/messages";
import { clientExamples } from "../../api/clientExamples";
import { diagnosticProfile } from "../../api/diagnosticProfile";
import {
  connectionUrl,
  endpointChoices,
  type EndpointCatalog,
} from "../../api/endpoints";
import type {
  Preset,
  PresetCapability,
  UserPresetView,
} from "../../api/presets";
import { readPresetView, presetReads } from "../../api/remotePresets";
import type {
  ProxyCredential,
  ProxyProtocol,
  ProxyUser,
  PolicyStatus,
} from "../../api/proxy";
import type { PermissionView } from "../../api/routing";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";
import { CapabilityView } from "../Presets/Capability";
import ClientExamples from "./ClientExamples";
import DiagnosticProfile, { DIAGNOSTIC_FILENAME } from "./DiagnosticProfile";
import ConnectionRouting from "./ConnectionRouting";
import {
  readConnectionLabels,
  type ConnectionLabels,
} from "./connectionLabels";
import {
  connectionPolicyState,
  connectionRoutes,
  reconcileConnectionRoute,
} from "./connectionState";
import { readConnectionDraft, writeConnectionDraft } from "./connectionDraft";

interface Snapshot {
  presets: UserPresetView;
  permission: PermissionView;
  capability: PresetCapability;
  endpoints: EndpointCatalog | null;
  policy: PolicyStatus;
}
export const DIAGNOSTIC_PREVIEW_MS = 60_000;
type Fields = {
  endpoint: string;
  host: string;
  port: string;
  protocol: ProxyProtocol | "https";
  operation: ConnectionOperation;
  route_kind: ConnectionRoute["kind"];
  route_value: string;
  device: Preset | "none";
};
const tcp = (operation: string) =>
  ["http_forward", "http_connect", "socks5_connect"].includes(operation);
function connectionOperations(
  protocol: Fields["protocol"],
): ConnectionOperation[] {
  return protocol === "http" || protocol === "https"
    ? ["http_forward", "http_connect"]
    : protocol === "socks5"
      ? ["socks5_connect", "socks5_bind", "socks5_udp"]
      : ["masque_udp"];
}

/** One focus boundary, whether opened directly or inside the credential drawer. */
function ConnectionSurface({
  inline,
  title,
  actions,
  canClose,
  close,
  children,
}: {
  inline: boolean;
  title: string;
  actions: ReactNode;
  canClose: boolean;
  close: () => void;
  children: ReactNode;
}) {
  const region = useRef<HTMLElement | null>(null);
  // Moving between views in one drawer needs a focus handoff, not another
  // focus trap. Subsequent metadata and preview updates must not steal focus.
  useEffect(() => {
    if (inline) region.current?.focus();
  }, [inline]);
  if (inline)
    return (
      <section
        ref={region}
        tabIndex={-1}
        aria-label={title}
        className="connection-workspace"
      >
        <div className="connection-workspace-toolbar">{actions}</div>
        {children}
      </section>
    );
  return (
    <Modal
      open
      width={1040}
      style={{
        top: 16,
        margin: "0 auto",
        paddingBottom: 16,
        maxWidth: "calc(100% - 32px)",
      }}
      classNames={{
        container: "connection-modal-container",
        body: "connection-modal-body",
      }}
      title={title}
      footer={actions}
      closable={canClose}
      mask={{ closable: false }}
      onCancel={close}
      destroyOnHidden
    >
      {children}
    </Modal>
  );
}
async function snapshot(
  client: ManagementClient,
  peer: string | null,
  user: string,
  signal: AbortSignal,
): Promise<Snapshot> {
  const result = await readPresetView(
    client,
    peer,
    async (api, signal) => {
      const presets = await api.userPresets(user, signal);
      const permission =
        peer === null
          ? await client.routePermission(user, signal)
          : await client.targetRoutePermission(peer, user, signal);
      if (permission.revision !== presets.revision)
        throw new ApiError("server", "policy_conflict", 409);
      return { presets, permission };
    },
    (value) => value.presets.revision,
    signal,
  );
  let endpoints: EndpointCatalog | null;
  try {
    endpoints = await (peer === null
      ? client.proxyEndpoints(signal)
      : client.targetEndpoints(peer, signal));
  } catch (failure) {
    const error = apiError(failure);
    // Only absence of this new read contract permits manual entry. Permission,
    // transport and malformed replies must not become permissive local data.
    if (
      error.kind !== "server" ||
      !(
        error.code === "remote_endpoints_unsupported" ||
        (peer === null && error.status === 404 && error.code === "not_found")
      )
    )
      throw failure;
    endpoints = null;
  }
  return {
    ...result.data,
    capability: result.capability,
    endpoints,
    policy: result.context.policy,
  };
}

/** One form for existing credentials and their one-time secret response.
 * Passwords leave the form only through an explicit clipboard or file export. */
export default function ConnectionModal({
  user,
  credential,
  peer,
  initialSecret,
  close,
  onBusy,
  readBlocked = false,
  inline = false,
}: {
  user: ProxyUser;
  credential: ProxyCredential;
  peer: string | null;
  initialSecret?: string;
  close: () => void;
  onBusy: (busy: boolean) => void;
  readBlocked?: boolean;
  inline?: boolean;
}) {
  const { t } = useMessages();
  const { controller, state } = useManagement();
  const epoch = controller.generation();
  const [form] = Form.useForm<Fields>();
  const formId = useId();
  // Bind one-time input to the first authenticated render too. A session
  // generation change must hide it until a new authorized read succeeds.
  const passwordGeneration = useRef<number | null>(
    state.session ? epoch : null,
  );
  if (passwordGeneration.current === null && state.session)
    passwordGeneration.current = epoch;
  const [passwordInput, setPasswordInput] = useState({
    value: initialSecret ?? "",
    id: credential.id,
    user: credential.user_id,
    revision: credential.verifier_revision,
    peer,
  });
  const password =
    passwordInput.id === credential.id &&
    passwordInput.user === credential.user_id &&
    credential.user_id === user.id &&
    passwordInput.revision === credential.verifier_revision &&
    passwordInput.peer === peer &&
    passwordGeneration.current === epoch &&
    !credential.revoked &&
    !user.deleted
      ? passwordInput.value
      : "";
  const [view, setView] = useState<Snapshot | null>(null),
    [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true),
    [busy, setBusy] = useState(false),
    [refresh, setRefresh] = useState(0);
  const [preview, setPreview] = useState<
    | (ReturnType<typeof connectionPreview> & {
        examples: ReturnType<typeof clientExamples>;
        operation: ConnectionOperation;
        generation: number;
        diagnostic: ReturnType<typeof diagnosticProfile>;
        owner: object;
        expires: number;
        serial: number;
        peer: string | null;
        userId: string;
        credentialId: string;
        session: typeof state.session;
      })
    | null
  >(null);
  const [copyStatus, setCopyStatus] = useState<"copied" | "failed" | null>(
    null,
  );
  const [downloadStatus, setDownloadStatus] = useState<
    "requested" | "failed" | null
  >(null);
  const [diagnosticStatus, setDiagnosticStatus] = useState<
    "requested" | "failed" | null
  >(null);
  const [expiredDiagnostic, setExpiredDiagnostic] = useState<object | null>(
    null,
  );
  const diagnosticOwner = useRef<object | null>(null);
  const downloadUrls = useRef(new Map<string, number>());
  const [labels, setLabels] = useState<ConnectionLabels | null>(null);
  const [labelError, setLabelError] = useState<ApiError | null>(null);
  const [manualOpen, setManualOpen] = useState(true);
  const [deviceOpen, setDeviceOpen] = useState(false);
  const [endpointChanged, setEndpointChanged] = useState(false);
  const [draftUnavailable, setDraftUnavailable] = useState(false);
  const initialEndpoint = useRef(false);
  const pending = useRef<AbortController | null>(null),
    serial = useRef(0);
  const passwordRequest = useRef<AbortController | null>(null);
  const automaticPassword = useRef<string | null>(null);
  const automaticPreview = useRef(false);
  const [passwordError, setPasswordError] = useState<ApiError | null>(null);
  const secret = useRef(password);
  secret.current = password;
  const currentScope = useRef({ user, credential, peer });
  currentScope.current = { user, credential, peer };
  const protocol =
    Form.useWatch("protocol", form) ?? user.protocols[0] ?? "http";
  const operation = Form.useWatch("operation", form);
  const endpoint = Form.useWatch("endpoint", form);
  const device = Form.useWatch("device", form) ?? "none";
  const load = useCallback(() => {
    const session = state.session;
    if (!session || state.busy || readBlocked) return;
    if (passwordRequest.current) {
      passwordRequest.current.abort();
      passwordRequest.current = null;
    }
    pending.current?.abort();
    // A replacement observation owns loading now. The aborted preview's
    // finally cannot clear busy after pending is reassigned to this read.
    setBusy(false);
    const request = new AbortController(),
      id = ++serial.current;
    pending.current = request;
    setLoading(true);
    setView(null);
    setError(null);
    setPreview(null);
    automaticPreview.current = false;
    diagnosticOwner.current = null;
    setDiagnosticStatus(null);
    setCopyStatus(null);
    setDownloadStatus(null);
    setLabels(null);
    setLabelError(null);
    void controller
      .resource(
        session,
        (client, _csrf, signal) => snapshot(client, peer, user.id, signal),
        request.signal,
      )
      .then((value) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          epoch === controller.generation()
        ) {
          if (pending.current === request) pending.current = null;
          setView(value);
          setLoading(false);
          form.setFieldsValue(
            reconcileConnectionRoute(
              value.permission.permission,
              form.getFieldValue("route_kind"),
              form.getFieldValue("route_value"),
            ),
          );
          if (!initialEndpoint.current) {
            initialEndpoint.current = true;
            const choices = value.endpoints
              ? endpointChoices(value.endpoints)
              : [];
            const saved = value.endpoints
              ? readConnectionDraft({
                  administrator: session.administrator.id,
                  node: value.endpoints.node_id,
                  user: user.id,
                  credential: credential.id,
                })
              : null;
            setDraftUnavailable(saved?.unavailable ?? false);
            const untouched = !(
              ["endpoint", "host", "port", "protocol"] as const
            ).some((name) => form.isFieldTouched(name));
            if (saved?.value && untouched) {
              const savedEndpoint = saved.value;
              const allowed = user.protocols.includes(
                savedEndpoint.protocol === "https"
                  ? "http"
                  : savedEndpoint.protocol,
              );
              const matches =
                savedEndpoint.endpoint === "manual" ||
                choices.some(
                  (entry) =>
                    entry.key === savedEndpoint.endpoint &&
                    entry.host === savedEndpoint.host &&
                    String(entry.port) === savedEndpoint.port &&
                    entry.protocol === savedEndpoint.protocol,
                );
              form.setFieldsValue({
                ...savedEndpoint,
                endpoint:
                  allowed && matches ? savedEndpoint.endpoint : undefined,
                protocol: allowed ? savedEndpoint.protocol : undefined,
                operation: allowed
                  ? savedEndpoint.protocol === "socks5"
                    ? "socks5_connect"
                    : savedEndpoint.protocol === "masque"
                      ? "masque_udp"
                      : "http_connect"
                  : undefined,
              });
              setEndpointChanged(!allowed || !matches);
              setManualOpen(true);
            } else {
              const endpoint = choices.find((entry) =>
                user.protocols.includes(
                  entry.protocol === "https" ? "http" : entry.protocol,
                ),
              );
              if (endpoint && untouched)
                form.setFieldsValue({
                  endpoint: endpoint.key,
                  host: endpoint.host,
                  port: String(endpoint.port),
                  protocol: endpoint.protocol,
                  operation:
                    endpoint.protocol === "socks5"
                      ? "socks5_connect"
                      : endpoint.protocol === "masque"
                        ? "masque_udp"
                        : "http_connect",
                });
            }
          } else {
            const selected = form.getFieldValue("endpoint");
            if (selected !== "manual" && selected !== undefined) {
              const endpoint =
                value.endpoints &&
                endpointChoices(value.endpoints).find(
                  (entry) => entry.key === selected,
                );
              if (
                !endpoint ||
                endpoint.host !== form.getFieldValue("host") ||
                String(endpoint.port) !== form.getFieldValue("port") ||
                endpoint.protocol !== form.getFieldValue("protocol")
              ) {
                // Listener indexes may be reused after a node restart. Do not
                // relabel old values as a new endpoint or auto-switch it. Keep
                // the address visible while requiring an explicit selection.
                form.setFieldValue("endpoint", undefined);
                setEndpointChanged(true);
                setManualOpen(true);
              }
            }
          }
        }
      })
      .catch((failure) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          epoch === controller.generation()
        ) {
          if (pending.current === request) pending.current = null;
          setError(apiError(failure));
          setLoading(false);
        }
      });
  }, [
    controller,
    state.session,
    state.busy,
    peer,
    user.id,
    credential.id,
    epoch,
    readBlocked,
    form,
    user.protocols,
  ]);
  useEffect(() => {
    load();
    return () => {
      serial.current++;
      pending.current?.abort();
      passwordRequest.current?.abort();
    };
  }, [load, refresh]);
  useEffect(() => {
    onBusy(busy || (peer !== null && loading));
  }, [busy, loading, peer, onBusy]);
  useEffect(
    () => () => {
      const request = passwordRequest.current;
      if (request) {
        passwordRequest.current = null;
        request.abort();
        setBusy(false);
      }
    },
    [
      credential.id,
      credential.verifier_revision,
      credential.revoked,
      user.deleted,
      peer,
    ],
  );
  useEffect(
    () => () => {
      secret.current = "";
      onBusy(false);
    },
    [onBusy],
  );
  useEffect(
    () => () => {
      for (const [url, timer] of downloadUrls.current) {
        window.clearTimeout(timer);
        URL.revokeObjectURL(url);
      }
      downloadUrls.current.clear();
    },
    [epoch],
  );
  useEffect(() => {
    if (!preview?.diagnostic) return;
    const owner = preview.owner;
    const timer = window.setTimeout(
      () => {
        if (diagnosticOwner.current === owner) setExpiredDiagnostic(owner);
      },
      Math.max(1, Math.ceil(preview.expires - performance.now()) + 1),
    );
    return () => window.clearTimeout(timer);
  }, [preview]);
  const blocked = busy || loading || state.busy;
  const canClose = !busy && !(peer !== null && loading);
  function replacePassword(value: string) {
    passwordGeneration.current = epoch;
    setPasswordInput({
      value,
      id: credential.id,
      user: credential.user_id,
      revision: credential.verifier_revision,
      peer,
    });
    setPreview(null);
    diagnosticOwner.current = null;
    setDiagnosticStatus(null);
    setCopyStatus(null);
    setDownloadStatus(null);
  }
  async function readPassword() {
    const session = state.session;
    if (
      !session ||
      blocked ||
      readBlocked ||
      pending.current ||
      passwordRequest.current ||
      credential.revoked ||
      user.deleted ||
      credential.user_id !== user.id
    )
      return;
    const request = new AbortController();
    const currentSerial = serial.current;
    passwordRequest.current = request;
    setBusy(true);
    setPasswordError(null);
    replacePassword("");
    try {
      const result = await controller.resource(
        session,
        async (client, csrf, signal) => {
          const node = await client.node(signal);
          if (peer !== null) {
            const target = await client.target(peer, signal);
            const policy = await client.targetPolicy(peer, signal);
            if (
              policy.controller_node_id !== node.node_id ||
              !target.active ||
              target.retired ||
              target.rollback_detected
            )
              throw new ApiError("server", "node_control_denied", 403);
            return client.targetCredentialSecret(
              peer,
              credential,
              {
                expected_node_id: peer,
                expected_target_revision: target.revision,
                user_id: credential.user_id,
                controller_epoch: policy.controller_epoch,
                verifier_revision: credential.verifier_revision,
              },
              csrf,
              signal,
            );
          }
          const owner = await client.owner(signal);
          if (owner.controller_node_id !== null)
            throw new ApiError("server", "node_control_denied", 403);
          return client.credentialSecret(
            credential,
            {
              expected_node_id: node.node_id,
              controller_epoch: owner.epoch,
              verifier_revision: credential.verifier_revision,
            },
            csrf,
            signal,
          );
        },
        request.signal,
      );
      try {
        if (
          !request.signal.aborted &&
          currentSerial === serial.current &&
          epoch === controller.generation() &&
          controller.snapshot().session === session &&
          currentScope.current.peer === peer &&
          currentScope.current.user.id === user.id &&
          !currentScope.current.user.deleted &&
          currentScope.current.credential.id === credential.id &&
          currentScope.current.credential.user_id === user.id &&
          currentScope.current.credential.verifier_revision ===
            credential.verifier_revision &&
          !currentScope.current.credential.revoked
        ) {
          replacePassword(result.secret);
        }
      } finally {
        result.secret = "";
      }
    } catch (cause) {
      if (
        !request.signal.aborted &&
        currentSerial === serial.current &&
        epoch === controller.generation()
      ) {
        setPasswordError(apiError(cause));
      }
    } finally {
      if (passwordRequest.current === request) passwordRequest.current = null;
      if (
        !request.signal.aborted &&
        currentSerial === serial.current &&
        epoch === controller.generation()
      )
        setBusy(false);
    }
  }
  const readStoredPassword = useEffectEvent(readPassword);
  useEffect(() => {
    const identity = `${epoch}:${peer}:${user.id}:${credential.id}:${credential.verifier_revision}`;
    if (
      pending.current ||
      passwordRequest.current ||
      !view ||
      blocked ||
      readBlocked ||
      password ||
      credential.revoked ||
      user.deleted ||
      credential.user_id !== user.id ||
      automaticPassword.current === identity
    )
      return;
    // Opening this workspace is the request to view its saved password. A
    // failure stays visible and never starts a retry/rotation loop.
    automaticPassword.current = identity;
    void readStoredPassword();
  }, [
    view,
    blocked,
    readBlocked,
    password,
    epoch,
    peer,
    user.id,
    user.deleted,
    credential.id,
    credential.user_id,
    credential.verifier_revision,
    credential.revoked,
  ]);
  const routes = view ? connectionRoutes(view.permission.permission) : [];
  const allowedProtocols = user.protocols.flatMap((value) =>
    value === "http" ? ["http", "https"] : [value],
  );
  const endpoints = view?.endpoints
    ? endpointChoices(view.endpoints).filter((entry) =>
        allowedProtocols.includes(entry.protocol),
      )
    : [];
  const runtimeMismatch =
    view?.endpoints &&
    view.endpoints.proxy_running !== view.policy.proxy_running;
  const operations = connectionOperations(protocol);
  const rememberEndpoint = () => {
    if (!state.session || !view?.endpoints || epoch !== controller.generation())
      return;
    const result = writeConnectionDraft(
      {
        administrator: state.session.administrator.id,
        node: view.endpoints.node_id,
        user: user.id,
        credential: credential.id,
      },
      form.getFieldsValue(["endpoint", "host", "port", "protocol"]),
    );
    if (result !== "incomplete") setDraftUnavailable(result === "unavailable");
  };
  const generate = async (fields: Fields) => {
    if (
      !state.session ||
      blocked ||
      pending.current ||
      passwordRequest.current ||
      !view ||
      user.deleted ||
      !user.active ||
      credential.revoked ||
      !credential.active ||
      credential.user_id !== user.id
    )
      return false;
    // React's disabled state can lag a same-batch click or effect. Acquire
    // request ownership synchronously before starting another async action.
    automaticPreview.current = true;
    const request = new AbortController(),
      id = ++serial.current;
    pending.current = request;
    setBusy(true);
    setError(null);
    setPreview(null);
    diagnosticOwner.current = null;
    setDiagnosticStatus(null);
    setCopyStatus(null);
    setDownloadStatus(null);
    try {
      const result = await controller.resource(
        state.session,
        async (client, _csrf, signal) => {
          const current = await snapshot(client, peer, user.id, signal);
          if (fields.endpoint !== "manual") {
            const endpoint =
              current.endpoints &&
              endpointChoices(current.endpoints).find(
                (entry) => entry.key === fields.endpoint,
              );
            if (
              !endpoint ||
              endpoint.protocol !== fields.protocol ||
              endpoint.host !== fields.host ||
              String(endpoint.port) !== fields.port
            )
              throw new ApiError("server", "policy_conflict", 409);
          }
          const route: ConnectionRoute =
            fields.route_kind === "default"
              ? { kind: "default" }
              : fields.route_kind === "pool" || fields.route_kind === "exit"
                ? { kind: fields.route_kind, id: fields.route_value }
                : { kind: fields.route_kind, value: fields.route_value };
          const pool =
            route.kind === "pool"
              ? await presetReads(client, peer).poolPreset(route.id, signal)
              : null;
          if (pool && pool.revision !== current.presets.revision)
            throw new ApiError("server", "policy_conflict", 409);
          const input: ConnectionInput = {
            login: credential.login,
            protocol: fields.protocol,
            operation: fields.operation,
            host: fields.host,
            port: fields.port,
            route,
            device: fields.device === "none" ? null : fields.device,
          };
          const preview = connectionPreview(input, {
            protocols: user.protocols,
            permission: current.permission.permission,
            user: current.presets.presets,
            pool: pool?.preset ?? null,
            capability: current.capability,
          });
          // Validate export syntax inside this recoverable action, not while
          // rendering user-entered fields (for example a multicast host).
          connectionUrl(preview);
          const examples = clientExamples({
            protocol: preview.protocol,
            host: preview.host,
            port: preview.port,
            username: preview.username,
            operation: fields.operation,
          });
          const diagnostic = diagnosticProfile({
            protocol: preview.protocol,
            host: preview.host,
            port: preview.port,
            username: preview.username,
            operation: fields.operation,
          });
          return {
            current,
            preview: {
              ...preview,
              operation: fields.operation,
              examples,
              diagnostic,
            },
          };
        },
        request.signal,
      );
      if (
        !request.signal.aborted &&
        id === serial.current &&
        epoch === controller.generation()
      ) {
        setView(result.current);
        if (labels?.revision !== result.current.permission.revision)
          setLabels(null);
        const owner = Object.freeze({});
        diagnosticOwner.current = owner;
        setExpiredDiagnostic(null);
        setPreview({
          ...result.preview,
          generation: epoch,
          owner,
          expires: performance.now() + DIAGNOSTIC_PREVIEW_MS,
          serial: id,
          peer,
          userId: user.id,
          credentialId: credential.id,
          session: state.session,
        });
      }
    } catch (failure) {
      if (
        !request.signal.aborted &&
        id === serial.current &&
        epoch === controller.generation()
      )
        setError(apiError(failure));
    } finally {
      if (pending.current === request) {
        pending.current = null;
        setBusy(false);
      }
    }
    return false;
  };
  const readLabels = async () => {
    if (
      !state.session ||
      blocked ||
      pending.current ||
      passwordRequest.current ||
      !view
    )
      return;
    const request = new AbortController(),
      id = ++serial.current;
    pending.current = request;
    setBusy(true);
    setLabels(null);
    setLabelError(null);
    try {
      const result = await controller.resource(
        state.session,
        (client, _csrf, signal) =>
          readConnectionLabels(client, peer, view.permission, signal),
        request.signal,
      );
      if (
        !request.signal.aborted &&
        id === serial.current &&
        epoch === controller.generation()
      )
        setLabels(result);
    } catch (failure) {
      if (
        !request.signal.aborted &&
        id === serial.current &&
        epoch === controller.generation()
      )
        setLabelError(apiError(failure));
    } finally {
      if (pending.current === request) {
        pending.current = null;
        setBusy(false);
      }
    }
  };
  const generateInitialPreview = useEffectEvent(() => {
    const fields = form.getFieldsValue(true);
    if (
      !fields.endpoint ||
      !fields.host ||
      !fields.port ||
      !fields.operation ||
      !fields.route_kind
    )
      return;
    automaticPreview.current = true;
    void generate(fields);
  });
  useEffect(() => {
    if (
      view &&
      !blocked &&
      !readBlocked &&
      !pending.current &&
      !passwordRequest.current &&
      !automaticPreview.current
    )
      generateInitialPreview();
  }, [view, blocked, readBlocked, password]);
  // Read generation and the current secret at the action boundary, too: a
  // session change can precede React's next render of these enabled buttons.
  const canUsePassword = () =>
    epoch === controller.generation() &&
    state.phase === "authenticated" &&
    !!state.session &&
    state.session === controller.snapshot().session &&
    !controller.snapshot().busy &&
    !blocked &&
    !readBlocked &&
    user.active &&
    !user.deleted &&
    credential.active &&
    !credential.revoked &&
    credential.user_id === user.id &&
    /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(secret.current);
  const canExport = () =>
    !!preview &&
    preview.generation === epoch &&
    canUsePassword() &&
    user.protocols.includes(
      preview.protocol === "https" ? "http" : preview.protocol,
    ) &&
    preview.protocol !== "masque";
  const copyPassword = async () => {
    if (!canUsePassword()) return;
    const generation = controller.generation();
    try {
      await navigator.clipboard.writeText(secret.current);
      if (generation === controller.generation()) setCopyStatus("copied");
    } catch {
      if (generation === controller.generation()) setCopyStatus("failed");
    }
  };
  // No password is required or accessed. Bind the public profile to the exact
  // checked preview, including invalidation before React's next render.
  const canExportDiagnostic = () =>
    !!preview?.diagnostic &&
    diagnosticOwner.current === preview.owner &&
    preview.serial === serial.current &&
    preview.peer === peer &&
    preview.userId === user.id &&
    preview.credentialId === credential.id &&
    preview.session === state.session &&
    preview.session === controller.snapshot().session &&
    preview.generation === epoch &&
    epoch === controller.generation() &&
    performance.now() <= preview.expires &&
    state.phase === "authenticated" &&
    !controller.snapshot().busy &&
    !blocked &&
    !readBlocked &&
    user.active &&
    !user.deleted &&
    credential.active &&
    !credential.revoked &&
    credential.user_id === user.id &&
    user.protocols.includes(
      preview.protocol === "https" ? "http" : preview.protocol,
    );
  const copyAuthenticatedUrl = async () => {
    if (!canExport() || !preview) return;
    const generation = controller.generation();
    setCopyStatus(null);
    try {
      // Copy only on request; never navigate to an authenticated proxy URL.
      await navigator.clipboard.writeText(
        connectionUrl(preview, preview.username, secret.current),
      );
      if (generation === controller.generation()) setCopyStatus("copied");
    } catch {
      if (generation === controller.generation()) setCopyStatus("failed");
    }
  };
  const requestDownload = (
    contents: () => string,
    filename: string,
    contentType: string,
  ) => {
    let url: string | null = null;
    let link: HTMLAnchorElement | null = null;
    try {
      if (
        typeof URL.createObjectURL !== "function" ||
        typeof URL.revokeObjectURL !== "function"
      ) {
        return false;
      }
      url = URL.createObjectURL(
        new Blob([contents() + "\n"], { type: contentType }),
      );
      link = document.createElement("a");
      link.href = url;
      link.download = filename;
      link.hidden = true;
      document.body.append(link);
      link.click();
      const requestedUrl = url;
      // Let the browser consume the download request before releasing its
      // backing data. A click cannot tell us whether the user saved the file.
      const timer = window.setTimeout(() => {
        downloadUrls.current.delete(requestedUrl);
        URL.revokeObjectURL(requestedUrl);
      }, 1_000);
      downloadUrls.current.set(url, timer);
      return true;
    } catch {
      if (url !== null) URL.revokeObjectURL(url);
      return false;
    } finally {
      link?.remove();
    }
  };
  const downloadAuthenticatedUrl = () => {
    if (!canExport() || !preview) return;
    setDownloadStatus(
      requestDownload(
        () => connectionUrl(preview, preview.username, secret.current),
        "vproxy-proxy-url.txt",
        "text/plain;charset=utf-8",
      )
        ? "requested"
        : "failed",
    );
  };
  const downloadDiagnostic = () => {
    if (!canExportDiagnostic() || !preview?.diagnostic) return;
    setDiagnosticStatus(
      requestDownload(
        () => JSON.stringify(preview.diagnostic, null, 2),
        DIAGNOSTIC_FILENAME,
        "application/json;charset=utf-8",
      )
        ? "requested"
        : "failed",
    );
  };
  const authenticatedUrl =
    canExport() && preview
      ? connectionUrl(preview, preview.username, password)
      : null;
  const readyExamples =
    canExport() && preview
      ? clientExamples(
          {
            protocol: preview.protocol,
            host: preview.host,
            port: preview.port,
            username: preview.username,
            operation: preview.operation,
          },
          password,
        )
      : preview?.examples;
  return (
    <ConnectionSurface
      inline={inline}
      title={t(initialSecret ? "users.secretTitle" : "presets.generatorTitle", {
        name: user.name,
      })}
      actions={
        <Space wrap className="connection-form-actions">
          <Button
            disabled={!canClose}
            onClick={() => {
              rememberEndpoint();
              replacePassword("");
              close();
            }}
          >
            {t(
              inline
                ? "connections.backToCredentials"
                : initialSecret
                  ? "users.secretClose"
                  : "connections.close",
            )}
          </Button>
          <Button
            type="primary"
            htmlType="submit"
            form={formId}
            loading={blocked}
            disabled={
              blocked ||
              !view ||
              !routes.length ||
              !user.active ||
              user.deleted ||
              credential.revoked ||
              !credential.active
            }
          >
            {t("presets.generate")}
          </Button>
        </Space>
      }
      canClose={canClose}
      close={() => {
        if (canClose) {
          rememberEndpoint();
          replacePassword("");
          close();
        }
      }}
    >
      <Space orientation="vertical" size={16} className="full-width">
        {initialSecret && (
          <Alert type="warning" showIcon title={t("users.secretWarning")} />
        )}
        <Descriptions
          column={1}
          size="small"
          items={[
            {
              key: "scope",
              label: t("control.scope"),
              children: (
                <Typography.Text className="managed-identifier">
                  {peer ?? t("control.localScope")}
                </Typography.Text>
              ),
            },
          ]}
        />
        {error && (
          <Alert
            type="error"
            showIcon
            title={t(errorMessage(error))}
            description={t(
              error.kind === "format"
                ? "presets.invalidInput"
                : "presets.unknownPolicy",
            )}
          />
        )}
        <Button
          size="small"
          disabled={blocked}
          onClick={() => setRefresh((value) => value + 1)}
        >
          {t("users.refresh")}
        </Button>
        {view && (
          <>
            {view.policy.proxy_running &&
            view.endpoints?.proxy_running &&
            connectionPolicyState(view.policy) === "users.running" ? (
              <Space wrap>
                <Tag color="success">{t("users.running")}</Tag>
                <Typography.Text type="secondary">
                  {t("connections.notTested")}
                </Typography.Text>
              </Space>
            ) : (
              <Alert
                type={
                  !view.policy.proxy_running ||
                  !view.endpoints?.proxy_running ||
                  connectionPolicyState(view.policy) !== "users.running"
                    ? "warning"
                    : "info"
                }
                showIcon
                title={t(
                  runtimeMismatch
                    ? "connections.stateChanged"
                    : view.policy.proxy_running
                      ? connectionPolicyState(view.policy)
                      : "users.proxyNotStarted",
                )}
                description={
                  peer === null &&
                  !initialSecret &&
                  !blocked &&
                  !runtimeMismatch &&
                  !view.policy.proxy_running ? (
                    <Space
                      orientation="vertical"
                      className="full-width"
                      size={4}
                    >
                      <span>{t("connections.notTested")}</span>
                      <Link
                        to="/service"
                        onClick={() => {
                          rememberEndpoint();
                          replacePassword("");
                          close();
                        }}
                      >
                        {t("connections.openService")}
                      </Link>
                    </Space>
                  ) : (
                    t("connections.notTested")
                  )
                }
              />
            )}
            {!routes.length && (
              <Alert type="warning" showIcon title={t("presets.noRoutes")} />
            )}
          </>
        )}
        <div className="connection-workspace-grid">
          <section
            className="connection-workspace-settings"
            aria-label={t("connections.settings")}
          >
            <ProForm<Fields>
              autoFocusFirstInput={!inline}
              id={formId}
              form={form}
              initialValues={{
                endpoint: "manual",
                host: "",
                port: "",
                protocol: user.protocols[0] ?? "http",
                operation:
                  user.protocols[0] === "socks5"
                    ? "socks5_connect"
                    : user.protocols[0] === "masque"
                      ? "masque_udp"
                      : "http_connect",
                route_kind: "default",
                route_value: "",
                device: "none",
              }}
              submitter={false}
              scrollToFirstError={{ focus: true }}
              onFinish={generate}
              onFinishFailed={({ errorFields }) => {
                if (
                  errorFields.some(({ name }) =>
                    name.some((field) =>
                      ["host", "port", "protocol"].includes(String(field)),
                    ),
                  )
                )
                  setManualOpen(true);
              }}
              onValuesChange={(changed) => {
                setPreview(null);
                diagnosticOwner.current = null;
                setDiagnosticStatus(null);
                setCopyStatus(null);
                setDownloadStatus(null);
                if (changed.endpoint !== undefined) setEndpointChanged(false);
                if (changed.endpoint === "manual") setManualOpen(true);
                if (changed.endpoint && changed.endpoint !== "manual") {
                  const endpoint = endpoints.find(
                    (entry) => entry.key === changed.endpoint,
                  );
                  if (endpoint)
                    form.setFieldsValue({
                      host: endpoint.host,
                      port: String(endpoint.port),
                      protocol: endpoint.protocol,
                      operation: connectionOperations(
                        endpoint.protocol,
                      ).includes(form.getFieldValue("operation"))
                        ? form.getFieldValue("operation")
                        : endpoint.protocol === "socks5"
                          ? "socks5_connect"
                          : endpoint.protocol === "masque"
                            ? "masque_udp"
                            : "http_connect",
                    });
                }
                if (
                  changed.host !== undefined ||
                  changed.port !== undefined ||
                  changed.protocol
                ) {
                  form.setFieldValue("endpoint", "manual");
                  setEndpointChanged(false);
                }
                if (
                  changed.protocol &&
                  !connectionOperations(changed.protocol).includes(
                    form.getFieldValue("operation"),
                  )
                )
                  form.setFieldValue(
                    "operation",
                    changed.protocol === "socks5"
                      ? "socks5_connect"
                      : changed.protocol === "masque"
                        ? "masque_udp"
                        : "http_connect",
                  );
                if (Object.hasOwn(changed, "route_kind"))
                  form.setFieldValue("route_value", "");
                if (
                  ["endpoint", "host", "port", "protocol"].some((name) =>
                    Object.hasOwn(changed, name),
                  )
                )
                  rememberEndpoint();
              }}
            >
              <ProFormSelect
                name="endpoint"
                label={t("connections.selectEndpoint")}
                disabled={blocked}
                fieldProps={{ allowClear: false }}
                rules={[{ required: true }]}
                tooltip={t("presets.endpointHint")}
                options={[
                  ...allowedProtocols.flatMap((protocol) => {
                    const entries = endpoints.filter(
                      (entry) => entry.protocol === protocol,
                    );
                    return entries.length
                      ? [
                          {
                            label: protocol.toUpperCase(),
                            options: entries.map((entry) => ({
                              value: entry.key,
                              label: connectionUrl(entry),
                            })),
                          },
                        ]
                      : [];
                  }),
                  { value: "manual", label: t("connections.manual") },
                ]}
              />
              {endpointChanged && (
                <Alert
                  className="management-form-notice"
                  type="warning"
                  showIcon
                  title={t("connections.endpointChanged")}
                />
              )}
              {view &&
                (view.endpoints === null ||
                  (view.policy.proxy_running && !endpoints.length)) && (
                  <Alert
                    className="management-form-notice"
                    type="warning"
                    showIcon
                    title={t(
                      view.endpoints === null
                        ? "connections.unsupported"
                        : "connections.unconfiguredHint",
                    )}
                  />
                )}
              {view?.endpoints && draftUnavailable && (
                <Alert
                  type="warning"
                  showIcon
                  title={t("connections.rememberFailed")}
                />
              )}
              {endpoint === "manual" || endpointChanged ? (
                <Collapse
                  className="management-form-notice"
                  activeKey={manualOpen ? ["manual"] : []}
                  onChange={(keys) => setManualOpen(keys.includes("manual"))}
                  items={[
                    {
                      key: "manual",
                      label: t("connections.manual"),
                      forceRender: true,
                      children: (
                        <>
                          <Typography.Paragraph type="secondary">
                            {t("presets.endpointHint")}
                          </Typography.Paragraph>
                          <ProFormText
                            name="host"
                            label={t("presets.host")}
                            disabled={blocked}
                            fieldProps={{ autoComplete: "off", maxLength: 253 }}
                            rules={[{ required: true }]}
                          />
                          <ProFormText
                            name="port"
                            label={t("presets.port")}
                            disabled={blocked}
                            fieldProps={{ inputMode: "numeric", maxLength: 5 }}
                            rules={[{ required: true }]}
                          />
                          <ProFormSelect
                            name="protocol"
                            label={t("presets.protocol")}
                            disabled={blocked}
                            options={allowedProtocols.map((value) => ({
                              value,
                              label: value.toUpperCase(),
                            }))}
                            fieldProps={{ allowClear: false }}
                            rules={[{ required: true }]}
                          />
                        </>
                      ),
                    },
                  ]}
                />
              ) : (
                <>
                  <Form.Item name="host" hidden>
                    <Input />
                  </Form.Item>
                  <Form.Item name="port" hidden>
                    <Input />
                  </Form.Item>
                  <Form.Item name="protocol" hidden>
                    <Input />
                  </Form.Item>
                </>
              )}
              <ProFormSelect
                name="operation"
                label={t("presets.operation")}
                disabled={blocked}
                options={operations.map((value) => ({
                  value,
                  label: t(`presets.${value}`),
                }))}
                rules={[{ required: true }]}
              />
              {device !== "none" && !tcp(operation ?? "") && (
                <Alert
                  className="management-form-notice"
                  type="warning"
                  showIcon
                  title={t("connections.deviceOperationConflict")}
                  action={
                    <Button
                      size="small"
                      disabled={blocked}
                      onClick={() => setDeviceOpen(true)}
                    >
                      {t("connections.reviewDevice")}
                    </Button>
                  }
                />
              )}
              <ConnectionRouting
                permission={view?.permission.permission}
                peer={peer}
                blocked={blocked}
                labels={labels}
                labelError={labelError}
                readLabels={() => void readLabels()}
              />
              <Collapse
                className="management-form-notice"
                activeKey={deviceOpen ? ["device"] : []}
                onChange={(keys) => setDeviceOpen(keys.includes("device"))}
                items={[
                  {
                    key: "device",
                    label: `${t("connections.advancedDevice")} · ${device === "none" ? t("presets.automatic") : device}`,
                    forceRender: true,
                    children: (
                      <>
                        <Typography.Paragraph type="secondary">
                          {t("presets.precedence")}
                        </Typography.Paragraph>
                        <ProFormSelect
                          name="device"
                          label={t("presets.device")}
                          disabled={blocked}
                          fieldProps={{ allowClear: false }}
                          options={[
                            { value: "none", label: t("presets.automatic") },
                            ...(tcp(operation ?? "")
                              ? (view?.presets.presets.allowed_presets
                                  .filter((name) =>
                                    view.capability.available_presets.includes(
                                      name,
                                    ),
                                  )
                                  .map((value) => ({ value, label: value })) ??
                                [])
                              : []),
                          ]}
                        />
                      </>
                    ),
                  },
                ]}
              />
            </ProForm>
          </section>
          <section
            className="connection-workspace-preview"
            aria-label={t("connections.preview")}
          >
            <Typography.Title level={2} className="connection-preview-title">
              {t("connections.preview")}
            </Typography.Title>
            <Form.Item label={t("users.secret")}>
              <Input
                aria-label={t("users.secret")}
                autoComplete="off"
                name="proxy-password-preview"
                maxLength={43}
                value={password}
                spellCheck={false}
                readOnly
                className="connection-secret"
                suffix={
                  <Button
                    type="text"
                    icon={<CopyOutlined aria-hidden />}
                    aria-label={t("connections.copyPassword")}
                    disabled={!canUsePassword()}
                    onClick={() => void copyPassword()}
                  />
                }
              />
              <Button
                type="link"
                disabled={
                  blocked ||
                  readBlocked ||
                  credential.revoked ||
                  user.deleted ||
                  credential.user_id !== user.id
                }
                onClick={() => void readPassword()}
              >
                {t("users.readPassword")}
              </Button>
              {passwordError && (
                <Alert
                  type="warning"
                  showIcon
                  title={t(errorMessage(passwordError))}
                />
              )}
            </Form.Item>
            {!preview && (
              <Typography.Paragraph type="secondary">
                {t("connections.previewHint")}
              </Typography.Paragraph>
            )}
            {preview && (
              <Descriptions
                column={1}
                items={[
                  {
                    key: "endpoint",
                    label: t("presets.endpoint"),
                    children: (
                      <Typography.Text code copyable>
                        {connectionUrl(preview)}
                      </Typography.Text>
                    ),
                  },
                  ...(authenticatedUrl
                    ? [
                        {
                          key: "authenticated-url",
                          label: t("connections.proxyUrl"),
                          children: (
                            <Typography.Text code>
                              {authenticatedUrl}
                            </Typography.Text>
                          ),
                        },
                      ]
                    : []),
                  {
                    key: "username",
                    label: t("users.login"),
                    children: (
                      <Typography.Text
                        code
                        copyable
                        className="managed-identifier"
                      >
                        {preview.username}
                      </Typography.Text>
                    ),
                  },
                  {
                    key: "preset",
                    label: t("presets.effective"),
                    children: preview.effective_preset ?? t("presets.native"),
                  },
                ]}
              />
            )}
            {preview && (
              <Space orientation="vertical" className="full-width">
                <Alert
                  type="warning"
                  showIcon
                  title={t(
                    preview.protocol === "masque"
                      ? "connections.masqueAuth"
                      : "connections.clipboardWarning",
                  )}
                  description={
                    preview.protocol === "http" || preview.protocol === "socks5"
                      ? t("connections.unencryptedProxy")
                      : undefined
                  }
                />
                {preview.protocol !== "masque" && (
                  <>
                    <Space wrap className="connection-form-actions">
                      <Button
                        disabled={!canExport()}
                        onClick={() => void copyAuthenticatedUrl()}
                      >
                        {t("connections.copyAuthenticatedUrl")}
                      </Button>
                      <Button
                        disabled={!canExport()}
                        onClick={downloadAuthenticatedUrl}
                      >
                        {t("connections.downloadAuthenticatedUrl")}
                      </Button>
                    </Space>
                    <Typography.Paragraph type="secondary">
                      {t("connections.downloadWarning")}
                    </Typography.Paragraph>
                  </>
                )}
                {copyStatus && (
                  <Alert
                    type={copyStatus === "copied" ? "success" : "error"}
                    showIcon
                    title={t(
                      copyStatus === "copied"
                        ? "connections.copied"
                        : "connections.copyFailed",
                    )}
                  />
                )}
                {downloadStatus && (
                  <Alert
                    type={downloadStatus === "requested" ? "info" : "error"}
                    showIcon
                    title={t(
                      downloadStatus === "requested"
                        ? "connections.downloadRequested"
                        : "connections.downloadFailed",
                    )}
                  />
                )}
              </Space>
            )}
            {readyExamples && (
              <ClientExamples value={readyExamples} canCopy={canExport} />
            )}
            {preview && (
              <DiagnosticProfile
                value={preview.diagnostic}
                disabled={!canExportDiagnostic()}
                expired={
                  expiredDiagnostic === preview.owner ||
                  performance.now() > preview.expires ||
                  preview.serial !== serial.current
                }
                status={diagnosticStatus}
                download={downloadDiagnostic}
              />
            )}
          </section>
        </div>
        {view && (
          <Collapse
            items={[
              {
                key: "observations",
                label: t("connections.observationDetails"),
                children: (
                  <Space
                    orientation="vertical"
                    className="full-width"
                    size={16}
                  >
                    <Typography.Paragraph>
                      {t("connections.policyObservationHint")}
                    </Typography.Paragraph>
                    <Typography.Paragraph>
                      {t("presets.previewHint")}
                    </Typography.Paragraph>
                    <Descriptions
                      column={1}
                      size="small"
                      items={[
                        {
                          key: "saved",
                          label: t("users.savedRevision"),
                          children: view.policy.saved_revision,
                        },
                        {
                          key: "applied",
                          label: t("users.appliedRevision"),
                          children: view.policy.applied_revision ?? "—",
                        },
                      ]}
                    />
                    <CapabilityView value={view.capability} />
                  </Space>
                ),
              },
            ]}
          />
        )}
      </Space>
    </ConnectionSurface>
  );
}
