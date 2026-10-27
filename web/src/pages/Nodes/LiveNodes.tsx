import { PageContainer, ProCard } from "@ant-design/pro-components";
import { Link } from "@umijs/max";
import {
  Alert,
  Button,
  Checkbox,
  Collapse,
  Descriptions,
  Empty,
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
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import {
  apiError,
  ApiError,
  type ManagementClient,
  type NodeView,
} from "../../api/client";
import { errorMessage } from "../../api/messages";
import { canonicalId, targetFilter, type PolicyStatus } from "../../api/proxy";
import { trafficHref } from "../../api/traffic";
import {
  deliveryAction,
  resourcesHref,
  usersHref,
  type Owner,
  type Target,
  type TargetPage,
} from "../../api/targets";
import { useManagement } from "../../auth/context";
import type { Intent, Scope, Token } from "../../auth/node-changes";
import ManagementGate from "../../components/ManagementGate";
import { useMessages } from "../../hooks/useMessages";
import TargetForm from "./TargetForm";
import CapabilityButton from "../../components/Presets/Capability";
import EndpointButton from "../../components/Connections/Endpoints";
import NodeSetupGuide from "./NodeSetupGuide";
import FirstUse from "./FirstUse";
import CertificateStatus from "./CertificateStatus";
import MaintenanceStatus from "./MaintenanceStatus";
import RuntimeStatus from "./RuntimeStatus";
import CommandHistory from "./CommandHistory";
import ChangeReview from "./ChangeReview";

type Work<T = unknown> = (
  client: ManagementClient,
  csrf: string,
  signal: AbortSignal,
) => Promise<T>;
function CurrentNodes() {
  const { controller, state } = useManagement();
  const { t } = useMessages();
  const epoch = controller.generation();
  const changes = controller.nodeChanges;
  useSyncExternalStore(changes.subscribe, changes.snapshot);
  const administratorId = state.session?.administrator.id;
  const [view, setView] = useState<{
    node: NodeView | null;
    policy: PolicyStatus | null;
    owner: Owner | null;
    targets: TargetPage | null;
    loading: boolean;
  }>({ node: null, policy: null, owner: null, targets: null, loading: true });
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [includeRetired, setIncludeRetired] = useState(false);
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [search, setSearch] = useState({
    epoch,
    draft: "",
    value: "",
    invalid: false,
  });
  // A changed session cannot send a prior administrator's filter/cursor before
  // the reset effect runs. Draft edits alone never request another page.
  const filter = search.epoch === epoch ? search.value : "";
  const [form, setForm] = useState<{
    target: Target | null;
    epoch: number;
    id: number;
  } | null>(null);
  const [setup, setSetup] = useState<{
    target: Target | null;
    epoch: number;
    id: number;
  } | null>(null);
  const [grant, setGrant] = useState<{
    expected: string;
    epoch: number;
    id: number;
  } | null>(null);
  const [confirmation, setConfirmation] = useState<{
    title:
      | "control.pause"
      | "control.resume"
      | "control.reactivate"
      | "control.retire"
      | "control.takeover";
    detail:
      | "control.pauseHint"
      | "control.reactivateHint"
      | "control.retireHint"
      | "control.takeoverHint";
    work: Work;
    intent: Intent;
    epoch: number;
    id: number;
  } | null>(null);
  const [grantForm] = Form.useForm();
  const read = useRef<AbortController | null>(null);
  const write = useRef<AbortController | null>(null);
  const sequence = useRef(0);
  const editor = useRef(0);
  const mounted = useRef(false);
  const lastNode = useRef<string | null>(null);
  const nodeId = view.node?.node_id ?? lastNode.current;
  const scope: Scope | null =
    state.session && nodeId
      ? {
          administratorId: state.session.administrator.id,
          nodeId,
        }
      : null;
  const change = scope ? changes.find(scope) : null;
  const storageIssue = changes.issue();
  function closeEditors() {
    editor.current++;
    setForm(null);
    setSetup(null);
    setGrant(null);
    setConfirmation(null);
  }
  function beginEditor(): number | null {
    if (
      !scope ||
      !mounted.current ||
      state.busy ||
      view.loading ||
      !view.node ||
      error ||
      epoch !== controller.generation() ||
      read.current ||
      write.current ||
      !changes.available(scope)
    )
      return null;
    closeEditors();
    return editor.current;
  }
  const cursor = search.epoch === epoch ? cursors.at(-1) : undefined;
  const refresh = useCallback(
    (preserveError = false) => {
      const session = state.session;
      if (!session || state.busy || write.current) return;
      if (lastNode.current) {
        const prior = changes.find({
          administratorId: session.administrator.id,
          nodeId: lastNode.current,
        });
        if (prior) changes.invalidateObservation(prior.token);
      }
      read.current?.abort();
      const request = new AbortController();
      read.current = request;
      const id = ++sequence.current;
      if (!preserveError) {
        setError(null);
      }
      setView((current) => ({ ...current, loading: true }));
      void controller
        .resource(
          session,
          async (client, _csrf, signal) => {
            const node = await client.node(signal);
            const policy = await client.policy(signal);
            const owner = await client.owner(signal);
            const targets = await client.targets(
              {
                after: cursor,
                limit: 25,
                include_retired: includeRetired,
                q: filter || undefined,
              },
              signal,
            );
            return { node, policy, owner, targets };
          },
          request.signal,
        )
        .then((result) => {
          if (
            !request.signal.aborted &&
            id === sequence.current &&
            epoch === controller.generation()
          ) {
            // A remounted page learns its node only after this read. Its ordinary
            // listing must not preserve an earlier precise review of a change.
            const prior = changes.find({
              administratorId: session.administrator.id,
              nodeId: result.node.node_id,
            });
            if (prior) changes.invalidateObservation(prior.token);
            lastNode.current = result.node.node_id;
            setView({ ...result, loading: false });
          }
        })
        .catch((error) => {
          if (
            !request.signal.aborted &&
            id === sequence.current &&
            epoch === controller.generation()
          ) {
            setError(apiError(error));
            setView({
              node: null,
              policy: null,
              owner: null,
              targets: null,
              loading: false,
            });
          }
        })
        .finally(() => {
          if (read.current === request) read.current = null;
        });
    },
    [
      controller,
      changes,
      state.session,
      state.busy,
      epoch,
      cursor,
      includeRetired,
      filter,
    ],
  );
  useEffect(() => {
    refresh();
    return () => {
      sequence.current++;
      read.current?.abort();
    };
  }, [refresh]);
  useEffect(() => {
    mounted.current = true;
    closeEditors();
    setSearch({ epoch, draft: "", value: "", invalid: false });
    setCursors([undefined]);
    return () => {
      mounted.current = false;
      editor.current++;
      write.current?.abort();
    };
  }, [epoch]);
  const runChange = async <T,>(
    intent: Intent,
    work: Work<T>,
    id: number,
    external?: AbortSignal,
  ): Promise<T | undefined> => {
    const session = state.session;
    if (
      !session ||
      !scope ||
      !view.node ||
      error ||
      state.busy ||
      read.current ||
      write.current ||
      !mounted.current ||
      id !== editor.current ||
      epoch !== controller.generation() ||
      external?.aborted
    )
      return undefined;
    const request = new AbortController();
    const cancel = () => request.abort();
    external?.addEventListener("abort", cancel, { once: true });
    write.current = request;
    const current = () =>
      mounted.current &&
      write.current === request &&
      !request.signal.aborted &&
      !external?.aborted &&
      controller.generation() === epoch &&
      controller.snapshot().session === session &&
      !controller.snapshot().busy &&
      editor.current === id &&
      lastNode.current === scope.nodeId;
    let token: Token | null = null;
    let admitted = false;
    const cancelled = () => {
      if (!token) return;
      if (admitted) changes.fail(token, new ApiError("network"));
      else changes.notStarted(token);
    };
    request.signal.addEventListener("abort", cancelled, { once: true });
    setBusy(true);
    setError(null);
    try {
      token = await changes.begin(scope, intent, current);
      if (!token) return undefined;
      const active = token;
      if (!current()) {
        changes.notStarted(active);
        return undefined;
      }
      const result = await controller.resource(
        session,
        async (client, csrf, signal) => {
          admitted = true;
          signal.addEventListener("abort", cancelled, { once: true });
          try {
            return await work(client, csrf, signal);
          } catch (failure) {
            changes.fail(active, apiError(failure));
            throw failure;
          } finally {
            signal.removeEventListener("abort", cancelled);
          }
        },
        request.signal,
      );
      if (!current()) throw new DOMException("Aborted", "AbortError");
      return changes.succeed(active) ? result : undefined;
    } catch (failure) {
      // Unmount/check cancellation fences the response, not the server commit.
      // Keep this non-secret note in the provider even if this page is gone.
      if (token) {
        if (admitted) changes.fail(token, apiError(failure));
        else changes.notStarted(token);
      }
      return undefined;
    } finally {
      external?.removeEventListener("abort", cancel);
      request.signal.removeEventListener("abort", cancelled);
      if (token) changes.release(token);
      if (write.current === request) {
        write.current = null;
        if (mounted.current) setBusy(false);
      }
    }
  };
  const mutate = async (
    intent: Intent,
    work: Work,
    id: number,
  ): Promise<boolean> => {
    const result = await runChange(intent, work, id);
    if (
      result === undefined ||
      !mounted.current ||
      id !== editor.current ||
      epoch !== controller.generation()
    )
      return false;
    closeEditors();
    refresh();
    return true;
  };
  const reviewCurrent = async () => {
    const session = state.session;
    if (
      !session ||
      !scope ||
      !change ||
      change.phase === "pending" ||
      state.busy ||
      read.current ||
      write.current ||
      epoch !== controller.generation()
    )
      return;
    closeEditors();
    changes.invalidateObservation(change.token);
    const targetId =
      change.intent.kind === "target" ? change.intent.targetId : null;
    const request = new AbortController();
    read.current = request;
    const id = ++sequence.current;
    setError(null);
    setView((current) => ({ ...current, loading: true }));
    try {
      const observation = await controller.resource(
        session,
        async (client, _csrf, signal) => {
          const node = await client.node(signal);
          if (node.node_id !== scope.nodeId) throw new ApiError("format");
          const owner = await client.owner(signal);
          let target: Target | null = null;
          if (targetId !== null) {
            try {
              target = await client.target(targetId, signal);
            } catch (failure) {
              const error = apiError(failure);
              if (!(
                error.kind === "server" &&
                error.status === 404 &&
                error.code === "resource_not_found"
              ))
                throw error;
            }
          }
          return { generation: epoch, owner, target, node };
        },
        request.signal,
      );
      if (
        !request.signal.aborted &&
        id === sequence.current &&
        epoch === controller.generation() &&
        changes.find(scope)?.token === change.token
      ) {
        changes.observe(change.token, observation);
        setView((current) => ({
          ...current,
          node: observation.node,
          owner: observation.owner,
          loading: false,
          targets:
            current.targets && targetId !== null
              ? {
                  ...current.targets,
                  items: current.targets.items.flatMap((target) =>
                    target.node_id !== targetId
                      ? [target]
                      : observation.target
                        ? [observation.target]
                        : [],
                  ),
                }
              : current.targets,
        }));
      }
    } catch (failure) {
      if (
        !request.signal.aborted &&
        id === sequence.current &&
        epoch === controller.generation()
      ) {
        setError(apiError(failure));
        setView((current) => ({ ...current, loading: false }));
      }
    } finally {
      if (read.current === request) read.current = null;
    }
  };
  const continueChange = async () => {
    const session = state.session;
    if (
      !session ||
      !scope ||
      !change ||
      state.busy ||
      read.current ||
      write.current ||
      error ||
      !mounted.current ||
      epoch !== controller.generation()
    )
      return;
    const request = new AbortController();
    write.current = request;
    const id = editor.current;
    const current = () =>
      mounted.current &&
      write.current === request &&
      !request.signal.aborted &&
      controller.generation() === epoch &&
      controller.snapshot().session === session &&
      !controller.snapshot().busy &&
      editor.current === id &&
      lastNode.current === scope.nodeId;
    setBusy(true);
    try {
      if (await changes.continue(change.token, epoch, current)) {
        if (!current()) return;
        closeEditors();
        setError(null);
      }
    } finally {
      if (write.current === request) {
        write.current = null;
        if (mounted.current) setBusy(false);
      }
    }
  };
  const readDisabled =
    busy || state.busy || view.loading || change?.phase === "pending";
  const disabled =
    readDisabled ||
    !!error ||
    !view.node ||
    !scope ||
    !changes.available(scope);
  const notice = change?.error ? (
    <Alert
      type="error"
      showIcon
      title={t(errorMessage(change.error))}
      description={t(
        change.phase === "rejected"
          ? "users.operationRejected"
          : "users.mutationUncertain",
      )}
    />
  ) : null;
  const owner = view.owner;
  return (
    <PageContainer
      className="management-page"
      title={t("nodes.title")}
      content={t("control.nodesDescription")}
      extra={
        <Space wrap>
          <Button
            loading={view.loading}
            disabled={busy || change?.phase === "pending"}
            onClick={() => refresh()}
          >
            {t("nodes.refresh")}
          </Button>
          <Button
            type="primary"
            disabled={disabled || !view.node}
            onClick={() => {
              const id = beginEditor();
              if (id !== null) setSetup({ target: null, epoch, id });
            }}
          >
            {t("setup.title")}
          </Button>
        </Space>
      }
    >
      <Space orientation="vertical" size={16} className="full-width">
        {change && (
          <ChangeReview
            change={change}
            epoch={epoch}
            reading={view.loading}
            blocked={busy || state.busy}
            readFailed={!!error}
            read={() => void reviewCurrent()}
            proceed={() => void continueChange()}
          />
        )}
        {change?.intent.kind === "proxy-service" && (
          <Alert
            type="warning"
            showIcon
            title={t("service.unconfirmed")}
            action={<Link to="/service">{t("service.inspect")}</Link>}
          />
        )}
        {(change?.intent.kind === "maintenance" ||
          change?.intent.kind === "runtime-drain") && (
          <Alert
            type="warning"
            showIcon
            title={t(
              change.intent.kind === "runtime-drain"
                ? "runtime.retained"
                : "maintenance.retained",
            )}
            description={
              <Typography.Text className="managed-identifier">
                {change.intent.targetId ?? change.scope.nodeId}
              </Typography.Text>
            }
          />
        )}
        {storageIssue && (
          <Alert
            type="warning"
            showIcon
            title={t("control.changeStorageBlocked")}
            description={t(`control.changeStorage.${storageIssue}`)}
          />
        )}
        {scope && !change && !storageIssue && !changes.available(scope) && (
          <Alert type="warning" showIcon title={t("control.changeCapacity")} />
        )}
        {!scope &&
          administratorId &&
          changes
            .snapshot()
            .some(
              (record) => record.scope.administratorId === administratorId,
            ) && (
            <Alert
              type="warning"
              showIcon
              title={t("control.changeIdentityPending")}
            />
          )}
        {error && (
          <Alert
            type="error"
            showIcon
            title={t(errorMessage(error))}
            action={<Button onClick={() => refresh()}>{t("api.retry")}</Button>}
          />
        )}
        {owner?.controller_node_id && (
          <Alert
            type="warning"
            showIcon
            title={t("control.locallyManaged")}
            description={t("control.ownerHint")}
          />
        )}
        <div className="node-local">
          {!view.node && (
            <ProCard
              className="node-card live-node-card"
              title={t("node.local")}
              variant="outlined"
            >
              <FirstUse policy={null} owner={null} unavailable />
            </ProCard>
          )}
          {view.node && (
            <ProCard
              className="node-card live-node-card"
              title={
                <Space wrap>
                  <Typography.Text className="node-title">
                    {view.node.name}
                  </Typography.Text>
                  <Tag color="blue">{t("node.local")}</Tag>
                </Space>
              }
              variant="outlined"
            >
              <Space orientation="vertical" className="full-width">
                <Tag>{t("node.apiReadSuccess")}</Tag>
                <FirstUse
                  policy={view.policy}
                  owner={owner}
                  unavailable={disabled || !!error}
                />
                <Descriptions
                  column={1}
                  items={[
                    {
                      key: "server-ip",
                      label: t("control.serverIp"),
                      children: t("control.serverIpUnregistered"),
                    },
                    {
                      key: "egress-ip",
                      label: t("control.egressIp"),
                      children: t("control.egressUnknown"),
                    },
                    {
                      key: "runtime",
                      label: t("users.proxyState"),
                      children: view.policy
                        ? t(
                            view.policy.proxy_running
                              ? view.policy.applied_revision === null
                                ? "users.degraded"
                                : view.policy.applied_revision ===
                                    view.policy.saved_revision
                                  ? "users.running"
                                  : "users.pending"
                              : "users.apiOnly",
                          )
                        : "—",
                    },
                  ]}
                />
                <Typography.Text type="secondary">
                  {t("control.healthUnknown")}
                </Typography.Text>
                <CertificateStatus
                  disabled={disabled}
                  nodeId={view.node.node_id}
                />
                <MaintenanceStatus
                  localNodeId={view.node.node_id}
                  target={null}
                  unavailable={busy || state.busy || view.loading || !!error}
                />
                <RuntimeStatus
                  localNodeId={view.node.node_id}
                  target={null}
                  unavailable={busy || state.busy || view.loading || !!error}
                />
                <div className="management-node-actions">
                  <EndpointButton
                    peer={null}
                    nodeId={view.node.node_id}
                    disabled={disabled}
                  />
                  <Link to="/users">{t("control.manageUsers")}</Link>
                  <Link to={resourcesHref()}>{t("control.manageIps")}</Link>
                  <Link to={trafficHref({ kind: "node", id: null })}>
                    {t("traffic.open")}
                  </Link>
                </div>
                <Collapse
                  ghost
                  items={[
                    {
                      key: "details",
                      label: t("control.nodeDetails"),
                      children: (
                        <Space orientation="vertical" className="full-width">
                          <Typography.Text className="managed-identifier">
                            {view.node.node_id}
                          </Typography.Text>
                          <Typography.Text type="secondary">
                            v{view.node.version} · {view.node.os} /{" "}
                            {view.node.arch}
                          </Typography.Text>

                          <Descriptions
                            column={1}
                            items={[
                              {
                                key: "saved",
                                label: t("users.savedRevision"),
                                children: view.policy?.saved_revision ?? "—",
                              },
                              {
                                key: "applied",
                                label: t("users.appliedRevision"),
                                children: view.policy?.applied_revision ?? "—",
                              },
                            ]}
                          />
                          <CapabilityButton peer={null} disabled={disabled} />
                        </Space>
                      ),
                    },
                  ]}
                />
              </Space>
            </ProCard>
          )}
        </div>
        <Alert
          type="info"
          showIcon
          title={t("control.registryNotice")}
          description={t("control.grantRequired")}
        />
        {view.targets && !view.targets.controller_available && (
          <Alert type="warning" showIcon title={t("control.tlsUnavailable")} />
        )}
        <Collapse
          className="management-node-control"
          items={[
            {
              key: "owner",
              label: t("control.localOwner"),
              children: (
                <ProCard loading={view.loading && !owner}>
                  <Descriptions
                    column={{ xs: 1, sm: 2 }}
                    items={[
                      {
                        key: "owner",
                        label: t("control.controller"),
                        children: owner
                          ? (owner.controller_node_id ??
                            t("control.localScope"))
                          : "—",
                      },
                      {
                        key: "epoch",
                        label: t("control.epoch"),
                        children: owner?.epoch ?? "—",
                      },
                    ]}
                  />
                  <Typography.Paragraph type="secondary">
                    {t("control.ownerHint")}
                  </Typography.Paragraph>
                  <Space wrap>
                    <Button
                      disabled={disabled || !owner}
                      onClick={() => {
                        const id = beginEditor();
                        if (id === null || !owner) return;
                        grantForm.resetFields();
                        setGrant({ expected: owner.epoch, epoch, id });
                      }}
                    >
                      {t("control.grant")}
                    </Button>
                    <Button
                      danger
                      disabled={disabled || !owner?.controller_node_id}
                      onClick={() => {
                        const id = beginEditor();
                        if (id === null || !owner) return;
                        setConfirmation({
                          title: "control.takeover",
                          detail: "control.takeoverHint",
                          epoch,
                          id,
                          intent: {
                            kind: "owner",
                            action: "takeover",
                            controllerId: null,
                            expectedEpoch: owner.epoch,
                          },
                          work: (client, csrf, signal) =>
                            client.setOwner(null, owner.epoch, csrf, signal),
                        });
                      }}
                    >
                      {t("control.takeover")}
                    </Button>
                  </Space>
                </ProCard>
              ),
            },
          ]}
        />
        <div className="node-filter-tools">
          <Input.Search
            className="node-filter"
            aria-label={t("control.searchNodes")}
            placeholder={t("control.searchNodes")}
            enterButton={t("users.searchSubmit")}
            allowClear
            maxLength={256}
            value={search.epoch === epoch ? search.draft : ""}
            disabled={readDisabled}
            status={
              search.epoch === epoch && search.invalid ? "error" : undefined
            }
            onChange={(event) => {
              const draft = event.target.value;
              // Search's clear action calls onSearch before onChange. Retain
              // that queued filter change instead of restoring this render's value.
              setSearch((current) => ({
                epoch,
                value: current.epoch === epoch ? current.value : "",
                draft,
                invalid: false,
              }));
            }}
            onSearch={(value) => {
              if (
                readDisabled ||
                read.current ||
                write.current ||
                epoch !== controller.generation()
              )
                return;
              let query: string;
              try {
                query = targetFilter(value);
              } catch {
                setSearch({
                  epoch,
                  value: filter,
                  draft: value,
                  invalid: true,
                });
                return;
              }
              closeEditors();
              setSearch({ epoch, value: query, draft: query, invalid: false });
              setCursors([undefined]);
              if (query === filter && cursors.length === 1) refresh();
            }}
          />
          <Checkbox
            checked={includeRetired}
            disabled={readDisabled}
            onChange={(event) => {
              setIncludeRetired(event.target.checked);
              setCursors([undefined]);
            }}
          >
            {t("control.includeRetired")}
          </Checkbox>
        </div>
        {search.epoch === epoch && search.invalid && (
          <Alert type="error" showIcon title={t("control.searchInvalid")} />
        )}
        <div className="node-grid">
          {view.targets?.items.map((target) => (
            <ProCard
              key={target.node_id}
              className="node-card live-node-card"
              title={
                <Typography.Text className="node-title">
                  {target.name}
                </Typography.Text>
              }
              variant="outlined"
              extra={
                <Tag color={target.rollback_detected ? "warning" : "default"}>
                  {t(
                    target.rollback_detected
                      ? "control.rollback"
                      : target.retired
                        ? "control.retired"
                        : target.active
                          ? "control.configured"
                          : "control.paused",
                  )}
                </Tag>
              }
            >
              <Space orientation="vertical" className="full-width">
                <Descriptions
                  column={1}
                  items={[
                    {
                      key: "server-ip",
                      label: t("control.serverIp"),
                      children: target.server_ip ? (
                        <Typography.Text className="managed-identifier">
                          {target.server_ip}
                        </Typography.Text>
                      ) : (
                        t("control.serverIpUnregistered")
                      ),
                    },
                    {
                      key: "egress-ip",
                      label: t("control.egressIp"),
                      children: t("control.egressUnknown"),
                    },
                  ]}
                />
                <Typography.Text type="secondary">
                  {t("control.egressHint")}
                </Typography.Text>
                <Typography.Text type="secondary">
                  {t("control.targetUnknown")}
                </Typography.Text>
                {view.node && (
                  <MaintenanceStatus
                    localNodeId={view.node.node_id}
                    target={target}
                    unavailable={busy || state.busy || view.loading || !!error}
                  />
                )}
                {view.node && (
                  <RuntimeStatus
                    localNodeId={view.node.node_id}
                    target={target}
                    unavailable={busy || state.busy || view.loading || !!error}
                  />
                )}
                <div className="management-node-actions">
                  {view.node && (
                    <CommandHistory
                      localNodeId={view.node.node_id}
                      targetId={target.node_id}
                      disabled={busy || state.busy || view.loading}
                    />
                  )}
                  <EndpointButton
                    peer={target.node_id}
                    nodeId={target.node_id}
                    disabled={disabled || !target.active || target.retired}
                  />
                  <Link to={usersHref(target.node_id)}>
                    {t("control.manageUsers")}
                  </Link>
                  <Link to={resourcesHref(target.node_id)}>
                    {t("control.manageIps")}
                  </Link>
                  <Link
                    to={trafficHref({ kind: "node", id: null }, target.node_id)}
                  >
                    {t("traffic.open")}
                  </Link>
                </div>
                <Collapse
                  ghost
                  items={[
                    {
                      key: "details",
                      label: t("control.nodeDetails"),
                      children: (
                        <Space orientation="vertical" className="full-width">
                          <Typography.Text className="managed-identifier">
                            {target.node_id}
                          </Typography.Text>
                          <Typography.Text
                            className="managed-identifier"
                            type="secondary"
                          >
                            {target.origin}
                          </Typography.Text>
                          <Descriptions
                            column={1}
                            items={[
                              {
                                key: "revision",
                                label: t("control.configRevision"),
                                children: target.revision,
                              },
                              {
                                key: "epoch",
                                label: t("control.observedEpoch"),
                                children: target.observed_epoch ?? "—",
                              },
                              {
                                key: "policy",
                                label: t("control.observedPolicy"),
                                children:
                                  target.observed_policy_revision ?? "—",
                              },
                            ]}
                          />

                          <Space wrap>
                            <Button
                              disabled={disabled || !view.node}
                              onClick={() => {
                                const id = beginEditor();
                                if (id !== null)
                                  setSetup({ target, epoch, id });
                              }}
                            >
                              {t("setup.continue")}
                            </Button>
                            <Button
                              disabled={disabled}
                              onClick={() => {
                                const id = beginEditor();
                                if (id !== null) setForm({ target, epoch, id });
                              }}
                            >
                              {t("control.editTarget")}
                            </Button>
                            <Button
                              disabled={disabled}
                              onClick={() => {
                                const id = beginEditor();
                                if (id === null) return;
                                setConfirmation({
                                  epoch,
                                  id,
                                  intent: {
                                    kind: "target",
                                    action: deliveryAction(target),
                                    targetId: target.node_id,
                                    expectedRevision: target.revision,
                                  },
                                  title: `control.${deliveryAction(target)}`,
                                  detail: target.retired
                                    ? "control.reactivateHint"
                                    : "control.pauseHint",
                                  work: (client, csrf, signal) =>
                                    client.targetState(
                                      target.node_id,
                                      target.revision,
                                      !target.active,
                                      false,
                                      csrf,
                                      signal,
                                    ),
                                });
                              }}
                            >
                              {t(`control.${deliveryAction(target)}`)}
                            </Button>
                            <Button
                              danger
                              disabled={disabled || target.retired}
                              onClick={() => {
                                const id = beginEditor();
                                if (id === null) return;
                                setConfirmation({
                                  epoch,
                                  id,
                                  intent: {
                                    kind: "target",
                                    action: "retire",
                                    targetId: target.node_id,
                                    expectedRevision: target.revision,
                                  },
                                  title: "control.retire",
                                  detail: "control.retireHint",
                                  work: (client, csrf, signal) =>
                                    client.targetState(
                                      target.node_id,
                                      target.revision,
                                      false,
                                      true,
                                      csrf,
                                      signal,
                                    ),
                                });
                              }}
                            >
                              {t("control.retire")}
                            </Button>
                            <CapabilityButton
                              peer={target.node_id}
                              disabled={disabled}
                            />
                          </Space>
                        </Space>
                      ),
                    },
                  ]}
                />
              </Space>
            </ProCard>
          ))}
        </div>
        {!view.loading && filter && view.targets?.items.length === 0 && (
          <Empty
            image={Empty.PRESENTED_IMAGE_SIMPLE}
            description={t("control.searchEmpty")}
          />
        )}
        <Space wrap>
          <Button
            disabled={readDisabled || cursors.length <= 1}
            onClick={() => setCursors((value) => value.slice(0, -1))}
          >
            {t("users.previous")}
          </Button>
          <Typography.Text>
            {t("users.page", { page: cursors.length })}
          </Typography.Text>
          <Button
            disabled={readDisabled || !view.targets?.next_cursor}
            onClick={() =>
              setCursors((value) => [...value, view.targets!.next_cursor!])
            }
          >
            {t("users.next")}
          </Button>
        </Space>
      </Space>
      {setup && setup.epoch === epoch && !state.busy && view.node && (
        <NodeSetupGuide
          key={`${epoch}:${view.node.node_id}:${setup.target?.node_id ?? "new"}:${setup.target?.revision ?? "new"}`}
          node={view.node}
          target={setup.target}
          controllerAvailable={view.targets?.controller_available ?? false}
          register={(value, signal) =>
            runChange(
              {
                kind: "target",
                action: "register",
                targetId: value.node_id,
                expectedRevision: null,
              },
              async (client, csrf, request) => {
                const target = await client.configureTarget(
                  value.node_id,
                  value.origin,
                  value.active,
                  null,
                  csrf,
                  request,
                  value.server_ip,
                );
                if (
                  target.origin !== value.origin ||
                  target.active !== value.active ||
                  target.retired
                )
                  throw new ApiError("format");
                return target;
              },
              setup.id,
              signal,
            )
          }
          close={closeEditors}
          registered={() => refresh()}
        />
      )}
      {form && form.epoch === epoch && !state.busy && (
        <TargetForm
          target={form.target}
          busy={busy}
          blocked={!!change}
          notice={notice}
          close={() => !busy && closeEditors()}
          submit={(value) =>
            mutate(
              {
                kind: "target",
                action: form.target ? "configure" : "register",
                targetId: value.node_id,
                expectedRevision: form.target?.revision ?? null,
              },
              (client, csrf, signal) =>
                client.configureTarget(
                  value.node_id,
                  value.origin,
                  value.active,
                  form.target?.revision ?? null,
                  csrf,
                  signal,
                  value.server_ip,
                ),
              form.id,
            )
          }
        />
      )}
      {grant && grant.epoch === epoch && !state.busy && (
        <Modal
          open
          maskClosable={false}
          title={t("control.grant")}
          okText={t("users.confirm")}
          cancelText={t("users.cancel")}
          confirmLoading={busy}
          okButtonProps={{ disabled: !!change }}
          closable={!busy}
          onCancel={() => !busy && closeEditors()}
          onOk={() => grantForm.submit()}
          destroyOnHidden
        >
          <Alert type="warning" showIcon title={t("control.grantHint")} />
          {notice}
          <Form
            form={grantForm}
            layout="vertical"
            preserve={false}
            disabled={busy || !!change}
            onFinish={({ controller_node_id }) =>
              void mutate(
                {
                  kind: "owner",
                  action: "grant",
                  controllerId: controller_node_id,
                  expectedEpoch: grant.expected,
                },
                (client, csrf, signal) =>
                  client.setOwner(
                    controller_node_id,
                    grant.expected,
                    csrf,
                    signal,
                  ),
                grant.id,
              )
            }
          >
            <Form.Item
              name="controller_node_id"
              label={t("control.nodeId")}
              rules={[
                {
                  validator: (_, value) =>
                    canonicalId(value)
                      ? Promise.resolve()
                      : Promise.reject(new Error(t("control.idRule"))),
                },
              ]}
            >
              <Input maxLength={22} autoComplete="off" />
            </Form.Item>
          </Form>
        </Modal>
      )}
      {confirmation && confirmation.epoch === epoch && !state.busy && (
        <Modal
          open
          maskClosable={false}
          title={t(confirmation.title)}
          okText={t("users.confirm")}
          cancelText={t("users.cancel")}
          confirmLoading={busy}
          okButtonProps={{ disabled: !!change }}
          closable={!busy}
          onCancel={() => !busy && closeEditors()}
          onOk={() =>
            void mutate(confirmation.intent, confirmation.work, confirmation.id)
          }
        >
          {notice}
          <Typography.Paragraph>{t(confirmation.detail)}</Typography.Paragraph>
        </Modal>
      )}
    </PageContainer>
  );
}
export default function LiveNodes() {
  return (
    <ManagementGate>
      <CurrentNodes />
    </ManagementGate>
  );
}
