import {
  Alert,
  Button,
  Collapse,
  Descriptions,
  Modal,
  Space,
  Typography,
} from "antd";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { ApiError, apiError } from "../../api/error";
import { errorMessage } from "../../api/messages";
import { drainNonce, type RuntimeStatus as Status } from "../../api/runtime";
import type { Target } from "../../api/targets";
import { useManagement } from "../../auth/context";
import type { Intent, Token } from "../../auth/node-changes";
import { useMessages } from "../../hooks/useMessages";

type DrainIntent = Extract<Intent, { kind: "runtime-drain" }>;
type View = {
  binding: string;
  status: Status;
  target: Target | null;
  fresh: boolean;
  original: boolean;
};

/** One irreversible request with an exact-ID read path. Browser notes retain
 * identity across reload; they never authorize replay on a replacement runtime. */
export default function RuntimeStatus({
  localNodeId,
  target,
  unavailable,
}: {
  localNodeId: string;
  target: Target | null;
  unavailable: boolean;
}) {
  const { controller, state } = useManagement();
  const { t } = useMessages();
  const changes = controller.nodeChanges;
  useSyncExternalStore(changes.subscribe, changes.snapshot);
  const epoch = controller.generation();
  const peer = target?.node_id ?? null,
    nodeId = peer ?? localNodeId;
  const binding = `${epoch}:${localNodeId}:${peer ?? "local"}:${target?.revision ?? "local"}`;
  const identity = useRef(binding);
  identity.current = binding;
  const scope = state.session
    ? { administratorId: state.session.administrator.id, nodeId: localNodeId }
    : null;
  const change = scope ? changes.find(scope) : null;
  const own =
    change?.intent.kind === "runtime-drain" && change.intent.targetId === peer
      ? change
      : null;
  const intent = own?.intent.kind === "runtime-drain" ? own.intent : null;
  const [expanded, setExpanded] = useState<string | null>(null);
  const open = expanded === binding || own !== null;
  const [view, setView] = useState<View | null>(null);
  const actual = view?.binding === binding ? view : null;
  const [failure, setFailure] = useState<{
    binding: string;
    error: ApiError;
    original: boolean;
  } | null>(null);
  const error = failure?.binding === binding ? failure : null;
  const [confirm, setConfirm] = useState<View | null>(null);
  const [working, setWorking] = useState<string | null>(null);
  const [reading, setReading] = useState<string | null>(null);
  const read = useRef<AbortController | null>(null),
    write = useRef<AbortController | null>(null);
  const serial = useRef(0),
    mounted = useRef(false);
  const observedToken = useRef<Token | null>(null);
  const busy = working === binding,
    loading = reading === binding;
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      serial.current++;
      read.current?.abort();
      write.current?.abort();
      if (observedToken.current)
        changes.invalidateObservation(observedToken.current);
      observedToken.current = null;
    };
  }, [binding, changes]);
  const belongs = () =>
    mounted.current &&
    identity.current === binding &&
    controller.generation() === epoch;
  const controlled = (snapshot: View) =>
    peer === null
      ? snapshot.status.ownership.controller_node_id === null
      : snapshot.target?.node_id === peer &&
        snapshot.target.active &&
        !snapshot.target.retired &&
        !snapshot.target.rollback_detected &&
        snapshot.status.ownership.controller_node_id === localNodeId;
  const writable =
    !!scope &&
    !!actual?.fresh &&
    !error &&
    !unavailable &&
    !state.busy &&
    !busy &&
    !loading &&
    !read.current &&
    !write.current &&
    changes.available(scope) &&
    controlled(actual) &&
    !actual.status.saved_accepting &&
    actual.status.runtime?.phase === "serving";

  const refresh = async (original = false) => {
    const session = state.session;
    if (
      !session ||
      unavailable ||
      state.busy ||
      write.current ||
      own?.phase === "pending" ||
      !belongs() ||
      (original && !intent)
    )
      return;
    read.current?.abort();
    const request = new AbortController();
    read.current = request;
    const id = ++serial.current,
      token = own?.token ?? null;
    if (token) changes.invalidateObservation(token);
    setConfirm(null);
    setReading(binding);
    setFailure(null);
    setView((previous) =>
      previous?.binding === binding ? { ...previous, fresh: false } : previous,
    );
    const current = () =>
      belongs() &&
      !request.signal.aborted &&
      serial.current === id &&
      controller.snapshot().session === session;
    try {
      const result = await controller.resource(
        session,
        async (client, _csrf, signal) => {
          const freshTarget =
            peer === null ? null : await client.target(peer, signal);
          const status = original
            ? await client.runtimeDrain(peer, intent!.request, signal)
            : await client.proxyRuntime(nodeId, peer, signal);
          return {
            binding,
            status,
            target: freshTarget,
            fresh: true,
            original,
          };
        },
        request.signal,
      );
      if (!current()) return;
      setView(result);
      if (token && scope && changes.find(scope)?.token === token) {
        changes.observe(token, {
          generation: epoch,
          owner: result.status.ownership,
          target: result.target,
        });
        observedToken.current = token;
      }
    } catch (problem) {
      if (current())
        setFailure({ binding, error: apiError(problem), original });
    } finally {
      if (read.current === request) {
        read.current = null;
        if (belongs()) setReading(null);
      }
    }
  };
  const submit = async () => {
    const snapshot = confirm,
      session = state.session;
    if (
      !snapshot ||
      !session ||
      !scope ||
      !writable ||
      snapshot !== actual ||
      !belongs()
    )
      return;
    let proposed: DrainIntent;
    try {
      proposed = {
        kind: "runtime-drain",
        targetId: peer,
        targetRevision: snapshot.target?.revision ?? null,
        request: {
          expected_node_id: nodeId,
          expected_epoch: snapshot.status.ownership.epoch,
          expected_revision: snapshot.status.saved_revision,
          runtime_id: snapshot.status.runtime!.runtime_id,
          request_id: drainNonce(),
        },
      };
    } catch (problem) {
      setFailure({ binding, error: apiError(problem), original: false });
      setConfirm(null);
      return;
    }
    const request = new AbortController();
    write.current = request;
    setWorking(binding);
    setFailure(null);
    let token: Token | null = null,
      admitted = false;
    const current = () =>
      belongs() &&
      !request.signal.aborted &&
      write.current === request &&
      controller.snapshot().session === session &&
      !controller.snapshot().busy;
    const cancelled = () => {
      if (token) {
        if (admitted) changes.fail(token, new ApiError("network"));
        else changes.notStarted(token);
      }
    };
    request.signal.addEventListener("abort", cancelled, { once: true });
    try {
      token = await changes.begin(scope, proposed, current);
      if (!token) return;
      const active = token;
      if (!current()) {
        changes.notStarted(active);
        return;
      }
      const status = await controller.resource(
        session,
        async (client, csrf, signal) => {
          admitted = true;
          signal.addEventListener("abort", cancelled, { once: true });
          try {
            return await client.drainRuntime(
              peer,
              proposed.request,
              proposed.targetRevision,
              csrf,
              signal,
            );
          } finally {
            signal.removeEventListener("abort", cancelled);
          }
        },
        request.signal,
      );
      if (!current()) throw new DOMException("Aborted", "AbortError");
      changes.runtimeAccepted(active);
      setView({
        binding,
        status,
        target: snapshot.target,
        fresh: false,
        original: true,
      });
    } catch (problem) {
      if (token) {
        if (admitted) changes.fail(token, apiError(problem));
        else changes.notStarted(token);
      }
      if (current())
        setFailure({ binding, error: apiError(problem), original: false });
    } finally {
      request.signal.removeEventListener("abort", cancelled);
      if (token) changes.release(token);
      if (write.current === request) {
        write.current = null;
        if (belongs()) {
          setWorking(null);
          setConfirm(null);
        }
      }
    }
  };
  const acknowledge = async () => {
    const session = state.session;
    if (
      !session ||
      !scope ||
      !own ||
      own.phase === "pending" ||
      !actual?.fresh ||
      error ||
      busy ||
      loading ||
      write.current ||
      !belongs() ||
      own.observation?.generation !== epoch
    )
      return;
    const request = new AbortController();
    write.current = request;
    setWorking(binding);
    const observation = own.observation;
    const current = () =>
      belongs() &&
      !request.signal.aborted &&
      write.current === request &&
      controller.snapshot().session === session &&
      !controller.snapshot().busy &&
      observedToken.current === own.token &&
      changes.find(scope)?.observation === observation;
    try {
      if (await changes.continue(own.token, epoch, current)) {
        if (
          belongs() &&
          !request.signal.aborted &&
          controller.snapshot().session === session
        )
          setView({ ...actual, fresh: false });
        observedToken.current = null;
      }
    } finally {
      if (write.current === request) {
        write.current = null;
        if (belongs()) setWorking(null);
      }
    }
  };
  const observed = actual?.status.runtime;
  const storageIssue = changes.issue();
  return (
    <Collapse
      ghost
      activeKey={open ? ["runtime"] : []}
      onChange={(keys) => {
        if (keys.includes("runtime")) {
          setExpanded(binding);
          if (!own) void refresh();
        } else if (!own) {
          setExpanded(null);
          serial.current++;
          read.current?.abort();
          setConfirm(null);
        }
      }}
      items={[
        {
          key: "runtime",
          label: t("runtime.title"),
          children: open && (
            <Space orientation="vertical" size={12} className="full-width">
              <Typography.Paragraph>{t("runtime.scope")}</Typography.Paragraph>
              <Typography.Text type="secondary">
                {t("runtime.wait")}
              </Typography.Text>
              <Alert type="info" showIcon title={t("runtime.boundary")} />
              {change && !own && (
                <Alert
                  type="warning"
                  showIcon
                  title={t("maintenance.otherChange")}
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
              {own && (
                <Alert
                  type={own.phase === "pending" ? "info" : "warning"}
                  showIcon
                  title={t(
                    own.phase === "pending"
                      ? "runtime.pending"
                      : "runtime.unknown",
                  )}
                  description={
                    <Space orientation="vertical">
                      <Typography.Text className="managed-identifier">
                        {intent!.request.runtime_id}
                      </Typography.Text>
                      <Typography.Text className="managed-identifier">
                        {intent!.request.request_id}
                      </Typography.Text>
                      {own.error && (
                        <Typography.Text>
                          {t(errorMessage(own.error))}
                        </Typography.Text>
                      )}
                    </Space>
                  }
                />
              )}
              <Space wrap>
                <Button
                  aria-label={t("runtime.read")}
                  loading={loading}
                  disabled={
                    loading ||
                    busy ||
                    unavailable ||
                    state.busy ||
                    own?.phase === "pending"
                  }
                  onClick={() => void refresh()}
                >
                  {t("runtime.read")}
                </Button>
                {intent && (
                  <Button
                    disabled={
                      loading ||
                      busy ||
                      unavailable ||
                      state.busy ||
                      own?.phase === "pending"
                    }
                    onClick={() => void refresh(true)}
                  >
                    {t("runtime.lookup")}
                  </Button>
                )}
              </Space>
              {error && (
                <Alert
                  type="error"
                  showIcon
                  title={t(
                    error.original && error.error.status === 404
                      ? "runtime.originalUnknown"
                      : error.error.status === 404
                        ? "runtime.unsupported"
                        : errorMessage(error.error),
                  )}
                />
              )}
              {actual && !actual.fresh && (
                <Alert
                  type="warning"
                  showIcon
                  title={t("maintenance.historical")}
                />
              )}
              {actual && (
                <>
                  <Typography.Text>
                    {t(
                      actual.original ? "runtime.original" : "runtime.current",
                    )}
                  </Typography.Text>
                  {observed ? (
                    <Descriptions
                      column={1}
                      items={[
                        {
                          key: "id",
                          label: t("runtime.runtimeId"),
                          children: (
                            <Typography.Text className="managed-identifier">
                              {observed.runtime_id}
                            </Typography.Text>
                          ),
                        },
                        {
                          key: "phase",
                          label: t("runtime.phase"),
                          children:
                            observed.phase === "serving" ? (
                              t("runtime.serving")
                            ) : (
                              <Alert
                                type={
                                  observed.phase === "draining"
                                    ? "info"
                                    : observed.phase === "drained"
                                      ? "success"
                                      : "error"
                                }
                                showIcon
                                title={t(`runtime.${observed.phase}`)}
                              />
                            ),
                        },
                        {
                          key: "active",
                          label: t("runtime.active"),
                          children:
                            observed.active_operations ??
                            t("maintenance.unknown"),
                        },
                        {
                          key: "request",
                          label: t("runtime.requestId"),
                          children:
                            observed.request?.request_id ??
                            t("maintenance.unknown"),
                        },
                      ]}
                    />
                  ) : (
                    <Alert
                      type="info"
                      showIcon
                      title={t("runtime.unavailable")}
                    />
                  )}
                  {observed && observed.phase !== "serving" && (
                    <Alert
                      type="warning"
                      showIcon
                      title={t("runtime.restart")}
                    />
                  )}
                  {actual.status.saved_accepting && (
                    <Alert
                      type="info"
                      showIcon
                      title={t("runtime.pausedRequired")}
                    />
                  )}
                  {!controlled(actual) && (
                    <Alert
                      type="warning"
                      showIcon
                      title={t("runtime.ownerBlocked")}
                    />
                  )}
                </>
              )}
              {own ? (
                <>
                  <Typography.Text>
                    {t("maintenance.acknowledgeHint")}
                  </Typography.Text>
                  <Button
                    loading={busy}
                    disabled={
                      !actual?.fresh ||
                      !!error ||
                      busy ||
                      loading ||
                      unavailable ||
                      state.busy ||
                      own.phase === "pending" ||
                      own.observation?.generation !== epoch
                    }
                    onClick={() => void acknowledge()}
                  >
                    {t("maintenance.acknowledge")}
                  </Button>
                </>
              ) : (
                <Button
                  danger
                  disabled={!writable}
                  onClick={() => actual && setConfirm(actual)}
                >
                  {t("runtime.start")}
                </Button>
              )}
              <Modal
                open={confirm !== null && confirm.binding === binding}
                title={t("runtime.start")}
                okText={t("runtime.confirm")}
                cancelText={t("runtime.cancel")}
                confirmLoading={busy}
                okButtonProps={{ disabled: !writable || confirm !== actual }}
                onOk={() => void submit()}
                onCancel={() => {
                  setConfirm(null);
                  write.current?.abort();
                }}
                destroyOnHidden
              >
                <Typography.Paragraph>
                  {t("runtime.scope")}
                </Typography.Paragraph>
                <Typography.Paragraph>{t("runtime.wait")}</Typography.Paragraph>
                <Typography.Text className="managed-identifier">
                  {nodeId}
                </Typography.Text>
                {confirm && (
                  <Descriptions
                    column={1}
                    items={[
                      {
                        key: "runtime",
                        label: t("runtime.runtimeId"),
                        children: confirm.status.runtime?.runtime_id,
                      },
                      {
                        key: "revision",
                        label: t("maintenance.expectedRevision"),
                        children: confirm.status.saved_revision,
                      },
                      {
                        key: "epoch",
                        label: t("maintenance.expectedEpoch"),
                        children: confirm.status.ownership.epoch,
                      },
                    ]}
                  />
                )}
              </Modal>
            </Space>
          ),
        },
      ]}
    />
  );
}
