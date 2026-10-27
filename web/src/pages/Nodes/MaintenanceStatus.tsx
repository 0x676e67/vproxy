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
import { apiError, ApiError } from "../../api/error";
import { errorMessage } from "../../api/messages";
import type { MaintenanceStatus as Status } from "../../api/maintenance";
import { nextCommand, type Job, type Target } from "../../api/targets";
import { useManagement } from "../../auth/context";
import type { Intent, Token } from "../../auth/node-changes";
import { useMessages } from "../../hooks/useMessages";

type MaintenanceIntent = Extract<Intent, { kind: "maintenance" }>;
type View = {
  binding: string;
  status: Status;
  target: Target | null;
  job: Job | null;
  fresh: boolean;
  resumable: boolean;
};

/** Correlation is deliberately stronger than a matching latest-job ID. A lost
 * first reply without an ID cannot claim a later current-slot command. */
export function matchesMaintenance(
  intent: MaintenanceIntent,
  job: Job | null,
  peer: string,
): boolean {
  return (
    job !== null &&
    job.resource === undefined &&
    job.maintenance !== undefined &&
    intent.jobId !== null &&
    job.job_id === intent.jobId &&
    job.node_id === peer &&
    job.controller_epoch === intent.expectedEpoch &&
    job.command_id === intent.commandId &&
    job.expected_policy_revision === intent.expectedRevision &&
    job.maintenance.accepting === intent.accepting
  );
}
const pending = (job: Job | null) =>
  job?.state === "pending" || job?.state === "blocked";

/** An explicit observation and one confirmed write at a time. A browser note
 * survives cancellation/reload but is never an API receipt or replay key. */
export default function MaintenanceStatus({
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
  const peer = target?.node_id ?? null;
  const nodeId = peer ?? localNodeId;
  const binding = `${epoch}:${localNodeId}:${peer ?? "local"}:${target?.revision ?? "local"}`;
  const identity = useRef(binding);
  identity.current = binding;
  const scope = state.session
    ? { administratorId: state.session.administrator.id, nodeId: localNodeId }
    : null;
  const change = scope ? changes.find(scope) : null;
  const own =
    change?.intent.kind === "maintenance" && change.intent.targetId === peer
      ? change
      : null;
  const [expanded, setExpanded] = useState<string | null>(null);
  const open = expanded === binding || own !== null;
  const [view, setView] = useState<View | null>(null);
  const actual = view?.binding === binding ? view : null;
  const [failure, setFailure] = useState<{
    binding: string;
    error: ApiError;
  } | null>(null);
  const error = failure?.binding === binding ? failure.error : null;
  const [receipt, setReceipt] = useState<{
    binding: string;
    kind: "saved" | "applied" | "rejected";
  } | null>(null);
  const [confirm, setConfirm] = useState<{
    view: View;
    accepting: boolean;
  } | null>(null);
  const [working, setWorking] = useState<string | null>(null);
  const [reading, setReading] = useState<string | null>(null);
  const read = useRef<AbortController | null>(null);
  const write = useRef<AbortController | null>(null);
  const serial = useRef(0);
  const mounted = useRef(false);
  const observedToken = useRef<Token | null>(null);
  const busy = working === binding;
  const loading = reading === binding;
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
  const canTarget = (snapshot: View) =>
    peer === null
      ? snapshot.status.ownership.controller_node_id === null
      : snapshot.target?.node_id === peer &&
        snapshot.target.active &&
        !snapshot.target.retired &&
        !snapshot.target.rollback_detected &&
        snapshot.status.ownership.controller_node_id === localNodeId;
  const hasSequence = (snapshot: View) =>
    BigInt(snapshot.status.saved_revision) < 9223372036854775807n &&
    (peer === null ||
      BigInt(snapshot.status.ownership.last_terminal_command) <
        9223372036854775807n);
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
    canTarget(actual) &&
    hasSequence(actual) &&
    (actual.status.saved_accepting || actual.resumable);

  const refresh = async (receiptOnly = false) => {
    const session = state.session;
    if (
      !session ||
      unavailable ||
      state.busy ||
      write.current ||
      own?.phase === "pending" ||
      !belongs()
    )
      return;
    if (
      receiptOnly &&
      (peer === null || own?.intent.kind !== "maintenance" || !own.intent.jobId)
    )
      return;
    read.current?.abort();
    const request = new AbortController();
    read.current = request;
    const id = ++serial.current;
    const token = own?.token ?? null;
    if (token) changes.invalidateObservation(token);
    setConfirm(null);
    setReading(binding);
    setFailure(null);
    setView((current) =>
      current?.binding === binding ? { ...current, fresh: false } : current,
    );
    const current = () =>
      belongs() &&
      !request.signal.aborted &&
      serial.current === id &&
      controller.snapshot().session === session;
    try {
      const result = await controller.resource(
        session,
        async (client, csrf, signal) => {
          // A receipt refresh must still address the original retained ID. It
          // does not retry execution, and a replacement current slot is refused.
          const job =
            peer === null || !own
              ? null
              : receiptOnly
                ? await client.maintenanceRefresh(
                    peer,
                    (own.intent as MaintenanceIntent).jobId!,
                    csrf,
                    signal,
                  )
                : await client.targetJob(peer, signal);
          if (
            receiptOnly &&
            (own?.intent.kind !== "maintenance" ||
              !matchesMaintenance(own.intent, job, peer!))
          )
            throw new ApiError("format");
          const freshTarget =
            peer === null ? null : await client.target(peer, signal);
          const status = await client.maintenance(nodeId, peer, signal);
          let resumable = false;
          try {
            const runtime = await client.proxyRuntime(nodeId, peer, signal);
            resumable =
              runtime.runtime === null || runtime.runtime.phase === "serving";
          } catch (problem) {
            const failure = apiError(problem);
            // Older peers can still support saved admission without the
            // runtime protocol. Unknown runtime state never enables resume.
            if (
              failure.status !== 404 &&
              failure.code !== "node_protocol_unsupported"
            )
              throw failure;
          }
          return {
            binding,
            status,
            target: freshTarget,
            job,
            fresh: true,
            resumable,
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
      if (current()) setFailure({ binding, error: apiError(problem) });
    } finally {
      if (read.current === request) {
        read.current = null;
        if (belongs()) setReading(null);
      }
    }
  };

  const submit = async () => {
    const confirmation = confirm;
    const session = state.session;
    if (
      !confirmation ||
      !session ||
      !scope ||
      !writable ||
      confirmation.view !== actual ||
      !belongs()
    )
      return;
    const snapshot = confirmation.view;
    const intent: MaintenanceIntent = {
      kind: "maintenance",
      targetId: peer,
      accepting: confirmation.accepting,
      expectedRevision: snapshot.status.saved_revision,
      expectedEpoch: snapshot.status.ownership.epoch,
      targetRevision: snapshot.target?.revision ?? null,
      commandId:
        peer === null
          ? null
          : nextCommand(snapshot.status.ownership.last_terminal_command),
      jobId: null,
    };
    const request = new AbortController();
    write.current = request;
    setWorking(binding);
    setFailure(null);
    setReceipt(null);
    let token: Token | null = null;
    let admitted = false;
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
      token = await changes.begin(scope, intent, current);
      if (!token) return;
      const active = token;
      if (!current()) {
        changes.notStarted(active);
        return;
      }
      const result = await controller.resource(
        session,
        async (client, csrf, signal) => {
          admitted = true;
          signal.addEventListener("abort", cancelled, { once: true });
          try {
            if (peer === null) {
              await client.setMaintenance(
                {
                  expected_node_id: nodeId,
                  expected_revision: intent.expectedRevision,
                  expected_epoch: intent.expectedEpoch,
                  accepting: intent.accepting,
                },
                csrf,
                signal,
              );
              return { kind: "saved" as const, job: null };
            }
            const response = await client.targetMaintenanceCommand(
              peer,
              {
                expected_target_revision: intent.targetRevision!,
                controller_epoch: intent.expectedEpoch,
                command_id: intent.commandId!,
                expected_policy_revision: intent.expectedRevision,
                mutation: {
                  action: "set_admission",
                  accepting: intent.accepting,
                },
              },
              csrf,
              signal,
            );
            return {
              kind: response.response?.status ?? null,
              job: response.job,
            };
          } finally {
            signal.removeEventListener("abort", cancelled);
          }
        },
        request.signal,
      );
      if (!current()) throw new DOMException("Aborted", "AbortError");
      if (result.kind === null && result.job)
        changes.maintenanceTicket(active, result.job.job_id);
      else if (result.kind !== null && changes.succeed(active))
        setReceipt({ binding, kind: result.kind });
    } catch (problem) {
      if (token) {
        if (admitted) changes.fail(token, apiError(problem));
        else changes.notStarted(token);
      }
      if (current()) setFailure({ binding, error: apiError(problem) });
    } finally {
      request.signal.removeEventListener("abort", cancelled);
      if (token) changes.release(token);
      if (write.current === request) {
        write.current = null;
        if (belongs()) {
          setWorking(null);
          setConfirm(null);
          if (admitted)
            setView((previous) =>
              previous?.binding === binding
                ? { ...previous, fresh: false }
                : previous,
            );
        }
      }
    }
  };
  const reviewable =
    !!own &&
    own.phase !== "pending" &&
    !!actual?.fresh &&
    !error &&
    !loading &&
    !busy &&
    !unavailable &&
    own.observation?.generation === epoch &&
    !pending(actual.job);
  const acknowledge = async () => {
    if (
      !reviewable ||
      !own ||
      !actual ||
      !scope ||
      !state.session ||
      !belongs() ||
      write.current
    )
      return;
    const request = new AbortController();
    const observation = actual;
    const session = state.session;
    write.current = request;
    setWorking(binding);
    const current = () =>
      belongs() &&
      !request.signal.aborted &&
      write.current === request &&
      controller.snapshot().session === session &&
      !controller.snapshot().busy &&
      observedToken.current === own.token &&
      changes.find(scope)?.observation === own.observation;
    try {
      if (await changes.continue(own.token, epoch, current)) {
        if (
          belongs() &&
          !request.signal.aborted &&
          controller.snapshot().session === session
        )
          setView({ ...observation, fresh: false });
        // Clearing the exact note is not proof of the old write's outcome.
        observedToken.current = null;
      }
    } finally {
      if (write.current === request) {
        write.current = null;
        if (belongs()) setWorking(null);
      }
    }
  };
  const intent = own?.intent.kind === "maintenance" ? own.intent : null;
  const observed = actual?.status;
  const intentJob =
    intent && peer
      ? matchesMaintenance(intent, actual?.job ?? null, peer)
      : false;
  const display = (value: boolean | null) =>
    value === null
      ? t("maintenance.unknown")
      : t(value ? "maintenance.accepting" : "maintenance.paused");
  return (
    <Collapse
      ghost
      activeKey={open ? ["maintenance"] : []}
      onChange={(keys) => {
        if (keys.includes("maintenance")) {
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
          key: "maintenance",
          label: t("maintenance.title"),
          children: open && (
            <Space orientation="vertical" size={12} className="full-width">
              <Typography.Paragraph type="secondary">
                {t("maintenance.scope")}
              </Typography.Paragraph>
              <Alert type="info" showIcon title={t("maintenance.shutdown")} />
              {peer !== null && (
                <Typography.Text type="secondary">
                  {t("maintenance.queue")}
                </Typography.Text>
              )}
              {change && !own && (
                <Alert
                  type="warning"
                  showIcon
                  title={t("maintenance.otherChange")}
                />
              )}
              {own && (
                <Alert
                  type={own.phase === "pending" ? "info" : "warning"}
                  showIcon
                  title={t(
                    own.phase === "pending"
                      ? "maintenance.pending"
                      : "maintenance.uncertain",
                  )}
                  description={
                    <Space orientation="vertical" className="full-width">
                      <Descriptions
                        column={1}
                        items={[
                          {
                            key: "intent",
                            label: t("maintenance.intent"),
                            children: display(intent!.accepting),
                          },
                          {
                            key: "revision",
                            label: t("maintenance.expectedRevision"),
                            children: intent!.expectedRevision,
                          },
                          {
                            key: "epoch",
                            label: t("maintenance.expectedEpoch"),
                            children: intent!.expectedEpoch,
                          },
                          ...(intent!.jobId
                            ? [
                                {
                                  key: "job",
                                  label: t("maintenance.job"),
                                  children: (
                                    <Typography.Text className="managed-identifier">
                                      {intent!.jobId}
                                    </Typography.Text>
                                  ),
                                },
                              ]
                            : []),
                        ]}
                      />
                      {own.error && (
                        <Typography.Text>
                          {t(errorMessage(own.error))}
                        </Typography.Text>
                      )}
                      <Typography.Text>
                        {t("maintenance.acknowledgeHint")}
                      </Typography.Text>
                    </Space>
                  }
                />
              )}
              <Space wrap>
                <Button
                  aria-label={t("maintenance.read")}
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
                  {t("maintenance.read")}
                </Button>
                {intent?.jobId && peer !== null && (
                  <Button
                    disabled={
                      loading ||
                      busy ||
                      unavailable ||
                      state.busy ||
                      own?.phase === "pending" ||
                      !intentJob
                    }
                    onClick={() => void refresh(true)}
                  >
                    {t("maintenance.readReceipt")}
                  </Button>
                )}
              </Space>
              {error && (
                <Alert
                  type="error"
                  showIcon
                  title={t(
                    error.status === 404
                      ? "maintenance.unsupported"
                      : errorMessage(error),
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
              {receipt?.binding === binding && (
                <Alert
                  type={receipt.kind === "rejected" ? "warning" : "success"}
                  showIcon
                  title={t(`maintenance.${receipt.kind}Reply`)}
                />
              )}
              {observed && (
                <Descriptions
                  column={{ xs: 1, sm: 2 }}
                  items={[
                    {
                      key: "saved",
                      label: t("maintenance.saved"),
                      children: display(observed.saved_accepting),
                    },
                    {
                      key: "runtime",
                      label: t("maintenance.runtime"),
                      children: display(observed.runtime_accepting),
                    },
                    {
                      key: "active",
                      label: t("maintenance.active"),
                      children:
                        observed.active_operations === null
                          ? t("maintenance.unknown")
                          : observed.active_operations === "0"
                            ? t("maintenance.zero")
                            : observed.active_operations,
                    },
                    {
                      key: "savedrev",
                      label: t("maintenance.savedRevision"),
                      children: observed.saved_revision,
                    },
                    {
                      key: "runtimeRev",
                      label: t("maintenance.runtimeRevision"),
                      children:
                        observed.applied_revision ?? t("maintenance.unknown"),
                    },
                    {
                      key: "durable",
                      label: t("maintenance.durableRevision"),
                      children:
                        observed.durable_applied_revision ??
                        t("maintenance.unknown"),
                    },
                  ]}
                />
              )}
              {actual?.fresh && !canTarget(actual) && (
                <Alert
                  type="warning"
                  showIcon
                  title={t(
                    peer === null
                      ? "maintenance.localControlled"
                      : "maintenance.remoteUnavailable",
                  )}
                />
              )}
              {actual?.fresh && !hasSequence(actual) && (
                <Alert
                  type="warning"
                  showIcon
                  title={t("maintenance.sequenceExhausted")}
                />
              )}
              {actual?.fresh &&
                !actual.status.saved_accepting &&
                !actual.resumable && (
                  <Alert
                    type="warning"
                    showIcon
                    title={t("runtime.resumeBlocked")}
                  />
                )}
              {own && actual?.fresh && peer !== null && (
                <>
                  {actual.job && (
                    <Typography.Text>
                      {t("maintenance.jobState")}:{" "}
                      {t(`control.job.${actual.job.state}`)}
                    </Typography.Text>
                  )}
                  {!intentJob && (
                    <Alert
                      type="warning"
                      showIcon
                      title={t("maintenance.receiptMismatch")}
                    />
                  )}
                  {pending(actual.job) && (
                    <Alert
                      type="warning"
                      showIcon
                      title={t("maintenance.receiptPending")}
                    />
                  )}
                </>
              )}
              {own ? (
                <Button
                  disabled={!reviewable}
                  loading={busy}
                  onClick={() => void acknowledge()}
                >
                  {t("maintenance.acknowledge")}
                </Button>
              ) : (
                <Button
                  danger={observed?.saved_accepting}
                  disabled={!writable}
                  onClick={() =>
                    actual &&
                    setConfirm({
                      view: actual,
                      accepting: !actual.status.saved_accepting,
                    })
                  }
                >
                  {t(
                    observed?.saved_accepting === false
                      ? "maintenance.resume"
                      : "maintenance.pause",
                  )}
                </Button>
              )}
              <Modal
                open={confirm !== null && confirm.view.binding === binding}
                title={t(
                  confirm?.accepting
                    ? "maintenance.resume"
                    : "maintenance.pause",
                )}
                okText={t("maintenance.confirm")}
                cancelText={t("maintenance.cancel")}
                confirmLoading={busy}
                okButtonProps={{
                  disabled: !writable || confirm?.view !== actual,
                }}
                onOk={() => void submit()}
                onCancel={() => {
                  setConfirm(null);
                  write.current?.abort();
                }}
                destroyOnHidden
              >
                <Typography.Paragraph>
                  {t("maintenance.confirmHint")}
                </Typography.Paragraph>
                {peer !== null && (
                  <Typography.Paragraph>
                    {t("maintenance.confirmRemote")}
                  </Typography.Paragraph>
                )}
                <Typography.Text className="managed-identifier">
                  {nodeId}
                </Typography.Text>
                {confirm && (
                  <Descriptions
                    column={1}
                    items={[
                      {
                        key: "revision",
                        label: t("maintenance.expectedRevision"),
                        children: confirm.view.status.saved_revision,
                      },
                      {
                        key: "epoch",
                        label: t("maintenance.expectedEpoch"),
                        children: confirm.view.status.ownership.epoch,
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
