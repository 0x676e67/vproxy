import {
  Alert,
  Button,
  Card,
  Collapse,
  Descriptions,
  Empty,
  Modal,
  Space,
  Spin,
  Typography,
} from "antd";
import { useEffect, useRef, useState } from "react";
import { ApiError, apiError } from "../../api/client";
import { connectionUrl, endpointChoices } from "../../api/endpoints";
import type { EndpointSelection } from "../../api/endpointSettings";
import { errorMessage } from "../../api/messages";
import { routingWritable } from "../../api/remoteRouting";
import { nextCommand } from "../../api/targets";
import { useManagement } from "../../auth/context";
import { useMessages, type MessageKey } from "../../hooks/useMessages";
import EndpointEditor from "./EndpointEditor";
import {
  effectiveEndpoints,
  readEndpointView,
  sameEndpointWriteView,
  type EndpointView,
} from "./endpointState";

interface ReadState {
  peer: string | null;
  nodeId: string | undefined;
  epoch: number;
  value: EndpointView | null;
  error: ApiError | null;
}

/** The selected node's persistent client declarations, not its listener
 * configuration. An uncertain write is only observed, never auto-submitted. */
export default function EndpointButton({
  peer,
  nodeId,
  disabled = false,
}: {
  peer: string | null;
  nodeId?: string;
  disabled?: boolean;
}) {
  const { t } = useMessages();
  const { controller, state } = useManagement();
  const epoch = controller.generation();
  const [open, setOpen] = useState(false);
  const [view, setView] = useState<ReadState | null>(null);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<{
    id: string;
    detached: boolean;
  } | null>(null);
  const [notice, setNotice] = useState<MessageKey | null>(null);
  const [blocked, setBlocked] = useState(false);
  const [unknown, setUnknown] = useState(false);
  const [reviewed, setReviewed] = useState(false);
  const [writing, setWriting] = useState(false);
  const pending = useRef<AbortController | null>(null);
  const mutation = useRef<AbortController | null>(null);
  const serial = useRef(0);
  const valid = (work: AbortController, id: number) =>
    !work.signal.aborted &&
    id === serial.current &&
    epoch === controller.generation();
  const current =
    view?.peer === peer && view.nodeId === nodeId && view.epoch === epoch
      ? view
      : null;
  const value = current?.value;
  const catalog = value?.catalog;
  const settings = value?.settings;
  const ticket = value?.context.job;
  const loading = open && current === null;

  const read = async (check = false, review = false) => {
    if (!state.session || state.busy || disabled || pending.current) return;
    const work = new AbortController();
    const id = ++serial.current;
    // An observation begun before the old mutation's caller settles cannot
    // authorize a new intent just because its response arrives later. Caller
    // cancellation still says nothing about the server's commit outcome.
    const reviewAfterWrite = review && mutation.current === null;
    pending.current = work;
    setBusy(true);
    setEditing(null);
    setReviewed(false);
    try {
      const result = await controller.resource(
        state.session,
        async (client, csrf, signal) => {
          if (
            check &&
            peer !== null &&
            ticket?.resource === "proxy_endpoints"
          ) {
            await client.refreshEndpointCommand(
              peer,
              ticket.job_id,
              csrf,
              signal,
            );
            if (signal.aborted) throw new DOMException("Aborted", "AbortError");
          }
          return readEndpointView(client, peer, nodeId, signal);
        },
        work.signal,
      );
      if (valid(work, id)) {
        setView({ peer, nodeId, epoch, value: result, error: null });
        setBlocked(false);
        setReviewed(reviewAfterWrite && mutation.current === null);
      }
    } catch (error) {
      if (valid(work, id))
        setView({
          peer,
          nodeId,
          epoch,
          value: value ?? null,
          error: apiError(error),
        });
    } finally {
      if (pending.current === work) {
        pending.current = null;
        setBusy(false);
      }
    }
  };
  useEffect(() => {
    setView(null);
    setBusy(false);
    setEditing(null);
    setNotice(null);
    setBlocked(false);
    setReviewed(false);
    if (open && state.phase === "authenticated" && !state.busy && !disabled)
      void read();
    return () => {
      // Cancellation cannot undo a dispatched mutation. Keep its uncertainty
      // when only the modal closes; a different session/node resets below.
      if (mutation.current && mutation.current === pending.current)
        setUnknown(true);
      serial.current++;
      pending.current?.abort();
      pending.current = null;
    };
    // Each read belongs to one modal/session/target scope, not every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    open,
    peer,
    nodeId,
    epoch,
    state.session,
    state.phase,
    state.busy,
    disabled,
  ]);
  useEffect(() => {
    setUnknown(false);
    setReviewed(false);
    setWriting(false);
    mutation.current = null;
    // A local modal guard is not a cross-session/node operation journal.
  }, [peer, nodeId, epoch, state.session]);
  useEffect(() => {
    if (state.phase !== "authenticated") setOpen(false);
  }, [state.phase]);
  const close = () => {
    if (mutation.current) setUnknown(true);
    setReviewed(false);
    serial.current++;
    pending.current?.abort();
    pending.current = null;
    setOpen(false);
    setView(null);
    setBusy(false);
    setEditing(null);
  };
  const save = async (selection: EndpointSelection) => {
    if (
      !state.session ||
      state.busy ||
      pending.current ||
      mutation.current ||
      !value?.settings ||
      !editing ||
      blocked ||
      unknown ||
      metadataPending ||
      !routingWritable(value.context)
    )
      return;
    const work = new AbortController();
    const id = ++serial.current;
    const before = value;
    const listenerId = editing.id;
    const detached = editing.detached;
    pending.current = work;
    setBusy(true);
    setNotice(null);
    let dispatched = false;
    try {
      const result = await controller.resource(
        state.session,
        async (client, csrf, signal) => {
          const fresh = await readEndpointView(client, peer, nodeId, signal);
          sameEndpointWriteView(before, fresh);
          if (signal.aborted) throw new DOMException("Aborted", "AbortError");
          const previous = before.settings!;
          const collection = detached ? previous.detached : previous.listeners;
          if (
            !collection.some((entry) => entry.id === listenerId) ||
            (detached && selection.mode !== "inherit")
          )
            throw new ApiError("format");
          // Validate finite counters before dispatch; a local validation error
          // must not be presented as a possibly committed network operation.
          nextCommand(previous.revision);
          if (peer === null) {
            dispatched = true;
            mutation.current = work;
            setWriting(true);
            const saved = await client.setEndpointSelection(
              listenerId,
              selection,
              previous.revision,
              previous.generation,
              csrf,
              signal,
            );
            if (saved.node_id !== previous.node_id)
              throw new ApiError("format");
            const changed = saved.listeners.find(
              (entry) => entry.id === listenerId,
            );
            if (
              detached
                ? !!changed ||
                  saved.detached.some((entry) => entry.id === listenerId)
                : !changed ||
                  changed.selection.mode !== selection.mode ||
                  (selection.mode === "custom" &&
                    (changed.selection.mode !== "custom" ||
                      changed.selection.public_address !==
                        selection.public_address))
            )
              throw new ApiError("format");
            return { settings: saved, submission: null };
          }
          if (fresh.context.scope.kind !== "target")
            throw new ApiError("format");
          const scope = fresh.context.scope;
          const commandId = nextCommand(scope.policy.last_terminal_command);
          dispatched = true;
          mutation.current = work;
          setWriting(true);
          return {
            settings: null,
            submission: await client.targetEndpointCommand(
              peer,
              {
                expected_target_revision: scope.target.revision,
                controller_epoch: scope.policy.controller_epoch,
                command_id: commandId,
                expected_metadata_revision: previous.revision,
                mutation: {
                  listener_id: listenerId,
                  generation: previous.generation,
                  selection,
                },
              },
              csrf,
              signal,
            ),
          };
        },
        work.signal,
      );
      if (!valid(work, id)) return;
      setEditing(null);
      if (result.settings) {
        setView({
          peer,
          nodeId,
          epoch,
          error: null,
          value: {
            ...before,
            settings: result.settings,
            catalog: effectiveEndpoints(result.settings),
          },
        });
        setNotice("connections.declarationSaved");
      } else if (result.submission) {
        const saved = result.submission.job;
        setView({
          peer,
          nodeId,
          epoch,
          error: null,
          value: { ...before, context: { ...before.context, job: saved } },
        });
        setBlocked(true);
        setNotice(
          saved.state === "saved"
            ? "connections.remoteSaved"
            : saved.state === "rejected"
              ? "connections.declarationRejected"
              : "connections.declarationQueued",
        );
      }
    } catch (error) {
      if (valid(work, id)) {
        const failure = apiError(error);
        setView({ peer, nodeId, epoch, value: before, error: failure });
        setBlocked(true);
        // Known 4xx rejections differ from a network/format/server uncertainty.
        if (
          dispatched &&
          !(
            failure.kind === "server" &&
            failure.status !== undefined &&
            failure.status >= 400 &&
            failure.status < 500
          )
        )
          setUnknown(true);
      }
    } finally {
      if (mutation.current === work) {
        mutation.current = null;
        setWriting(false);
      }
      if (pending.current === work) {
        pending.current = null;
        setBusy(false);
      }
    }
  };
  const metadataPending =
    ticket?.resource === "proxy_endpoints" &&
    (ticket.state === "pending" ||
      ticket.state === "blocked" ||
      (ticket.state === "saved" &&
        (!settings ||
          ticket.metadata_revision === null ||
          BigInt(settings.revision) < BigInt(ticket.metadata_revision))));
  const editable =
    !!settings &&
    routingWritable(value?.context ?? null) &&
    !busy &&
    !writing &&
    !blocked &&
    !unknown &&
    !metadataPending;
  const canCopy =
    !busy &&
    !writing &&
    !blocked &&
    !metadataPending &&
    !unknown &&
    !loading &&
    !current?.error &&
    !disabled &&
    !state.busy;
  const canBeginNew =
    unknown &&
    reviewed &&
    !busy &&
    !writing &&
    !pending.current &&
    !mutation.current &&
    !blocked &&
    !metadataPending &&
    !current?.error &&
    !disabled &&
    !state.busy &&
    !!settings &&
    routingWritable(value?.context ?? null);
  const entry =
    editing && settings?.listeners.find((item) => item.id === editing.id);
  const detachedEntry =
    editing && settings?.detached.find((item) => item.id === editing.id);
  const feedback = (
    <>
      {current?.error && (
        <Alert type="error" showIcon title={t(errorMessage(current.error))} />
      )}
      {notice && (
        <Alert
          type={
            notice === "connections.declarationRejected" ? "warning" : "info"
          }
          showIcon
          title={t(notice)}
        />
      )}
      {unknown && (
        <Alert type="warning" showIcon title={t("connections.writeUnknown")} />
      )}
    </>
  );
  return (
    <>
      <Button
        size="small"
        disabled={disabled || state.busy || state.phase !== "authenticated"}
        onClick={() => setOpen(true)}
      >
        {t("connections.open")}
      </Button>
      {open && state.phase === "authenticated" && (
        <Modal
          open
          title={t("connections.open")}
          width={760}
          onCancel={close}
          destroyOnHidden
          style={{ top: 16, margin: "0 auto", maxWidth: "calc(100% - 32px)" }}
          classNames={{
            container: "connection-modal-container",
            body: "connection-modal-body",
          }}
          footer={<Button onClick={close}>{t("connections.close")}</Button>}
        >
          <Space orientation="vertical" size={16} className="full-width">
            <Space wrap className="connection-form-actions">
              <Button
                loading={busy}
                disabled={busy || loading || disabled || state.busy}
                onClick={() => void read(false, true)}
              >
                {t("connections.readLatest")}
              </Button>
              {ticket?.resource === "proxy_endpoints" && peer !== null && (
                <Button
                  disabled={busy || disabled || state.busy}
                  onClick={() => void read(true, true)}
                >
                  {t("connections.checkDeclaration")}
                </Button>
              )}
              {unknown && (
                <Button
                  disabled={!canBeginNew}
                  onClick={() => {
                    if (
                      !canBeginNew ||
                      pending.current ||
                      mutation.current ||
                      controller.generation() !== epoch
                    )
                      return;
                    // Explicitly begin a new intent from the reviewed snapshot;
                    // neither replay nor claim completion of the previous one.
                    setUnknown(false);
                    setReviewed(false);
                    setEditing(null);
                    setNotice("connections.newDeclarationNotice");
                  }}
                >
                  {t("connections.beginNewDeclaration")}
                </Button>
              )}
            </Space>
            {loading && (
              <div role="status">
                <Spin /> {t("connections.reading")}
              </div>
            )}
            {editing && !editing.detached && entry ? (
              <EndpointEditor
                key={
                  settings!.revision +
                  ":" +
                  settings!.generation +
                  ":" +
                  entry.id
                }
                entry={entry}
                busy={busy}
                blocked={
                  blocked || unknown || !routingWritable(value?.context ?? null)
                }
                notice={feedback}
                cancel={() => setEditing(null)}
                submit={save}
              />
            ) : editing?.detached && detachedEntry ? (
              <>
                {feedback}
                <Alert
                  type="warning"
                  showIcon
                  title={t("connections.clearDetachedHint")}
                  description={
                    <Typography.Text code className="managed-identifier">
                      {detachedEntry.protocol.toUpperCase()} —{" "}
                      {detachedEntry.bind}
                    </Typography.Text>
                  }
                />
                <Space wrap className="connection-form-actions">
                  <Button disabled={busy} onClick={() => setEditing(null)}>
                    {t("users.cancel")}
                  </Button>
                  <Button
                    danger
                    loading={busy}
                    disabled={
                      blocked ||
                      unknown ||
                      !routingWritable(value?.context ?? null)
                    }
                    onClick={() => void save({ mode: "inherit" })}
                  >
                    {t("connections.clearDetached")}
                  </Button>
                </Space>
              </>
            ) : (
              <>
                {feedback}
                {catalog && (
                  <>
                    <Descriptions
                      column={1}
                      size="small"
                      items={[
                        {
                          key: "node",
                          label: t("control.nodeId"),
                          children: (
                            <Typography.Text
                              code
                              className="managed-identifier"
                            >
                              {catalog.node_id}
                            </Typography.Text>
                          ),
                        },
                        {
                          key: "running",
                          label: t("connections.observedState"),
                          children: t(
                            catalog.proxy_running
                              ? "connections.running"
                              : "connections.stopped",
                          ),
                        },
                        ...(settings
                          ? [
                              {
                                key: "revision",
                                label: t("connections.metadataRevision"),
                                children: settings.revision,
                              },
                            ]
                          : []),
                      ]}
                    />
                    <Alert
                      type="info"
                      showIcon
                      title={t("connections.connectivityNotTested")}
                    />
                    {!settings && (
                      <Alert
                        type="info"
                        showIcon
                        title={t("connections.managementUnsupported")}
                      />
                    )}
                    {settings && !routingWritable(value?.context ?? null) && (
                      <Alert
                        type="warning"
                        showIcon
                        title={t(
                          ticket?.state === "pending" ||
                            ticket?.state === "blocked"
                            ? "connections.otherCommand"
                            : "control.denied",
                        )}
                      />
                    )}
                    {ticket?.resource === "proxy_endpoints" && (
                      <Alert
                        type="info"
                        title={t("connections.metadataTicket")}
                        description={
                          <Space orientation="vertical">
                            <Typography.Text>
                              {t(
                                ticket.state === "saved"
                                  ? "connections.metadataSaved"
                                  : `control.job.${ticket.state}`,
                              )}
                            </Typography.Text>
                            <Typography.Text
                              code
                              className="managed-identifier"
                            >
                              {ticket.job_id}
                            </Typography.Text>
                          </Space>
                        }
                      />
                    )}
                    {ticket?.resource === "proxy_endpoints" &&
                      ticket.state === "blocked" && (
                        <Alert
                          type="warning"
                          title={t("connections.blockedTicket")}
                        />
                      )}
                    {!catalog.listeners.length && (
                      <Empty description={t("connections.noListeners")} />
                    )}
                    {catalog.listeners.map((listener, index) => {
                      const setting = settings?.listeners[index];
                      const choices = endpointChoices({
                        ...catalog,
                        listeners: [listener],
                      });
                      return (
                        <Card
                          key={setting?.id ?? index + ":" + listener.protocol}
                          size="small"
                          title={listener.protocol.toUpperCase()}
                          extra={
                            setting && (
                              <Button
                                size="small"
                                disabled={!editable}
                                onClick={() =>
                                  setEditing({
                                    id: setting.id,
                                    detached: false,
                                  })
                                }
                              >
                                {t("connections.editAddress")}
                              </Button>
                            )
                          }
                        >
                          <Space
                            orientation="vertical"
                            size={12}
                            className="full-width"
                          >
                            <Descriptions
                              column={1}
                              size="small"
                              items={[
                                {
                                  key: "bind",
                                  label: t("connections.bind"),
                                  children: (
                                    <Typography.Text
                                      code
                                      className="managed-identifier"
                                    >
                                      {listener.bind}
                                    </Typography.Text>
                                  ),
                                },
                                {
                                  key: "public",
                                  label: t("connections.publicAddress"),
                                  children:
                                    listener.public_address === null ? (
                                      t("connections.notPublished")
                                    ) : (
                                      <Typography.Text
                                        code
                                        className="managed-identifier"
                                      >
                                        {listener.public_address}
                                      </Typography.Text>
                                    ),
                                },
                                ...(setting
                                  ? [
                                      {
                                        key: "selection",
                                        label: t("connections.selectionMode"),
                                        children: t(
                                          `connections.mode.${setting.selection.mode}`,
                                        ),
                                      },
                                    ]
                                  : []),
                              ]}
                            />
                            {choices.map((choice) => (
                              <Space
                                key={choice.key}
                                orientation="vertical"
                                size={4}
                                className="full-width"
                              >
                                <Typography.Text strong>
                                  {choice.protocol.toUpperCase()}
                                </Typography.Text>
                                <Typography.Text
                                  code
                                  copyable={canCopy}
                                  className="managed-identifier"
                                >
                                  {connectionUrl(choice)}
                                </Typography.Text>
                                {choice.protocol === "masque" && (
                                  <Typography.Text type="secondary">
                                    {t("connections.masqueAuth")}
                                  </Typography.Text>
                                )}
                              </Space>
                            ))}
                          </Space>
                        </Card>
                      );
                    })}
                    {!!settings?.detached.length && (
                      <Collapse
                        items={[
                          {
                            key: "detached",
                            label:
                              t("connections.detached") +
                              " (" +
                              settings.detached.length +
                              ")",
                            children: (
                              <Space
                                orientation="vertical"
                                className="full-width"
                              >
                                <Typography.Paragraph>
                                  {t("connections.detachedHint")}
                                </Typography.Paragraph>
                                {settings.detached.map((item) => (
                                  <Card
                                    key={item.id}
                                    size="small"
                                    title={item.protocol.toUpperCase()}
                                  >
                                    <Space
                                      orientation="vertical"
                                      className="full-width"
                                    >
                                      <Typography.Text
                                        code
                                        className="managed-identifier"
                                      >
                                        {item.bind}
                                      </Typography.Text>
                                      <Typography.Text>
                                        {t(
                                          `connections.mode.${item.selection.mode}`,
                                        )}
                                      </Typography.Text>
                                      {item.selection.mode === "custom" && (
                                        <Typography.Text
                                          code
                                          className="managed-identifier"
                                        >
                                          {item.selection.public_address}
                                        </Typography.Text>
                                      )}
                                      <Button
                                        danger
                                        disabled={!editable}
                                        onClick={() =>
                                          setEditing({
                                            id: item.id,
                                            detached: true,
                                          })
                                        }
                                      >
                                        {t("connections.clearDetached")}
                                      </Button>
                                    </Space>
                                  </Card>
                                ))}
                              </Space>
                            ),
                          },
                        ]}
                      />
                    )}
                    <Collapse
                      items={[
                        {
                          key: "details",
                          label: t("connections.endpointDetails"),
                          children: (
                            <Space
                              orientation="vertical"
                              className="full-width"
                            >
                              {settings && (
                                <Typography.Paragraph>
                                  {t("connections.metadataOnlyHint")}
                                </Typography.Paragraph>
                              )}
                              <Typography.Paragraph>
                                {t("connections.endpointHint")}
                              </Typography.Paragraph>
                              <Typography.Paragraph>
                                {t("connections.runningHint")}
                              </Typography.Paragraph>
                              <Typography.Paragraph>
                                {t("connections.configuredHint")}
                              </Typography.Paragraph>
                              <Typography.Paragraph>
                                {t("connections.unconfiguredHint")}
                              </Typography.Paragraph>
                            </Space>
                          ),
                        },
                      ]}
                    />
                    <Alert
                      type="info"
                      showIcon
                      title={t("connections.withoutCredentials")}
                      description={t("connections.credentialHint")}
                    />
                  </>
                )}
              </>
            )}
          </Space>
        </Modal>
      )}
    </>
  );
}
