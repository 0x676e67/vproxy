import {
  Alert,
  Button,
  Card,
  Checkbox,
  Descriptions,
  Form,
  Input,
  Modal,
  Space,
  Switch,
  Tag,
  Typography,
} from "antd";
import { useEffect, useRef, useState } from "react";
import { ApiError, apiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import {
  webhookChange,
  type WebhookChange,
  type WebhookView,
} from "../../api/notifications";
import { drainNonce } from "../../api/runtime";
import { useManagement } from "../../auth/context";
import {
  browserJournal,
  type JournalEntry,
  type JournalLease,
} from "../../auth/review-journal";
import {
  webhookCodec,
  webhookResult,
  type WebhookNote,
} from "../../auth/webhook-review";
import { useMessages } from "../../hooks/useMessages";

interface Fields {
  enabled: boolean;
  automatic_retry: boolean;
  url: string;
  bearer: string;
  clear_bearer: boolean;
  discard_pending: boolean;
}
const fields = (view: WebhookView): Fields => ({
  enabled: view.enabled,
  automatic_retry: view.automatic_retry,
  url: "",
  bearer: "",
  clear_bearer: false,
  discard_pending: false,
});

/** Local settings are deliberately outside target control. Browser notes retain
 * assertions for unknown writes, never destination capabilities or tokens. */
export default function WebhookSettings() {
  const { t } = useMessages(),
    { controller, state } = useManagement();
  const [form] = Form.useForm<Fields>();
  const discard = Form.useWatch("discard_pending", form);
  const [journal] = useState(() =>
    browserJournal("notifications", webhookCodec),
  );
  const [notes, setNotes] = useState<readonly JournalEntry<WebhookNote>[]>([]);
  const [value, setValue] = useState<WebhookView | null>(null);
  const [failure, setFailure] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false),
    [fresh, setFresh] = useState(false);
  const [issue, setIssue] = useState(false);
  const [confirm, setConfirm] = useState<
    "save" | "forget" | "retry" | "review" | null
  >(null);
  const pending = useRef<AbortController | null>(null),
    mounted = useRef(false);
  const reviewing = useRef<JournalEntry<WebhookNote> | null>(null);
  const lastRevision = useRef<string | null>(null);
  const identity = useRef({
    session: state.session,
    epoch: controller.generation(),
  });
  identity.current = { session: state.session, epoch: controller.generation() };
  const reloadNotes = () => {
    setNotes(journal.load());
    setIssue(journal.issue() !== null);
  };
  const session = state.session;
  const review =
    value && session
      ? notes.find(
          (row) =>
            row.value.nodeId === value.node_id &&
            row.value.administratorId === session.administrator.id,
        )
      : undefined;
  const disabled = busy || state.busy || !session || !value || !fresh || issue;

  const read = async () => {
    const expected = controller.snapshot().session,
      epoch = controller.generation();
    if (!expected || controller.snapshot().busy || pending.current) return;
    const request = new AbortController();
    pending.current = request;
    setBusy(true);
    setFresh(false);
    setFailure(null);
    try {
      const next = await controller.resource(
        expected,
        async (client, _, signal) => {
          const node = await client.node(signal);
          return client.webhook(node.node_id, signal);
        },
        request.signal,
      );
      if (
        !mounted.current ||
        request.signal.aborted ||
        identity.current.session !== expected ||
        identity.current.epoch !== epoch
      )
        return;
      if (lastRevision.current !== `${next.node_id}:${next.revision}`) {
        form.setFieldsValue(fields(next));
        lastRevision.current = `${next.node_id}:${next.revision}`;
      }
      setValue(next);
      setFresh(true);
      reloadNotes();
    } catch (error) {
      if (
        mounted.current &&
        !request.signal.aborted &&
        identity.current.session === expected &&
        identity.current.epoch === epoch
      )
        setFailure(apiError(error));
    } finally {
      if (pending.current === request) {
        pending.current = null;
        if (mounted.current) setBusy(false);
      }
    }
  };
  useEffect(() => {
    mounted.current = true;
    const detach = journal.subscribe(reloadNotes);
    reloadNotes();
    return () => {
      mounted.current = false;
      pending.current?.abort();
      detach();
    };
  }, [journal]);
  useEffect(() => {
    pending.current?.abort();
    pending.current = null;
    setValue(null);
    setFresh(false);
    setConfirm(null);
    lastRevision.current = null;
    form.resetFields();
    void read();
    return () => {
      pending.current?.abort();
    };
  }, [session, controller.generation()]);

  const submit = async () => {
    const action = confirm,
      snapshot = value,
      expected = session,
      epoch = controller.generation();
    if (!action || !snapshot || !expected || disabled) return;
    const current = () =>
      mounted.current &&
      identity.current.session === expected &&
      identity.current.epoch === epoch;
    if (action === "review") {
      const entry = reviewing.current;
      if (
        entry &&
        entry.id === review?.id &&
        (await journal.clear(entry.key, entry.id, current)) &&
        current()
      ) {
        setConfirm(null);
        reviewing.current = null;
        reloadNotes();
      }
      return;
    }
    if (review) return;
    const request = new AbortController();
    pending.current = request;
    const belongs = () => current() && !request.signal.aborted;
    let lease: JournalLease<WebhookNote> | null = null,
      admitted = false;
    setBusy(true);
    setFailure(null);
    try {
      const input = form.getFieldsValue(),
        operation = drainNonce();
      const payload: WebhookChange | null =
        action === "retry"
          ? null
          : webhookChange({
              expected_node_id: snapshot.node_id,
              expected_revision: snapshot.revision,
              operation_id: operation,
              enabled: action === "forget" ? false : !!input.enabled,
              automatic_retry:
                action === "forget" ? false : !!input.automatic_retry,
              url: action === "forget" || !input.url ? null : input.url,
              bearer:
                action === "forget" || !input.bearer ? null : input.bearer,
              clear_bearer: action === "forget" ? false : !!input.clear_bearer,
              clear_destination: action === "forget",
              discard_pending: !!input.discard_pending,
            });
      const note: WebhookNote = {
        administratorId: expected.administrator.id,
        nodeId: snapshot.node_id,
        operationId: operation,
        revision: snapshot.revision,
        action: action === "retry" ? "retry" : "configure",
        deliveryId: action === "retry" ? (snapshot.pending?.id ?? null) : null,
        attempts:
          action === "retry" ? (snapshot.pending?.attempts ?? null) : null,
      };
      if (payload?.enabled && !payload.url && !snapshot.configured)
        throw new ApiError("format");
      lease = await journal.acquire(note, belongs);
      if (!lease || !belongs()) {
        if (belongs()) setIssue(true);
        return;
      }
      const next = await controller.resource(
        expected,
        async (client, csrf, signal) => {
          admitted = true;
          // Inputs are never retained to replay a lost write. Only the non-secret
          // note survives reload; a fresh read resolves the original operation.
          form.setFieldsValue({ url: "", bearer: "" });
          return payload
            ? client.configureWebhook(payload, csrf, signal)
            : client.retryWebhook(
                {
                  expected_node_id: snapshot.node_id,
                  expected_revision: snapshot.revision,
                  delivery_id: snapshot.pending?.id ?? "",
                  expected_attempts: snapshot.pending?.attempts ?? 0,
                },
                csrf,
                signal,
              );
        },
        request.signal,
      );
      if (!belongs()) return;
      if (!lease.remove()) setIssue(true);
      setValue(next);
      setFresh(true);
      form.setFieldsValue(fields(next));
      lastRevision.current = `${next.node_id}:${next.revision}`;
    } catch (error) {
      const problem = apiError(error);
      if (belongs()) {
        if (!admitted) {
          // Local preflight made no request and cannot stale the saved view.
          // Keep the fields editable so a mistyped URL needs no refresh cycle.
          setFailure(new ApiError("server", "invalid_webhook", 400));
        } else {
          // These fixed rejections occur before the store mutates this request.
          // 5xx/network/invalid success stay unknown and cannot trigger a replay.
          if (
            problem.kind === "server" &&
            [400, 403, 409].includes(problem.status ?? 0)
          )
            lease?.remove();
          setFailure(problem);
          setFresh(false);
        }
      }
    } finally {
      if (!admitted) lease?.remove();
      lease?.release();
      if (pending.current === request) {
        pending.current = null;
        if (mounted.current) {
          setBusy(false);
          setConfirm(null);
          reloadNotes();
        }
      }
    }
  };
  const delivery = value?.pending;
  return (
    <Card title={t("notifications.title")}>
      <Space orientation="vertical" size={16} className="full-width">
        <Typography.Paragraph>
          {t("notifications.description")}
        </Typography.Paragraph>
        <Button
          onClick={() => void read()}
          disabled={busy || state.busy || !session}
          loading={busy}
        >
          {t("notifications.refresh")}
        </Button>
        {failure && (
          <Alert type="error" showIcon title={t(errorMessage(failure))} />
        )}
        {issue && (
          <Alert
            type="warning"
            showIcon
            title={t("notifications.notesUnavailable")}
          />
        )}
        {value && (
          <>
            <Descriptions
              size="small"
              column={1}
              items={[
                {
                  key: "enabled",
                  label: t("notifications.savedState"),
                  children: (
                    <Tag>
                      {t(
                        value.enabled
                          ? "notifications.enabled"
                          : "notifications.disabled",
                      )}
                    </Tag>
                  ),
                },
                {
                  key: "destination",
                  label: t("notifications.destination"),
                  children: t(
                    value.configured
                      ? "notifications.configured"
                      : "notifications.notConfigured",
                  ),
                },
                {
                  key: "token",
                  label: t("notifications.token"),
                  children: t(
                    value.has_bearer
                      ? "notifications.configured"
                      : "notifications.notConfigured",
                  ),
                },
                {
                  key: "cursor",
                  label: t("notifications.cursor"),
                  children: value.cursor,
                },
                {
                  key: "skipped",
                  label: t("notifications.skipped"),
                  children: value.skipped_through,
                },
                {
                  key: "accepted",
                  label: t("notifications.lastAccepted"),
                  children:
                    value.last_accepted_delivery_id ?? t("notifications.none"),
                },
                {
                  key: "discarded",
                  label: t("notifications.discarded"),
                  children:
                    value.discarded_delivery_id ?? t("notifications.none"),
                },
              ]}
            />
            {delivery && (
              <Alert
                showIcon
                type={
                  delivery.outcome === "ready" || delivery.outcome === "sending"
                    ? "info"
                    : "warning"
                }
                title={t(`notifications.outcome.${delivery.outcome}`)}
                description={
                  <Space orientation="vertical" size={4}>
                    <Typography.Text code>{delivery.id}</Typography.Text>
                    <Typography.Text>
                      {t("notifications.attempts", {
                        count: delivery.attempts,
                      })}
                      {delivery.http_status
                        ? ` · HTTP ${delivery.http_status}`
                        : ""}
                    </Typography.Text>
                    {delivery.automatic_retry_eligible && (
                      <Typography.Text>
                        {t("notifications.autoEligible")}
                      </Typography.Text>
                    )}
                    <Typography.Text>
                      {t("notifications.refreshDelivery")}
                    </Typography.Text>
                  </Space>
                }
              />
            )}
            {review && (
              <Alert
                type="warning"
                showIcon
                title={t("notifications.reviewRequired")}
                description={
                  <Space orientation="vertical">
                    <Typography.Text>
                      {t(
                        `notifications.result.${webhookResult(review.value, value)}`,
                      )}
                    </Typography.Text>
                    <Typography.Text code>
                      {review.value.operationId}
                    </Typography.Text>
                    <Button
                      onClick={() => {
                        reviewing.current = review;
                        setConfirm("review");
                      }}
                      disabled={disabled}
                    >
                      {t("notifications.finishReview")}
                    </Button>
                  </Space>
                }
              />
            )}
            <Form
              form={form}
              layout="vertical"
              disabled={disabled || !!review}
              onFinish={() => setConfirm("save")}
            >
              <Form.Item
                name="enabled"
                label={t("notifications.enable")}
                valuePropName="checked"
              >
                <Switch />
              </Form.Item>
              <Form.Item
                name="url"
                label={t("notifications.url")}
                extra={t("notifications.urlHint")}
              >
                <Input.Password
                  autoComplete="off"
                  maxLength={2048}
                  placeholder={
                    value.configured ? t("notifications.keep") : "https://"
                  }
                />
              </Form.Item>
              <Form.Item
                name="bearer"
                label={t("notifications.token")}
                extra={t("notifications.tokenHint")}
              >
                <Input.Password
                  autoComplete="new-password"
                  maxLength={1024}
                  placeholder={value.has_bearer ? t("notifications.keep") : ""}
                />
              </Form.Item>
              <Form.Item name="clear_bearer" valuePropName="checked">
                <Checkbox>{t("notifications.clearToken")}</Checkbox>
              </Form.Item>
              <Form.Item
                name="automatic_retry"
                valuePropName="checked"
                extra={t("notifications.autoHint")}
              >
                <Checkbox>{t("notifications.auto")}</Checkbox>
              </Form.Item>
              {delivery && (
                <Form.Item name="discard_pending" valuePropName="checked">
                  <Checkbox>{t("notifications.discardHint")}</Checkbox>
                </Form.Item>
              )}
              <Space wrap>
                <Button
                  type="primary"
                  htmlType="submit"
                  disabled={disabled || !!review || (!!delivery && !discard)}
                >
                  {t("notifications.save")}
                </Button>
                <Button
                  danger
                  onClick={() => setConfirm("forget")}
                  disabled={
                    disabled ||
                    !!review ||
                    !value.configured ||
                    (!!delivery && !discard)
                  }
                >
                  {t("notifications.forget")}
                </Button>
                {delivery &&
                  [
                    "unknown",
                    "rejected",
                    "deferred",
                    "destination_blocked",
                  ].includes(delivery.outcome) && (
                    <Button
                      onClick={() => setConfirm("retry")}
                      disabled={
                        disabled ||
                        !!review ||
                        delivery.attempts === 4_294_967_295
                      }
                    >
                      {t("notifications.retry")}
                    </Button>
                  )}
              </Space>
            </Form>
          </>
        )}
        <Modal
          open={confirm !== null}
          title={t(
            confirm === "retry"
              ? "notifications.retry"
              : confirm === "forget"
                ? "notifications.forget"
                : confirm === "review"
                  ? "notifications.finishReview"
                  : "notifications.save",
          )}
          okText={t("notifications.confirm")}
          cancelText={t("notifications.cancel")}
          onCancel={() => setConfirm(null)}
          onOk={() => void submit()}
          confirmLoading={busy}
          okButtonProps={{
            disabled: disabled || (confirm !== "review" && !!review),
          }}
        >
          <Typography.Paragraph>
            {t(
              confirm === "retry"
                ? "notifications.retryWarning"
                : confirm === "forget"
                  ? "notifications.forgetWarning"
                  : confirm === "review"
                    ? "notifications.reviewWarning"
                    : "notifications.saveWarning",
            )}
          </Typography.Paragraph>
        </Modal>
      </Space>
    </Card>
  );
}
