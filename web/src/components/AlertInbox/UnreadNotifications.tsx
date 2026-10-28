import { Alert, Button, Empty, Space, Tag, Typography } from "antd";
import { Link } from "@umijs/max";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import type {
  AlertEpisode,
  UnreadAlertOptions,
  UnreadAlertPage,
} from "../../api/alertEvents";
import { alertCodes, type AlertCode } from "../../api/alerts";
import { ApiError, apiError, type ManagementClient } from "../../api/client";
import { errorMessage } from "../../api/messages";
import { useManagement } from "../../auth/context";
import { useMessages, type MessageKey } from "../../hooks/useMessages";
import { alertHistoryHref } from "../../routing/scope";
import { recordedTime } from "../../pages/Alerts/EpisodeReview";

/** One local inbox. Reads never acknowledge; a bulk action uses bounded,
 * exact-transition batches and the same durable unknown-result fences as the
 * history page. New transitions after the displayed watermark stay unread. */
export default function UnreadNotifications({
  onNavigate,
}: {
  onNavigate: () => void;
}) {
  const { controller, state } = useManagement(),
    { t, intl } = useMessages();
  const session = state.session,
    epoch = controller.generation();
  const reviews = controller.alertAcknowledgements;
  const notes = useSyncExternalStore(reviews.subscribe, reviews.snapshot);
  const mounted = useRef(false),
    pending = useRef<AbortController | null>(null);
  const [page, setPage] = useState<UnreadAlertPage | null>(null);
  const [busy, setBusy] = useState(false),
    [writing, setWriting] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const belongs = () =>
    mounted.current &&
    controller.generation() === epoch &&
    controller.snapshot().session === session;
  const retained = notes.filter(
    (note) =>
      note.intent.administratorId === session?.administrator.id &&
      note.intent.nodeId === page?.node_id,
  );
  const disabled = busy || state.busy || !session;
  const readWith = async (
    client: ManagementClient,
    signal: AbortSignal,
    options: UnreadAlertOptions = {},
  ) => {
    const node = page?.node_id ?? (await client.node(signal)).node_id;
    return client.unreadAlerts(node, options, signal);
  };
  const read = async (options: UnreadAlertOptions = {}) => {
    if (!session || pending.current || !belongs()) return;
    const request = new AbortController();
    pending.current = request;
    setBusy(true);
    setError(null);
    setProgress(null);
    try {
      const result = await controller.resource(
        session,
        (client, _csrf, signal) => readWith(client, signal, options),
        request.signal,
      );
      if (belongs() && !request.signal.aborted) setPage(result);
    } catch (failure) {
      if (belongs() && !request.signal.aborted) setError(apiError(failure));
    } finally {
      if (pending.current === request) pending.current = null;
      if (belongs()) setBusy(false);
    }
  };
  useEffect(() => {
    mounted.current = true;
    void read();
    return () => {
      mounted.current = false;
      pending.current?.abort();
      pending.current = null;
    };
  }, [controller, epoch, session]);

  const mark = async (single?: AlertEpisode) => {
    if (disabled || pending.current || !session || !page || !belongs()) return;
    const request = new AbortController(),
      original = page;
    const valid = () => belongs() && !request.signal.aborted;
    pending.current = request;
    setBusy(true);
    setWriting(true);
    setError(null);
    setProgress(0);
    let completed = 0;
    try {
      let batch = single
        ? { ...original, items: [single], next_cursor: null }
        : await controller.resource(
            session,
            (client, _csrf, signal) =>
              client.unreadAlerts(
                original.node_id,
                { through: original.through_sequence },
                signal,
              ),
            request.signal,
          );
      // The retained store has at most 16,384 episodes. A fixed watermark and
      // strictly decreasing cursor prevent an endless "mark arriving events" loop.
      for (let round = 0; round < 512; round++) {
        if (!valid()) return;
        const tokens: object[] = [];
        let admitted = false,
          accepted = false,
          rejected = false;
        const interrupted = () => {
          if (admitted) tokens.forEach((token) => reviews.unknown(token));
        };
        request.signal.addEventListener("abort", interrupted, { once: true });
        try {
          for (const row of batch.items) {
            const token = await reviews.begin(
              {
                administratorId: session.administrator.id,
                nodeId: row.node_id,
                episodeId: row.id,
                transitionSequence: row.latest_transition_sequence,
              },
              valid,
            );
            if (!token)
              throw new ApiError("server", "alert_history_capacity", 503);
            tokens.push(token);
          }
          if (!valid()) return;
          if (batch.items.length) {
            await controller.resource(
              session,
              async (client, csrf, signal) => {
                admitted = true;
                signal.addEventListener("abort", interrupted, { once: true });
                try {
                  return await client.acknowledgeAlertBatch(
                    {
                      expected_node_id: original.node_id,
                      items: batch.items.map((row) => ({
                        episode_id: row.id,
                        expected_transition_sequence:
                          row.latest_transition_sequence,
                      })),
                    },
                    csrf,
                    signal,
                  );
                } finally {
                  signal.removeEventListener("abort", interrupted);
                }
              },
              request.signal,
            );
            accepted = valid();
            if (!accepted) return;
            completed += batch.items.length;
            setProgress(completed);
          }
        } catch (failure) {
          const problem = apiError(failure);
          rejected =
            problem.status === 409 && problem.code === "alert_history_conflict";
          throw failure;
        } finally {
          request.signal.removeEventListener("abort", interrupted);
          for (const token of tokens) {
            if (accepted || rejected || !admitted) reviews.complete(token);
            else reviews.unknown(token);
            reviews.release(token);
          }
        }
        if (!batch.next_cursor) break;
        if (round === 511) throw new ApiError("format");
        const before = batch.next_cursor;
        batch = await controller.resource(
          session,
          (client, _csrf, signal) =>
            client.unreadAlerts(
              original.node_id,
              { through: original.through_sequence, before },
              signal,
            ),
          request.signal,
        );
      }
      if (valid()) {
        const fresh = await controller.resource(
          session,
          (client, _csrf, signal) =>
            client.unreadAlerts(original.node_id, {}, signal),
          request.signal,
        );
        if (valid()) setPage(fresh);
      }
    } catch (failure) {
      if (valid()) setError(apiError(failure));
    } finally {
      if (pending.current === request) pending.current = null;
      if (belongs()) {
        setBusy(false);
        setWriting(false);
      }
    }
  };
  return (
    <Space orientation="vertical" size={16} className="full-width">
      <div className="notification-toolbar">
        <Button
          onClick={() => void read()}
          disabled={disabled}
          loading={busy && !writing}
        >
          {t("users.refresh")}
        </Button>
        <Button
          type="primary"
          disabled={disabled || !page?.items.length || retained.length > 0}
          loading={writing}
          onClick={() => void mark()}
        >
          {t("inbox.markAll")}
        </Button>
      </div>
      <Typography.Text type="secondary">{t("inbox.readHint")}</Typography.Text>
      {progress !== null && (
        <Typography.Text role="status">
          {t("inbox.progress", { count: progress })}
        </Typography.Text>
      )}
      {error && (
        <Alert showIcon type="warning" title={t(errorMessage(error))} />
      )}
      {retained.length > 0 &&
        (!writing || retained.some((note) => note.phase === "unknown")) && (
          <Alert
            showIcon
            type="warning"
            title={t("alertEvents.unknown")}
            action={
              <Link to={alertHistoryHref()} onClick={onNavigate}>
                {t("inbox.review")}
              </Link>
            }
          />
        )}
      {!busy && !error && page?.items.length === 0 && (
        <Empty description={t("inbox.empty")} />
      )}
      <ul
        className="notification-list"
        aria-label={t("inbox.unread")}
        aria-busy={busy}
      >
        {page?.items.map((row) => (
          <li key={row.id}>
            <Space wrap className="notification-heading">
              <Tag color="gold">{t("inbox.unread")}</Tag>
              <Tag color={row.status === "active" ? "error" : "default"}>
                {t(`alerts.status.${row.status}`)}
              </Tag>
            </Space>
            <Typography.Text strong>
              {t(
                alertCodes.includes(row.code as AlertCode)
                  ? (`alerts.code.${row.code}` as MessageKey)
                  : "alerts.code.unknown",
              )}
            </Typography.Text>
            <Typography.Text type="secondary" className="managed-identifier">
              {row.origin_node_id}
              {row.resource_id ? ` / ${row.resource_id}` : ""}
            </Typography.Text>
            <Typography.Text type="secondary">
              {recordedTime(row.last_observed_at_unix_ms, intl.locale) ??
                t("alertEvents.unknownTime")}
            </Typography.Text>
            <Space wrap>
              <Link
                to={alertHistoryHref(null, row.latest_transition_sequence)}
                onClick={onNavigate}
              >
                {t("inbox.details")}
              </Link>
              <Button
                disabled={
                  disabled ||
                  retained.some((note) => note.intent.episodeId === row.id)
                }
                onClick={() => void mark(row)}
              >
                {t("alertEvents.ack")}
              </Button>
            </Space>
          </li>
        ))}
      </ul>
      {page?.next_cursor && (
        <Button
          disabled={disabled}
          onClick={() =>
            void read({
              before: page.next_cursor!,
              through: page.through_sequence,
            })
          }
        >
          {t("inbox.older")}
        </Button>
      )}
      <Link to={alertHistoryHref()} onClick={onNavigate}>
        {t("inbox.history")}
      </Link>
    </Space>
  );
}
