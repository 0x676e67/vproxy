import {
  Alert,
  Button,
  Card,
  Descriptions,
  Modal,
  Space,
  Tag,
  Typography,
} from "antd";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import type { AlertEpisode } from "../../api/alertEvents";
import { alertCodes, type AlertCode } from "../../api/alerts";
import { apiError, type ApiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import { useManagement } from "../../auth/context";
import type { AckIntent } from "../../auth/alert-acknowledgements";
import { useMessages, type MessageKey } from "../../hooks/useMessages";

export function recordedTime(
  value: string | null,
  locale: string,
): string | null {
  if (value === null || BigInt(value) > 8_640_000_000_000_000n) return null;
  return new Date(Number(value)).toLocaleString(locale);
}
export default function EpisodeReview({
  value,
  fresh,
  blocked,
  current,
  onRead,
  onValue,
  onInvalid,
  onBusy,
}: {
  value: AlertEpisode;
  fresh: boolean;
  blocked: boolean;
  current: () => boolean;
  onRead: (id: string) => void;
  onValue: (value: AlertEpisode) => void;
  onInvalid: () => void;
  onBusy: (value: boolean) => void;
}) {
  const { controller, state } = useManagement(),
    { t, intl } = useMessages();
  const reviews = controller.alertAcknowledgements;
  useSyncExternalStore(reviews.subscribe, reviews.snapshot);
  const actor = state.session?.administrator.id;
  const review = actor
    ? reviews.find({
        administratorId: actor,
        nodeId: value.node_id,
        episodeId: value.id,
      })
    : null;
  const latest = useRef({ value, fresh, current });
  latest.current = { value, fresh, current };
  const mounted = useRef(false),
    pending = useRef<AbortController | null>(null);
  const [confirm, setConfirm] = useState<AlertEpisode | null>(null),
    [finish, setFinish] = useState(false);
  const [working, setWorking] = useState(false),
    [failure, setFailure] = useState<ApiError | null>(null);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      pending.current?.abort();
    };
  }, []);
  const disabled = blocked || working || state.busy || !state.session || !fresh;
  const date = (time: string | null) =>
    time === null
      ? t("alertEvents.unknownTime")
      : (recordedTime(time, intl.locale) ??
        t("alertEvents.outsideDate", { value: time }));
  const acknowledge = async () => {
    const snapshot = confirm,
      session = state.session,
      epoch = controller.generation();
    if (
      !snapshot ||
      snapshot !== value ||
      disabled ||
      review ||
      !session ||
      !current() ||
      pending.current
    )
      return;
    const request = new AbortController();
    pending.current = request;
    setWorking(true);
    onBusy(true);
    setFailure(null);
    let token: object | null = null,
      admitted = false;
    const belongs = () =>
      mounted.current &&
      !request.signal.aborted &&
      controller.generation() === epoch &&
      controller.snapshot().session === session &&
      latest.current.value === snapshot &&
      latest.current.fresh &&
      latest.current.current();
    const cancelled = () => {
      if (token) {
        if (admitted) reviews.unknown(token);
        else reviews.complete(token);
      }
    };
    request.signal.addEventListener("abort", cancelled, { once: true });
    try {
      const intent: AckIntent = {
        administratorId: session.administrator.id,
        nodeId: snapshot.node_id,
        episodeId: snapshot.id,
        transitionSequence: snapshot.latest_transition_sequence,
      };
      token = await reviews.begin(intent, belongs);
      if (!token) return;
      if (!belongs()) {
        reviews.complete(token);
        return;
      }
      const result = await controller.resource(
        session,
        async (client, csrf, signal) => {
          admitted = true;
          signal.addEventListener("abort", cancelled, { once: true });
          try {
            return await client.acknowledgeAlertEpisode(
              snapshot.id,
              {
                expected_node_id: snapshot.node_id,
                expected_transition_sequence:
                  snapshot.latest_transition_sequence,
              },
              csrf,
              signal,
            );
          } finally {
            signal.removeEventListener("abort", cancelled);
          }
        },
        request.signal,
      );
      if (!belongs()) {
        reviews.unknown(token);
        return;
      }
      reviews.complete(token);
      onValue(result);
    } catch (error) {
      const problem = apiError(error);
      const rejected =
        problem.status === 409 && problem.code === "alert_history_conflict";
      if (token) {
        if (rejected && belongs()) reviews.complete(token);
        else if (admitted) reviews.unknown(token);
        else reviews.complete(token);
      }
      if (belongs()) {
        setFailure(problem);
        onInvalid();
      }
    } finally {
      request.signal.removeEventListener("abort", cancelled);
      if (token) reviews.release(token);
      if (pending.current === request) pending.current = null;
      if (mounted.current) {
        setWorking(false);
        onBusy(false);
        setConfirm(null);
      }
    }
  };
  const finishReview = async () => {
    const record = review,
      snapshot = value,
      session = state.session,
      epoch = controller.generation();
    if (!record || disabled || record.phase !== "unknown" || !session) return;
    const valid = () =>
      mounted.current &&
      latest.current.value === snapshot &&
      latest.current.fresh &&
      latest.current.current() &&
      controller.generation() === epoch &&
      controller.snapshot().session === session;
    setWorking(true);
    onBusy(true);
    try {
      await reviews.reviewed(record.token, valid);
    } finally {
      if (mounted.current) {
        setWorking(false);
        onBusy(false);
        setFinish(false);
      }
    }
  };
  const reason = t(
    alertCodes.includes(value.code as AlertCode)
      ? (`alerts.code.${value.code}` as MessageKey)
      : "alerts.code.unknown",
  );
  const issue = reviews.issue(),
    capacity = reviews.snapshot().length >= 32;
  return (
    <Card size="small" title={`${t("alertEvents.episodeTitle")} ${value.id}`}>
      <Space orientation="vertical" size={12} className="full-width">
        <Typography.Text type="secondary">
          {t("alertEvents.episodeHint")}
        </Typography.Text>
        <Space wrap>
          <Tag>{t(`alerts.status.${value.status}`)}</Tag>
          <Tag>
            {t(
              value.is_acknowledged
                ? "alertEvents.acknowledged"
                : value.acknowledged_transition_sequence === null
                  ? "alertEvents.unacknowledged"
                  : "alertEvents.previousAck",
            )}
          </Tag>
        </Space>
        <Typography.Text>{reason}</Typography.Text>
        <Descriptions
          size="small"
          column={{ xs: 1, sm: 2 }}
          items={[
            {
              key: "origin",
              label: t("alerts.subject"),
              children: (
                <Typography.Text code>{value.origin_node_id}</Typography.Text>
              ),
            },
            {
              key: "observer",
              label: t("alertEvents.observer"),
              children: <Typography.Text code>{value.node_id}</Typography.Text>,
            },
            {
              key: "latest",
              label: t("alertEvents.latest"),
              children: value.latest_transition_sequence,
            },
            {
              key: "boot",
              label: t("alertEvents.boot"),
              children: <Typography.Text code>{value.boot_id}</Typography.Text>,
            },
            {
              key: "incident",
              label: t("alertEvents.incident"),
              children: value.incident_id,
            },
            {
              key: "observed",
              label: t("alerts.observed"),
              children: date(value.last_observed_at_unix_ms),
            },
            {
              key: "ack",
              label: t("alertEvents.ackSequence"),
              children:
                value.acknowledged_transition_sequence ??
                t("alertEvents.unknownTime"),
            },
            {
              key: "by",
              label: t("alertEvents.ackBy"),
              children: value.acknowledged_by ?? t("alertEvents.unknownTime"),
            },
            {
              key: "at",
              label: t("alertEvents.ackAt"),
              children: date(value.acknowledged_at_unix_ms),
            },
            ...(value.end_reason
              ? [
                  {
                    key: "end",
                    label: t("alertEvents.endReason"),
                    children: t(`alertEvents.end.${value.end_reason}`),
                  },
                ]
              : []),
          ]}
        />
        {failure && (
          <Alert showIcon type="error" title={t(errorMessage(failure))} />
        )}
        {issue && (
          <Alert showIcon type="warning" title={t("alertEvents.storage")} />
        )}
        {!issue && capacity && !review && (
          <Alert showIcon type="warning" title={t("alertEvents.capacity")} />
        )}
        {review && (
          <Alert
            type="warning"
            showIcon
            title={t(
              review.phase === "pending"
                ? "alertEvents.confirming"
                : "alertEvents.unknown",
            )}
            description={
              review.phase === "unknown" &&
              value.acknowledged_transition_sequence !== null &&
              BigInt(value.acknowledged_transition_sequence) >=
                BigInt(review.intent.transitionSequence)
                ? t("alertEvents.covered")
                : review.phase === "unknown" &&
                    BigInt(value.latest_transition_sequence) >
                      BigInt(review.intent.transitionSequence)
                  ? t("alertEvents.advanced")
                  : undefined
            }
          />
        )}
        <Space wrap>
          <Button
            disabled={blocked || working || state.busy}
            onClick={() => onRead(review?.intent.episodeId ?? value.id)}
          >
            {t(review ? "alertEvents.readOriginal" : "alerts.refresh")}
          </Button>
          {!review && !value.is_acknowledged && (
            <Button
              disabled={disabled || !!issue || capacity}
              onClick={() => setConfirm(value)}
            >
              {t("alertEvents.ack")}
            </Button>
          )}
          {review?.phase === "unknown" && (
            <Button disabled={disabled} onClick={() => setFinish(true)}>
              {t("alertEvents.finish")}
            </Button>
          )}
        </Space>
        <Modal
          open={confirm !== null}
          title={t("alertEvents.confirm")}
          okText={t("alertEvents.ack")}
          cancelText={t("users.cancel")}
          confirmLoading={working}
          okButtonProps={{
            disabled: disabled || confirm !== value || !!review,
          }}
          cancelButtonProps={{ disabled: working }}
          onOk={() => void acknowledge()}
          onCancel={() => {
            if (!working) setConfirm(null);
          }}
        >
          <Typography.Paragraph>
            {t("alertEvents.confirmHint")}
          </Typography.Paragraph>
          <Typography.Text>
            {t("alertEvents.latest")}: {confirm?.latest_transition_sequence}
          </Typography.Text>
        </Modal>
        <Modal
          open={finish}
          title={t("alertEvents.finish")}
          okText={t("alertEvents.finish")}
          cancelText={t("users.cancel")}
          confirmLoading={working}
          okButtonProps={{ disabled }}
          onOk={() => void finishReview()}
          onCancel={() => {
            if (!working) setFinish(false);
          }}
        >
          <Typography.Paragraph>
            {t("alertEvents.finishHint")}
          </Typography.Paragraph>
        </Modal>
      </Space>
    </Card>
  );
}
