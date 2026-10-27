import {
  Alert,
  Button,
  Collapse,
  Descriptions,
  Space,
  Tag,
  Typography,
} from "antd";
import { useEffect, useRef, useState } from "react";
import { acmeDate, type AcmeStatus as Status } from "../../api/acme";
import { apiError, type ApiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";

function StatusView({ value }: { value: Status }) {
  const { t, intl } = useMessages();
  if (value.mode === "manual")
    return <Typography.Paragraph>{t("acme.manual")}</Typography.Paragraph>;
  const date = (value: string) =>
    acmeDate(value)?.toLocaleString(intl.locale) ?? t("acme.dateRange");
  return (
    <Space orientation="vertical" className="full-width">
      {value.environment === "staging" && (
        <Alert type="warning" showIcon title={t("acme.stagingWarning")} />
      )}
      <Space wrap>
        <Tag>{t(`acme.environment.${value.environment}`)}</Tag>
        <Tag>{t(`acme.activity.${value.activity}`)}</Tag>
      </Space>
      {value.last_failure && (
        <Alert
          type="warning"
          showIcon
          title={t("acme.lastFailure")}
          description={t(`acme.failure.${value.last_failure}`)}
        />
      )}
      <Descriptions
        size="small"
        column={1}
        items={[
          {
            key: "certificate",
            label: t("acme.certificate"),
            children: t(
              value.certificate?.available
                ? "acme.available"
                : "acme.unavailable",
            ),
          },
          {
            key: "before",
            label: t("acme.validFrom"),
            children: value.certificate
              ? date(value.certificate.not_before_unix_s)
              : t("acme.notActivated"),
          },
          {
            key: "after",
            label: t("acme.validUntil"),
            children: value.certificate
              ? date(value.certificate.not_after_unix_s)
              : t("acme.notActivated"),
          },
          {
            key: "challenge",
            label: t("acme.challenge"),
            children: value.challenge,
          },
          {
            key: "next",
            label: t("acme.nextAttempt"),
            children:
              value.next_attempt_at_unix_s === null
                ? t("acme.noSchedule")
                : BigInt(value.next_attempt_at_unix_s) <=
                    BigInt(value.observed_at_unix_s)
                  ? t("acme.due")
                  : date(value.next_attempt_at_unix_s),
          },
          {
            key: "observed",
            label: t("acme.observed"),
            children: date(value.observed_at_unix_s),
          },
        ]}
      />
    </Space>
  );
}

/** Explicit local-only reads. A session change or closed panel cancels the read. */
export default function AcmeStatus({ disabled }: { disabled: boolean }) {
  const { controller, state } = useManagement();
  const { t } = useMessages();
  const epoch = controller.generation();
  const [expandedEpoch, setExpandedEpoch] = useState<number | null>(null);
  const open = expandedEpoch === epoch;
  const [refresh, setRefresh] = useState(0);
  const [view, setView] = useState<{
    epoch: number;
    value: Status | null;
    loading: boolean;
    error: ApiError | null;
  } | null>(null);
  const serial = useRef(0);
  const current = view?.epoch === epoch ? view : null;
  useEffect(() => {
    if (!open || !state.session || state.busy) return;
    const request = new AbortController();
    const id = ++serial.current;
    setView({ epoch, value: null, loading: true, error: null });
    void controller
      .resource(
        state.session,
        (client, _csrf, signal) => client.acmeStatus(signal),
        request.signal,
      )
      .then((value) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          epoch === controller.generation()
        )
          setView({ epoch, value, loading: false, error: null });
      })
      .catch((error) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          epoch === controller.generation()
        )
          setView({
            epoch,
            value: null,
            loading: false,
            error: apiError(error),
          });
      });
    return () => {
      serial.current++;
      request.abort();
    };
  }, [open, refresh, controller, state.session, state.busy, epoch]);
  return (
    <Collapse
      ghost
      activeKey={open ? ["acme"] : []}
      onChange={(keys) =>
        setExpandedEpoch(keys.includes("acme") ? epoch : null)
      }
      items={[
        {
          key: "acme",
          label: t("acme.title"),
          collapsible: disabled && !open ? "disabled" : undefined,
          children: open && (
            <Space orientation="vertical" className="full-width">
              <Typography.Paragraph type="secondary">
                {t("acme.scope")}
              </Typography.Paragraph>
              <Button
                loading={current?.loading}
                disabled={current?.loading || state.busy || disabled}
                onClick={() => setRefresh((value) => value + 1)}
              >
                {t("acme.refresh")}
              </Button>
              {current?.error && (
                <Alert
                  type="error"
                  showIcon
                  title={t(
                    current.error.status === 404
                      ? "acme.unsupported"
                      : errorMessage(current.error),
                  )}
                />
              )}
              {current?.value && <StatusView value={current.value} />}
            </Space>
          ),
        },
      ]}
    />
  );
}
