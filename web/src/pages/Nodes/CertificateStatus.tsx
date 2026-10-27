import {
  Alert,
  Button,
  Card,
  Collapse,
  Descriptions,
  Space,
  Tag,
  Typography,
} from "antd";
import { useEffect, useRef, useState } from "react";
import {
  certificateCondition,
  certificateDate,
  type CertificateEntry,
  type CertificateStatus as Status,
} from "../../api/certificates";
import { apiError, type ApiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";
import AcmeStatus from "./AcmeStatus";

function StatusView({ value }: { value: Status }) {
  const { t, intl } = useMessages();
  const date = (seconds: string) =>
    certificateDate(seconds)?.toLocaleString(intl.locale) ??
    t("certificates.dateRange");
  const condition = (entry: CertificateEntry) =>
    certificateCondition(entry, value.observed_at_unix_s);
  return (
    <Space orientation="vertical" size={12} className="full-width">
      <Typography.Paragraph type="secondary">
        {t("certificates.observed")}:{" "}
        {value.observed_at_unix_s === null
          ? t("certificates.clockUnknown")
          : date(value.observed_at_unix_s)}
      </Typography.Paragraph>
      {value.entries.map((entry) => (
        <Card
          size="small"
          key={`${entry.role}:${entry.id ?? "local"}`}
          title={
            <Space wrap size="small">
              <Typography.Text>
                {t(`certificates.role.${entry.role}`)}
              </Typography.Text>
              <Tag>{t(`certificates.source.${entry.source}`)}</Tag>
              {entry.protocol && <Tag>{entry.protocol.toUpperCase()}</Tag>}
              {entry.id && (
                <Typography.Text code title={entry.id}>
                  {entry.id.slice(0, 8)}…
                </Typography.Text>
              )}
            </Space>
          }
        >
          <Space orientation="vertical" className="full-width">
            <Tag>{t(`certificates.condition.${condition(entry)}`)}</Tag>
            {entry.certificate && (
              <Descriptions
                size="small"
                column={{ xs: 1, md: 2 }}
                items={[
                  {
                    key: "sha256",
                    label: "SHA-256",
                    span: "filled",
                    children: (
                      <Typography.Paragraph
                        code
                        copyable={{
                          text: entry.certificate.sha256,
                          tooltips: [
                            t("certificates.copy"),
                            t("certificates.copied"),
                          ],
                        }}
                        style={{
                          marginBottom: 0,
                          overflowWrap: "anywhere",
                          wordBreak: "break-all",
                        }}
                      >
                        {entry.certificate.sha256}
                      </Typography.Paragraph>
                    ),
                  },
                  {
                    key: "before",
                    label: t("certificates.validFrom"),
                    children: date(entry.certificate.not_before_unix_s),
                  },
                  {
                    key: "after",
                    label: t("certificates.validUntil"),
                    children: date(entry.certificate.not_after_unix_s),
                  },
                ]}
              />
            )}
          </Space>
        </Card>
      ))}
    </Space>
  );
}

interface Intent {
  epoch: number;
  nodeId: string;
}

/** Explicit local reads only. A new session or node requires a new expansion;
 * closing/cancelling also fences transports that ignore AbortSignal. */
export default function CertificateStatus({
  disabled,
  nodeId,
}: {
  disabled: boolean;
  nodeId: string;
}) {
  const { controller, state } = useManagement();
  const { t } = useMessages();
  const epoch = controller.generation();
  const [intent, setIntent] = useState<Intent | null>(null);
  const open = intent?.epoch === epoch && intent.nodeId === nodeId;
  const issued = useRef<Intent | null>(null);
  const serial = useRef(0);
  const currentNode = useRef(nodeId);
  currentNode.current = nodeId;
  const [view, setView] = useState<{
    epoch: number;
    nodeId: string;
    value: Status | null;
    error: ApiError | null;
    signal: AbortSignal;
    loading: boolean;
  } | null>(null);
  const current = view?.epoch === epoch && view.nodeId === nodeId ? view : null;
  const loading = current?.loading && !current.signal.aborted;
  const interrupted = current?.loading && current.signal.aborted;
  useEffect(() => {
    const session = state.session;
    if (
      !open ||
      !intent ||
      issued.current === intent ||
      !session ||
      state.busy ||
      disabled
    )
      return;
    issued.current = intent;
    const request = new AbortController();
    const id = ++serial.current;
    const belongs = () =>
      !request.signal.aborted &&
      id === serial.current &&
      epoch === controller.generation() &&
      currentNode.current === nodeId &&
      controller.snapshot().session === session;
    setView({
      epoch,
      nodeId,
      value: null,
      error: null,
      signal: request.signal,
      loading: true,
    });
    void controller
      .resource(
        session,
        (client, _csrf, signal) => client.certificateStatus(nodeId, signal),
        request.signal,
      )
      .then((value) => {
        if (belongs())
          setView({
            epoch,
            nodeId,
            value,
            error: null,
            signal: request.signal,
            loading: false,
          });
      })
      .catch((error) => {
        if (belongs())
          setView({
            epoch,
            nodeId,
            value: null,
            error: apiError(error),
            signal: request.signal,
            loading: false,
          });
      });
    return () => {
      serial.current++;
      request.abort();
    };
  }, [
    open,
    intent,
    controller,
    state.session,
    state.busy,
    disabled,
    epoch,
    nodeId,
  ]);
  const management = current?.value?.entries.find(
    (entry) => entry.role === "management",
  );
  return (
    <Collapse
      ghost
      activeKey={open ? ["certificates"] : []}
      onChange={(keys) =>
        setIntent(keys.includes("certificates") ? { epoch, nodeId } : null)
      }
      items={[
        {
          key: "certificates",
          label: t("certificates.title"),
          collapsible: disabled && !open ? "disabled" : undefined,
          children: open && (
            <Space orientation="vertical" size={12} className="full-width">
              <Typography.Paragraph type="secondary">
                {t("certificates.scope")}
              </Typography.Paragraph>
              <Alert
                type="info"
                showIcon
                title={t("certificates.validityOnly")}
              />
              <Button
                aria-label={t("certificates.refresh")}
                aria-busy={!!loading}
                loading={!!loading}
                disabled={!!loading || state.busy || disabled}
                onClick={() => setIntent({ epoch, nodeId })}
              >
                {t("certificates.refresh")}
              </Button>
              {current?.error && (
                <Alert
                  type="error"
                  showIcon
                  title={t(
                    current.error.status === 404
                      ? "certificates.unsupported"
                      : errorMessage(current.error),
                  )}
                />
              )}
              {interrupted && (
                <Alert
                  type="warning"
                  showIcon
                  title={t("certificates.interrupted")}
                />
              )}
              {current?.value && <StatusView value={current.value} />}
              {management?.source === "acme" && (
                <AcmeStatus disabled={disabled} />
              )}
            </Space>
          ),
        },
      ]}
    />
  );
}
