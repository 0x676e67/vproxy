import { Alert, Button, Collapse, Space, Typography } from "antd";
import type { DiagnosticProfile as Profile } from "../../api/diagnosticProfile";
import { useMessages } from "../../hooks/useMessages";

export const DIAGNOSTIC_FILENAME = "vproxy-connection-profile.json";
export default function DiagnosticProfile({
  value,
  disabled,
  expired,
  status,
  download,
}: {
  value: Readonly<Profile> | null;
  disabled: boolean;
  expired: boolean;
  status: "requested" | "failed" | null;
  download: () => void;
}) {
  const { t } = useMessages();
  const command = `vproxy manage test-connection --profile "./${DIAGNOSTIC_FILENAME}"${value?.protocol === "http" || value?.protocol === "socks5" ? " --allow-plaintext" : ""}`;
  return (
    <Collapse
      items={[
        {
          key: "diagnostic",
          label: t("connections.diagnostic"),
          children: value ? (
            <Space orientation="vertical" size={12} className="full-width">
              <Typography.Paragraph>
                {t("connections.diagnosticHint")}
              </Typography.Paragraph>
              <Typography.Text type="secondary">
                {t("connections.diagnosticMetadata")}
              </Typography.Text>
              <Button disabled={disabled} onClick={download}>
                {t("connections.downloadDiagnostic")}
              </Button>
              {expired && (
                <Alert
                  showIcon
                  type="warning"
                  title={t("connections.diagnosticExpired")}
                />
              )}
              {status && (
                <Alert
                  showIcon
                  type={status === "requested" ? "info" : "error"}
                  title={t(
                    status === "requested"
                      ? "connections.diagnosticRequested"
                      : "connections.diagnosticFailed",
                  )}
                />
              )}
              <Typography.Paragraph>
                {t("connections.diagnosticRun")}
              </Typography.Paragraph>
              {value.protocol !== "https" && (
                <Alert
                  showIcon
                  type="warning"
                  title={t("connections.diagnosticPlaintext")}
                />
              )}
              <pre
                className="connection-example"
                tabIndex={0}
                aria-label={t("connections.diagnosticCommand")}
              >
                <code>{command}</code>
              </pre>
              <Typography.Paragraph>
                {t(
                  value.protocol === "https"
                    ? "connections.diagnosticCa"
                    : "connections.diagnosticDns",
                )}
              </Typography.Paragraph>
              <Typography.Paragraph type="secondary">
                {t("connections.diagnosticAutomation")}
              </Typography.Paragraph>
            </Space>
          ) : (
            <Typography.Paragraph>
              {t("connections.diagnosticUnsupported")}
            </Typography.Paragraph>
          ),
        },
      ]}
    />
  );
}
