import { Alert, Button, Collapse, Space, Tabs, Typography } from "antd";
import { useState } from "react";
import type { clientExamples } from "../../api/clientExamples";
import { useMessages } from "../../hooks/useMessages";

/** Sensitive recipes stay in the authenticated connection workspace. Clipboard
 * writes require a click; this component never stores or executes a recipe. */
export default function ClientExamples({
  value,
  canCopy,
}: {
  value: ReturnType<typeof clientExamples>;
  canCopy?: () => boolean;
}) {
  const { t } = useMessages();
  const [status, setStatus] = useState<"copied" | "copyFailed" | null>(null);
  const allowed = () =>
    !value.supported || !value.containsPassword || canCopy?.() === true;
  const copy = async (code: string) => {
    if (!allowed()) return;
    setStatus(null);
    try {
      await navigator.clipboard.writeText(code);
      if (allowed()) setStatus("copied");
    } catch {
      if (allowed()) setStatus("copyFailed");
    }
  };
  const recipe = (code: string, name: string) => (
    <>
      <Button disabled={!allowed()} onClick={() => void copy(code)}>
        {t("connections.copyExample")}
      </Button>
      {status && (
        <Typography.Paragraph role="status">
          {t(`connections.${status}`)}
        </Typography.Paragraph>
      )}
      <pre className="connection-example" tabIndex={0} aria-label={name}>
        <code>{code}</code>
      </pre>
    </>
  );
  return (
    <Collapse
      defaultActiveKey={
        value.supported && value.containsPassword ? ["examples"] : []
      }
      items={[
        {
          key: "examples",
          label: t("connections.clientExamples"),
          children: !value.supported ? (
            <Typography.Paragraph>
              {t("connections.examplesUnsupported")}
            </Typography.Paragraph>
          ) : (
            <Space orientation="vertical" className="full-width" size={12}>
              <Alert
                type="info"
                showIcon
                title={t(
                  value.containsPassword
                    ? "connections.examplesPasswordHint"
                    : "connections.examplesHint",
                )}
                description={
                  !value.httpsProxy && !value.containsPassword
                    ? t("connections.unencryptedProxy")
                    : undefined
                }
              />
              {value.httpsProxy && (
                <Typography.Paragraph>
                  {t("connections.examplesTls")}
                </Typography.Paragraph>
              )}
              <Tabs
                className="full-width"
                destroyOnHidden
                items={[
                  {
                    key: "curl",
                    label: "curl",
                    children: (
                      <>
                        <Typography.Paragraph>
                          {t(
                            value.containsPassword
                              ? "connections.curlReadyHint"
                              : "connections.curlHint",
                          )}
                        </Typography.Paragraph>
                        {recipe(value.curl, "curl")}
                      </>
                    ),
                  },
                  {
                    key: "python",
                    label: "Python Requests",
                    children: (
                      <>
                        <Typography.Paragraph>
                          {t(
                            value.containsPassword
                              ? "connections.pythonReadyHint"
                              : "connections.pythonHint",
                            {
                              dependency: value.pythonDependency,
                            },
                          )}
                        </Typography.Paragraph>
                        {recipe(value.python, "Python Requests")}
                      </>
                    ),
                  },
                ]}
              />
            </Space>
          ),
        },
      ]}
    />
  );
}
