import {
  Alert,
  Button,
  Descriptions,
  Form,
  Input,
  Radio,
  Space,
  Typography,
} from "antd";
import { type ReactNode } from "react";
import {
  publicEndpointAddress,
  publicEndpointInput,
  type ListenerProtocol,
} from "../../api/endpoints";
import {
  selectedPublicAddress,
  type EndpointSelection,
} from "../../api/endpointSettings";
import { useMessages } from "../../hooks/useMessages";

export interface EditableEndpoint {
  id: string;
  protocol: ListenerProtocol;
  bind: string;
  configured_public_address: string | null;
  selection: EndpointSelection;
}

/** One listener's non-secret declaration, never the listener or egress itself.
 * The owner remounts this form after an explicit reload/version change rather
 * than replacing a dirty draft's expected revision behind the operator's back. */
export default function EndpointEditor({
  entry,
  busy,
  blocked,
  notice,
  cancel,
  submit,
}: {
  entry: EditableEndpoint;
  busy: boolean;
  blocked: boolean;
  notice: ReactNode;
  cancel: () => void;
  submit: (selection: EndpointSelection) => Promise<void>;
}) {
  const { t } = useMessages();
  const [form] = Form.useForm();
  const mode = Form.useWatch("mode", form) ?? entry.selection.mode;
  const host = Form.useWatch("host", form);
  const port = Form.useWatch("port", form);
  const existing =
    entry.selection.mode === "custom"
      ? entry.selection.public_address
      : entry.configured_public_address;
  const initial = existing === null ? null : publicEndpointAddress(existing);
  let preview: string | null = null;
  let validPreview = true;
  try {
    preview = selectedPublicAddress(
      mode === "custom"
        ? { mode, public_address: publicEndpointInput(host, port) }
        : { mode },
      entry.configured_public_address,
    );
  } catch {
    validPreview = false;
  }
  return (
    <Form
      form={form}
      layout="vertical"
      preserve
      disabled={busy || blocked}
      initialValues={{
        mode: entry.selection.mode,
        host: initial?.host ?? "",
        port: initial ? String(initial.port) : "",
      }}
      onFinish={async (fields) => {
        const selection: EndpointSelection =
          fields.mode === "custom"
            ? {
                mode: "custom",
                public_address: publicEndpointInput(fields.host, fields.port),
              }
            : { mode: fields.mode };
        await submit(selection);
      }}
    >
      <Space orientation="vertical" size={16} className="full-width">
        <Descriptions
          column={1}
          size="small"
          items={[
            {
              key: "protocol",
              label: t("connections.listenerProtocol"),
              children: entry.protocol.toUpperCase(),
            },
            {
              key: "bind",
              label: t("connections.bind"),
              children: (
                <Typography.Text code className="managed-identifier">
                  {entry.bind}
                </Typography.Text>
              ),
            },
            {
              key: "configured",
              label: t("connections.startupAddress"),
              children:
                entry.configured_public_address ??
                t("connections.unconfigured"),
            },
          ]}
        />
        <Alert
          type="info"
          showIcon
          title={t("connections.metadataOnly")}
          description={t("connections.metadataOnlyHint")}
        />
        {notice}
        <Form.Item
          name="mode"
          label={t("connections.selectionMode")}
          rules={[{ required: true }]}
        >
          <Radio.Group>
            <Space orientation="vertical">
              <Radio value="inherit">{t("connections.mode.inherit")}</Radio>
              <Radio value="custom">{t("connections.mode.custom")}</Radio>
              <Radio value="hidden">{t("connections.mode.hidden")}</Radio>
            </Space>
          </Radio.Group>
        </Form.Item>
        {mode === "custom" && (
          <>
            <Form.Item
              name="host"
              label={t("connections.clientHost")}
              extra={t("connections.clientHostHint")}
              rules={[
                {
                  validator: (_, value) => {
                    try {
                      publicEndpointInput(value, "1");
                      return Promise.resolve();
                    } catch {
                      return Promise.reject(
                        new Error(t("connections.hostRule")),
                      );
                    }
                  },
                },
              ]}
            >
              <Input
                autoFocus
                maxLength={253}
                autoComplete="off"
                spellCheck={false}
                placeholder="proxy.example"
              />
            </Form.Item>
            <Form.Item
              name="port"
              label={t("connections.clientPort")}
              rules={[
                {
                  validator: (_, value) =>
                    /^[1-9][0-9]{0,4}$/.test(value ?? "") &&
                    Number(value) <= 65535
                      ? Promise.resolve()
                      : Promise.reject(new Error(t("connections.portRule"))),
                },
              ]}
            >
              <Input
                inputMode="numeric"
                maxLength={5}
                autoComplete="off"
                placeholder="1080"
              />
            </Form.Item>
          </>
        )}
        {mode === "hidden" && (
          <Alert type="warning" showIcon title={t("connections.hiddenHint")} />
        )}
        <div aria-live="polite">
          <Typography.Text strong>
            {t("connections.addressPreview")}
          </Typography.Text>
          <Typography.Paragraph code className="managed-identifier">
            {validPreview
              ? (preview ?? t("connections.notPublished"))
              : t("connections.previewIncomplete")}
          </Typography.Paragraph>
        </div>
        <Space wrap className="connection-form-actions">
          <Button onClick={cancel} disabled={busy}>
            {t("users.cancel")}
          </Button>
          <Button
            type="primary"
            htmlType="submit"
            loading={busy}
            disabled={blocked || !validPreview}
          >
            {t("connections.saveDeclaration")}
          </Button>
        </Space>
      </Space>
    </Form>
  );
}
