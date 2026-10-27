import { Alert, Form, Input, Modal, Switch } from "antd";
import { useEffect, type ReactNode } from "react";
import { canonicalId } from "../../api/proxy";
import { canonicalOrigin, validServerIp, type Target } from "../../api/targets";
import { useMessages } from "../../hooks/useMessages";

export interface TargetInput {
  node_id: string;
  origin: string;
  active: boolean;
  server_ip: string | null;
}

/** Share the same admission fields with onboarding, not a second form contract. */
export function TargetFields({ target }: { target: Target | null }) {
  const { t } = useMessages();
  return (
    <>
      <Form.Item
        name="node_id"
        label={t("control.nodeId")}
        rules={[
          {
            validator: (_, value) =>
              canonicalId(value)
                ? Promise.resolve()
                : Promise.reject(new Error(t("control.idRule"))),
          },
        ]}
      >
        <Input disabled={!!target} maxLength={22} autoComplete="off" />
      </Form.Item>
      <Form.Item
        name="origin"
        label={t("control.origin")}
        extra={t("control.originHint")}
        rules={[
          {
            validator: (_, value) =>
              canonicalOrigin(value)
                ? Promise.resolve()
                : Promise.reject(new Error(t("control.originRule"))),
          },
        ]}
      >
        <Input
          maxLength={300}
          autoComplete="off"
          placeholder="https://node.example:9443"
        />
      </Form.Item>
      <Form.Item
        name="server_ip"
        label={t("control.serverIp")}
        extra={t("control.serverIpHint")}
        rules={[
          {
            validator: (_, value) =>
              value === undefined || value === "" || validServerIp(value)
                ? Promise.resolve()
                : Promise.reject(new Error(t("control.serverIpRule"))),
          },
        ]}
      >
        <Input maxLength={45} autoComplete="off" />
      </Form.Item>
      <Form.Item
        name="active"
        label={t("control.deliveryEnabled")}
        valuePropName="checked"
      >
        <Switch />
      </Form.Item>
    </>
  );
}

export default function TargetForm({
  target,
  busy,
  blocked,
  notice,
  close,
  submit,
}: {
  target: Target | null;
  busy: boolean;
  blocked: boolean;
  notice: ReactNode;
  close: () => void;
  submit: (value: TargetInput) => Promise<boolean>;
}) {
  const { t } = useMessages();
  const [form] = Form.useForm();
  useEffect(() => {
    form.setFieldsValue({
      node_id: target?.node_id ?? "",
      origin: target?.origin ?? "",
      active: target?.active ?? true,
      server_ip: target?.server_ip ?? "",
    });
  }, [form, target]);
  return (
    <Modal
      open
      title={t(target ? "control.editTarget" : "control.addTarget")}
      okText={t("users.save")}
      cancelText={t("users.cancel")}
      confirmLoading={busy}
      okButtonProps={{ disabled: blocked }}
      maskClosable={false}
      closable={!busy}
      cancelButtonProps={{ disabled: busy }}
      onCancel={close}
      onOk={() => form.submit()}
      destroyOnHidden
    >
      <Alert type="info" showIcon title={t("control.enrollmentRequired")} />
      {notice}
      <Form
        form={form}
        layout="vertical"
        preserve={false}
        disabled={busy || blocked}
        onFinish={(value) =>
          void submit({ ...value, server_ip: value.server_ip || null })
        }
      >
        <TargetFields target={target} />
      </Form>
    </Modal>
  );
}
