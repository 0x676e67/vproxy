import { Alert, Form, Input, Modal, Typography } from "antd";
import { useEffect, useState } from "react";
import { apiError, type ApiError, type SessionView } from "../api/client";
import { errorMessage } from "../api/messages";
import { validCurrentPassword, validNewPassword } from "../api/password";
import { useManagement } from "../auth/context";
import { useMessages } from "../hooks/useMessages";

interface Fields {
  current: string;
  next: string;
  confirmation: string;
}

/** Exists only while opened for the current session. No password enters shared
 * state/storage; submit and unmount clear Form/DOM fields, not immutable JS RAM. */
export default function PasswordDialog({
  session,
  close,
}: {
  session: SessionView;
  close: () => void;
}) {
  const { controller, state } = useManagement();
  const { t, intl } = useMessages();
  const [form] = Form.useForm<Fields>();
  const [error, setError] = useState<ApiError | null>(null);
  useEffect(() => {
    const invalid = form
      .getFieldsError()
      .filter(({ errors }) => errors.length > 0);
    if (invalid.length)
      void form.validateFields(invalid.map(({ name }) => name)).catch(() => {});
  }, [form, intl.locale]);
  const busy = state.busy;
  return (
    <Modal
      open
      title={t("account.password.title")}
      onCancel={close}
      onOk={() => form.submit()}
      okText={t("account.password.submit")}
      cancelText={t("account.password.cancel")}
      confirmLoading={busy}
      okButtonProps={{ disabled: busy }}
      cancelButtonProps={{ disabled: busy }}
      closable={!busy}
      keyboard={!busy}
      maskClosable={!busy}
      destroyOnHidden
    >
      <Typography.Paragraph>
        {t("account.password.scope", {
          username: session.administrator.username,
        })}
      </Typography.Paragraph>
      <Alert type="info" showIcon title={t("account.password.sessions")} />
      <Form<Fields>
        form={form}
        layout="vertical"
        preserve={false}
        clearOnDestroy
        autoComplete="off"
        onFinish={async (values) => {
          let current = values.current,
            next = values.next;
          values.current = values.next = values.confirmation = "";
          // Do not keep entered fields populated while the mutation is pending.
          form.resetFields();
          setError(null);
          try {
            await controller.changePassword(session, current, next);
          } catch (failure) {
            if (
              failure instanceof DOMException &&
              failure.name === "AbortError"
            )
              return;
            if (controller.snapshot().session === session)
              setError(apiError(failure));
          } finally {
            current = "";
            next = "";
          }
        }}
      >
        {error && (
          <Alert
            type="error"
            showIcon
            title={t(
              error.code === "invalid_credentials"
                ? "account.password.incorrect"
                : errorMessage(error),
            )}
          />
        )}
        <Form.Item
          name="current"
          label={t("account.password.current")}
          rules={[
            {
              validator: async (_, value: unknown) => {
                if (!validCurrentPassword(value))
                  throw new Error(t("account.password.currentRequired"));
              },
            },
          ]}
        >
          <Input.Password
            autoFocus
            autoComplete="current-password"
            disabled={busy}
            maxLength={1024}
          />
        </Form.Item>
        <Form.Item
          name="next"
          label={t("account.password.next")}
          rules={[
            {
              validator: async (_, value: unknown) => {
                if (!validNewPassword(value))
                  throw new Error(t("account.password.policy"));
              },
            },
          ]}
        >
          <Input.Password
            autoComplete="new-password"
            disabled={busy}
            maxLength={1024}
          />
        </Form.Item>
        <Form.Item
          name="confirmation"
          label={t("account.password.confirmation")}
          dependencies={["next"]}
          rules={[
            ({ getFieldValue }) => ({
              validator: async (_, value: unknown) => {
                if (
                  typeof value !== "string" ||
                  !value ||
                  value !== getFieldValue("next")
                )
                  throw new Error(t("account.password.mismatch"));
              },
            }),
          ]}
        >
          <Input.Password
            autoComplete="new-password"
            disabled={busy}
            maxLength={1024}
          />
        </Form.Item>
      </Form>
    </Modal>
  );
}
