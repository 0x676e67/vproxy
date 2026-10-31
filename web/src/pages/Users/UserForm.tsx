import {
  ModalForm,
  ProFormCheckbox,
  ProFormDigit,
  ProFormText,
} from "@ant-design/pro-components";
import type { ProxyUser, UserInput } from "../../api/proxy";
import { validUserName } from "../../api/proxy";
import { useMessages } from "../../hooks/useMessages";
import type { ReactNode } from "react";
import { Tooltip } from "antd";

export default function UserForm({
  user,
  busy,
  close,
  submit,
  notice,
}: {
  user: ProxyUser | null;
  busy: boolean;
  close: () => void;
  submit: (input: UserInput) => Promise<boolean>;
  notice: ReactNode;
}) {
  const { t } = useMessages();
  return (
    <ModalForm<UserInput>
      open
      title={t(user ? "users.edit" : "users.create")}
      initialValues={
        user ?? {
          name: "",
          protocols: ["http", "socks5", "masque"],
          concurrent_limit: 32,
        }
      }
      modalProps={{
        destroyOnHidden: true,
        onCancel: close,
        maskClosable: false,
        closable: !busy,
      }}
      submitter={{
        searchConfig: {
          submitText: t("users.save"),
          resetText: t("users.cancel"),
        },
        submitButtonProps: { loading: busy },
        resetButtonProps: { disabled: busy, onClick: close },
      }}
      onFinish={submit}
    >
      {notice}
      <ProFormText
        name="name"
        label={t("users.name")}
        fieldProps={{ maxLength: 128, disabled: busy, autoComplete: "off" }}
        rules={[
          { required: true, message: t("users.nameRule") },
          {
            validator: async (_, value: string) => {
              if (value && !validUserName(value))
                throw new Error(t("users.nameRule"));
            },
          },
        ]}
      />
      <ProFormCheckbox.Group
        name="protocols"
        label={t("users.protocols")}
        disabled={busy}
        options={[
          {
            label: (
              <Tooltip title={t("users.httpShared")}>
                <span>HTTP + HTTPS</span>
              </Tooltip>
            ),
            value: "http",
          },
          { label: "SOCKS5", value: "socks5" },
          { label: "MASQUE", value: "masque" },
        ]}
      />
      <ProFormDigit
        name="concurrent_limit"
        label={t("users.limit")}
        min={1}
        max={1_000_000}
        fieldProps={{ precision: 0, disabled: busy }}
        rules={[{ required: true, message: t("users.limitRule") }]}
      />
    </ModalForm>
  );
}
