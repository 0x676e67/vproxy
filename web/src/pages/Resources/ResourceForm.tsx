import {
  ModalForm,
  ProFormSelect,
  ProFormText,
} from "@ant-design/pro-components";
import type { ReactNode } from "react";
import { Alert } from "antd";
import { canonicalId, validUserName } from "../../api/proxy";
import { validCidr, validIp, type ResourceKind } from "../../api/routing";
import { useMessages } from "../../hooks/useMessages";

export interface ResourceFields {
  name: string;
  cidr: string;
  ip: string;
  prefix_id: string;
  family: "v4" | "v6";
}
export default function ResourceForm({
  kind,
  busy,
  blocked,
  notice,
  close,
  submit,
}: {
  kind: ResourceKind;
  busy: boolean;
  blocked: boolean;
  notice: ReactNode;
  close: () => void;
  submit: (values: ResourceFields) => Promise<boolean>;
}) {
  const { t } = useMessages();
  return (
    <ModalForm<ResourceFields>
      open
      title={t("resources.register")}
      initialValues={{
        name: "",
        cidr: "",
        ip: "",
        prefix_id: "",
        family: "v4",
      }}
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
        submitButtonProps: { loading: busy, disabled: busy || blocked },
        resetButtonProps: { disabled: busy, onClick: close },
      }}
      onFinish={submit}
    >
      {notice}
      <Alert
        type="info"
        showIcon
        title={t(
          kind === "prefixes"
            ? "resources.prefixHint"
            : kind === "addresses"
              ? "resources.addressHint"
              : "resources.poolHint",
        )}
      />
      <ProFormText
        name="name"
        label={t("resources.name")}
        fieldProps={{ maxLength: 128, disabled: busy, autoComplete: "off" }}
        rules={[
          { required: true, message: t("users.nameRule") },
          {
            validator: async (_, value) => {
              if (value && !validUserName(value))
                throw new Error(t("users.nameRule"));
            },
          },
        ]}
      />
      {kind === "prefixes" && (
        <ProFormText
          name="cidr"
          label={t("resources.cidr")}
          fieldProps={{ maxLength: 49, disabled: busy, autoComplete: "off" }}
          rules={[
            { required: true, message: t("resources.cidrRule") },
            {
              validator: async (_, value) => {
                if (value && !validCidr(value))
                  throw new Error(t("resources.cidrRule"));
              },
            },
          ]}
        />
      )}
      {kind === "addresses" && (
        <>
          <ProFormText
            name="ip"
            label={t("resources.ip")}
            fieldProps={{ maxLength: 45, disabled: busy, autoComplete: "off" }}
            rules={[
              { required: true, message: t("resources.ipRule") },
              {
                validator: async (_, value) => {
                  if (value && !validIp(value))
                    throw new Error(t("resources.ipRule"));
                },
              },
            ]}
          />
          <ProFormText
            name="prefix_id"
            label={t("resources.prefixId")}
            fieldProps={{ maxLength: 22, disabled: busy, autoComplete: "off" }}
            rules={[
              {
                validator: async (_, value) => {
                  if (value && !canonicalId(value))
                    throw new Error(t("resources.idRule"));
                },
              },
            ]}
          />
        </>
      )}
      {kind === "pools" && (
        <ProFormSelect
          name="family"
          label={t("resources.family")}
          disabled={busy}
          options={[
            { label: "IPv4", value: "v4" },
            { label: "IPv6", value: "v6" },
          ]}
          rules={[{ required: true }]}
        />
      )}
    </ModalForm>
  );
}
