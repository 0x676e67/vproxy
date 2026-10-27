import { PlusOutlined } from "@ant-design/icons";
import {
  ModalForm,
  ProFormSelect,
  ProFormText,
} from "@ant-design/pro-components";
import { useIntl } from "@umijs/max";
import { Alert, App, Button, Form, Space } from "antd";
import { useEffect, useState } from "react";
import LanguageSwitch from "../../components/LanguageSwitch";
import type { ManagedNode } from "../../data/nodes";
import { createPendingNode } from "../../data/samples";
import { useNodeLabels } from "./labels";

interface SampleForm {
  name: string;
  region: string;
  parentId?: string;
}

export default function AddNodeButton({
  nodes,
  onAdd,
}: {
  nodes: readonly ManagedNode[];
  onAdd: (node: ManagedNode) => void;
}) {
  const { t } = useNodeLabels();
  const intl = useIntl();
  const { message } = App.useApp();
  const [open, setOpen] = useState(false);
  const [form] = Form.useForm<SampleForm>();
  const limit = nodes.length >= 20;

  useEffect(() => {
    if (!open) return;
    // AntD stores validation messages. Revalidate only errors already visible
    // when the locale changes; do not erase input or validate untouched fields.
    const invalid = form
      .getFieldsError()
      .filter(({ errors }) => errors.length > 0);
    if (invalid.length > 0) {
      void form.validateFields(invalid.map(({ name }) => name)).catch(() => {});
    }
  }, [intl.locale, form, open]);

  return (
    <ModalForm<SampleForm>
      title={
        <Space wrap>
          {t("form.title")}
          <LanguageSwitch />
        </Space>
      }
      form={form}
      open={open}
      onOpenChange={setOpen}
      width={520}
      trigger={
        <Button type="primary" icon={<PlusOutlined />} disabled={limit}>
          {t(limit ? "form.limit" : "form.add")}
        </Button>
      }
      modalProps={{ destroyOnHidden: true }}
      submitter={{
        searchConfig: {
          submitText: t("form.submit"),
          resetText: t("form.cancel"),
        },
      }}
      onFinish={async (values) => {
        if (nodes.length >= 20) return false;
        onAdd(
          createPendingNode({ ...values, parentId: values.parentId ?? null }),
        );
        void message.success(t("form.added"));
        return true;
      }}
    >
      <Alert
        type="info"
        showIcon
        title={t("form.notice")}
        className="sample-form-notice"
      />
      <ProFormText
        name="name"
        label={t("node.name")}
        placeholder={t("form.namePlaceholder")}
        fieldProps={{ maxLength: 48, autoComplete: "off", allowClear: false }}
        rules={[
          { required: true, whitespace: true, message: t("form.nameRequired") },
          {
            pattern: /^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/,
            message: t("form.namePattern"),
          },
          {
            validator: async (_, value: string | undefined) => {
              if (nodes.some((node) => node.name === value?.trim())) {
                throw new Error(t("form.nameDuplicate"));
              }
            },
          },
        ]}
      />
      <ProFormText
        name="region"
        label={t("node.region")}
        placeholder={t("form.regionPlaceholder")}
        fieldProps={{ maxLength: 64, autoComplete: "off", allowClear: false }}
        rules={[
          {
            required: true,
            whitespace: true,
            message: t("form.regionRequired"),
          },
          { max: 64, message: t("form.regionLength") },
        ]}
      />
      <ProFormSelect
        name="parentId"
        label={t("node.parent")}
        placeholder={t("form.parentPlaceholder")}
        // Pending samples do not pretend to be enrolled control nodes.
        options={nodes
          .filter((node) => node.control !== "pending")
          .map((node) => ({ label: node.name, value: node.id }))}
        fieldProps={{ allowClear: true }}
      />
    </ModalForm>
  );
}
