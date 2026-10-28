import { Button, Form, Input, Select, Space } from "antd";
import { useEffect } from "react";
import type { UserSearchInput } from "../../api/proxy";
import { userSearchQuery } from "../../api/proxy";
import { useMessages } from "../../hooks/useMessages";

export default function UserSearch({
  disabled,
  active,
  submit,
  clear,
  value,
  resetToken,
}: {
  disabled: boolean;
  active: boolean;
  submit: (value: UserSearchInput) => void;
  clear: () => void;
  value?: UserSearchInput | null;
  /** Explicit result location also replaces a draft when the applied ID repeats. */
  resetToken?: object;
}) {
  const { t } = useMessages();
  const [form] = Form.useForm<UserSearchInput>();
  useEffect(() => {
    if (value !== undefined)
      form.setFieldsValue(value ?? { mode: "name", q: "" });
  }, [form, value?.mode, value?.q, resetToken]);
  return (
    <Form<UserSearchInput>
      name="managed-users-search"
      form={form}
      layout="vertical"
      initialValues={{ mode: "name", q: "" }}
      disabled={disabled}
      aria-label={t("users.searchTitle")}
      className="management-user-search"
      onFinish={(value) => {
        if (!disabled) submit({ mode: value.mode, q: value.q.trim() });
      }}
    >
      <div className="management-filter-bar">
        <Form.Item
          name="mode"
          label={t("users.searchMode")}
          className="management-search-mode"
        >
          <Select
            onChange={() => void form.validateFields(["q"]).catch(() => {})}
            options={[
              { value: "name", label: t("users.searchName") },
              { value: "id", label: t("users.searchId") },
            ]}
          />
        </Form.Item>
        <Form.Item
          name="q"
          label={t("users.searchQuery")}
          dependencies={["mode"]}
          className="management-search-query"
          rules={[
            {
              validator: async (_, value: unknown) => {
                try {
                  userSearchQuery({
                    mode: form.getFieldValue("mode"),
                    q: typeof value === "string" ? value.trim() : "",
                  });
                } catch {
                  throw new Error(t("users.searchInvalid"));
                }
              },
            },
          ]}
        >
          <Input autoComplete="off" />
        </Form.Item>
        <Form.Item className="management-search-actions">
          <Space wrap>
            <Button htmlType="submit" type="primary">
              {t("users.searchSubmit")}
            </Button>
            <Button
              disabled={disabled || !active}
              onClick={() => {
                if (disabled) return;
                form.resetFields();
                clear();
              }}
            >
              {t("users.searchClear")}
            </Button>
          </Space>
        </Form.Item>
      </div>
    </Form>
  );
}
