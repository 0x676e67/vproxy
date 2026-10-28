import { LoginForm, ProCard, ProFormText } from "@ant-design/pro-components";
import { Alert, Button, Form, Result, Space, Spin, Typography } from "antd";
import { useEffect, type ReactNode } from "react";
import { errorMessage } from "../../api/messages";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";

interface LoginValues {
  username: string;
  password: string;
}

function Login() {
  const { controller, state } = useManagement();
  const { intl, t } = useMessages();
  const [form] = Form.useForm<LoginValues>();
  useEffect(() => {
    const invalid = form
      .getFieldsError()
      .filter(({ errors }) => errors.length > 0);
    if (invalid.length > 0) {
      void form.validateFields(invalid.map(({ name }) => name)).catch(() => {});
    }
  }, [form, intl.locale]);

  return (
    <ProCard variant="outlined" className="management-login">
      <LoginForm<LoginValues>
        form={form}
        contentStyle={{ width: "100%" }}
        title="vproxy"
        subTitle={t("auth.description")}
        submitter={{
          searchConfig: { submitText: t("auth.signIn") },
          submitButtonProps: { loading: state.busy },
        }}
        onFinish={async (values) => {
          const accepted = await controller.login(
            values.username,
            values.password,
          );
          if (accepted) form.resetFields(["password"]);
          return accepted;
        }}
      >
        {state.passwordChangeNotice && (
          <Alert
            className="management-form-notice"
            showIcon
            type={
              state.passwordChangeNotice === "changed" ? "success" : "warning"
            }
            title={t(`account.password.${state.passwordChangeNotice}`)}
          />
        )}
        {state.error && (
          <Alert
            className="management-form-notice"
            type="error"
            showIcon
            title={t(errorMessage(state.error))}
          />
        )}
        <ProFormText
          name="username"
          label={t("auth.username")}
          fieldProps={{
            autoComplete: "username",
            maxLength: 64,
            disabled: state.busy,
            allowClear: false,
          }}
          rules={[{ required: true, message: t("auth.usernameRequired") }]}
        />
        <ProFormText.Password
          name="password"
          label={t("auth.password")}
          fieldProps={{
            autoComplete: "current-password",
            maxLength: 1024,
            disabled: state.busy,
            allowClear: false,
          }}
          rules={[
            { required: true, message: t("auth.passwordRequired") },
            {
              validator: async (_, value: string | undefined) => {
                if (value && new TextEncoder().encode(value).length > 1024)
                  throw new Error(t("auth.passwordLength"));
              },
            },
          ]}
        />
        <Typography.Paragraph type="secondary">
          {t("auth.credentialsNotice")}
        </Typography.Paragraph>
      </LoginForm>
    </ProCard>
  );
}

/** Keep connection failures distinct from anonymous sessions and bad passwords. */
export default function ManagementGate({ children }: { children: ReactNode }) {
  const { controller, state } = useManagement();
  const { t } = useMessages();
  if (state.phase === "checking") {
    return (
      <div className="management-state" role="status">
        <Space orientation="vertical">
          <Spin />
          <span>{t("auth.checking")}</span>
        </Space>
      </div>
    );
  }
  if (state.phase === "error") {
    const httpsRequired = state.error?.kind === "https";
    return (
      <Result
        status="warning"
        title={t(httpsRequired ? "auth.httpsTitle" : "auth.unavailable")}
        subTitle={state.error ? t(errorMessage(state.error)) : undefined}
        extra={
          httpsRequired ? undefined : (
            <Button type="primary" onClick={() => void controller.check()}>
              {t("api.retry")}
            </Button>
          )
        }
      />
    );
  }
  if (state.phase === "anonymous") return <Login />;
  return (
    <Space orientation="vertical" size={16} className="full-width">
      {state.error && (
        <Alert
          type="error"
          showIcon
          title={t("auth.logoutUnconfirmed")}
          description={t(errorMessage(state.error))}
          action={
            <Button onClick={() => void controller.check()}>
              {t("auth.refreshSession")}
            </Button>
          }
        />
      )}
      {children}
    </Space>
  );
}
