import { KeyOutlined, LogoutOutlined, UserOutlined } from "@ant-design/icons";
import { Button, Dropdown } from "antd";
import { lazy, Suspense, useState } from "react";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";
const PasswordDialog = lazy(() => import("../PasswordDialog"));

export default function AccountActions() {
  const { controller, state } = useManagement();
  const { t } = useMessages();
  const [passwordOpen, setPasswordOpen] = useState(false);
  if (state.phase !== "authenticated" || !state.session) return null;
  const username = state.session.administrator.username;
  const label = t("auth.accountMenu", { username });
  return (
    <>
      <Dropdown
        trigger={["click"]}
        autoFocus
        disabled={state.busy}
        menu={{
          "aria-label": label,
          items: [
            {
              key: "password",
              icon: <KeyOutlined aria-hidden />,
              label: t("account.password.title"),
              disabled: state.busy,
            },
            {
              key: "signOut",
              icon: <LogoutOutlined aria-hidden />,
              label: t("auth.signOut"),
              disabled: state.busy,
            },
          ],
          onClick: ({ key }) => {
            if (key === "password") setPasswordOpen(true);
            if (key === "signOut") void controller.logout();
          },
        }}
      >
        <Button
          className="management-header-action management-account"
          type="text"
          icon={<UserOutlined aria-hidden />}
          aria-label={label}
          aria-haspopup="menu"
          title={label}
          loading={state.busy}
          disabled={state.busy}
        >
          <span className="management-account-name">{username}</span>
        </Button>
      </Dropdown>
      {passwordOpen && (
        <Suspense fallback={null}>
          <PasswordDialog
            session={state.session}
            close={() => setPasswordOpen(false)}
          />
        </Suspense>
      )}
    </>
  );
}
