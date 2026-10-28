import { CheckOutlined, MoonOutlined, SunOutlined } from "@ant-design/icons";
import { Button, Dropdown } from "antd";
import { useMessages } from "../../hooks/useMessages";
import { useConsoleTheme } from "../../theme";

export default function ThemeSwitch() {
  const { mode, select } = useConsoleTheme();
  const { t } = useMessages();
  const label = `${t("theme.title")}: ${t(`theme.${mode}`)}`;
  return (
    <Dropdown
      trigger={["click"]}
      autoFocus
      menu={{
        "aria-label": t("theme.title"),
        selectable: true,
        selectedKeys: [mode],
        items: [
          {
            key: "light",
            label: t("theme.light"),
            icon: <SunOutlined aria-hidden />,
            extra:
              mode === "light" ? (
                <CheckOutlined aria-label={t("theme.current")} />
              ) : null,
          },
          {
            key: "dark",
            label: t("theme.dark"),
            icon: <MoonOutlined aria-hidden />,
            extra:
              mode === "dark" ? (
                <CheckOutlined aria-label={t("theme.current")} />
              ) : null,
          },
        ],
        onClick: ({ key }) => {
          if (key === "light" || key === "dark") select(key);
        },
      }}
    >
      <Button
        type="text"
        className="management-header-action"
        icon={
          mode === "light" ? (
            <SunOutlined aria-hidden />
          ) : (
            <MoonOutlined aria-hidden />
          )
        }
        aria-label={label}
        aria-haspopup="menu"
        title={label}
      />
    </Dropdown>
  );
}
