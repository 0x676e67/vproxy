import { CheckOutlined, MoonOutlined, SunOutlined } from "@ant-design/icons";
import { Button, Dropdown, type MenuProps } from "antd";
import { useMessages } from "../../hooks/useMessages";
import { useConsoleTheme } from "../../theme";

/** Share the choices with the compact toolbar without nesting dropdowns. */
export function useThemeMenu() {
  const { mode, select } = useConsoleTheme();
  const { t } = useMessages();
  const label = `${t("theme.title")}: ${t(`theme.${mode}`)}`;
  return {
    mode,
    label,
    menu: {
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
    } satisfies MenuProps,
  };
}

export default function ThemeSwitch() {
  const { mode, label, menu } = useThemeMenu();
  return (
    <Dropdown trigger={["click"]} autoFocus menu={menu}>
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
