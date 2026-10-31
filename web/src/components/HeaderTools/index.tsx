import { GithubOutlined, MoreOutlined } from "@ant-design/icons";
import { Button, Dropdown } from "antd";
import { useMessages } from "../../hooks/useMessages";
import LanguageSwitch, { useLanguageMenu } from "../LanguageSwitch";
import ProjectLink from "../ProjectLink";
import ThemeSwitch, { useThemeMenu } from "../ThemeSwitch";

function CompactTools() {
  const { t } = useMessages();
  const theme = useThemeMenu();
  const language = useLanguageMenu();
  const label = t("app.tools");
  return (
    <Dropdown
      trigger={["click"]}
      autoFocus
      menu={{
        "aria-label": label,
        selectable: true,
        selectedKeys: [theme.mode, language.locale],
        items: [
          {
            key: "project",
            label: <ProjectLink compact />,
            icon: <GithubOutlined aria-hidden />,
          },
          { type: "divider" },
          {
            type: "group",
            key: "theme",
            label: t("theme.title"),
            children: theme.menu.items,
          },
          {
            type: "group",
            key: "language",
            label: language.label,
            children: language.menu.items,
          },
        ],
        onClick: (info) => {
          theme.menu.onClick(info);
          language.menu.onClick(info);
        },
      }}
    >
      <Button
        type="text"
        className="management-header-action"
        icon={<MoreOutlined aria-hidden />}
        aria-label={label}
        aria-haspopup="menu"
        title={label}
      />
    </Dropdown>
  );
}

/** Keep low-frequency preferences out of the primary mobile action row. */
export default function HeaderTools({ compact }: { compact: boolean }) {
  const { t } = useMessages();
  if (compact) return <CompactTools />;
  return (
    <div
      className="management-header-tools"
      role="group"
      aria-label={t("app.tools")}
    >
      <ProjectLink />
      <ThemeSwitch />
      <LanguageSwitch />
    </div>
  );
}
