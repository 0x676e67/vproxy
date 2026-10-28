import {
  MenuFoldOutlined,
  MenuOutlined,
  MenuUnfoldOutlined,
} from "@ant-design/icons";
import { Button } from "antd";
import { useMessages } from "../../hooks/useMessages";

/** Both placements must bind ProLayout's collapse action explicitly. */
export default function NavigationToggle({
  collapsed,
  className,
  onClick,
  sidebar = false,
}: {
  collapsed: boolean;
  className?: string;
  onClick: () => void;
  sidebar?: boolean;
}) {
  const { t } = useMessages();
  const label = t(
    sidebar
      ? collapsed
        ? "layout.expandNavigation"
        : "layout.collapseNavigation"
      : collapsed
        ? "layout.openNavigation"
        : "layout.closeNavigation",
  );
  return (
    <Button
      type="text"
      className={[
        "management-header-action",
        sidebar && "management-sidebar-toggle",
        className,
      ]
        .filter(Boolean)
        .join(" ")}
      onClick={onClick}
      aria-label={label}
      aria-expanded={!collapsed}
      title={label}
      icon={
        sidebar ? (
          collapsed ? (
            <MenuUnfoldOutlined aria-hidden />
          ) : (
            <MenuFoldOutlined aria-hidden />
          )
        ) : (
          <MenuOutlined aria-hidden />
        )
      }
    >
      {sidebar && !collapsed ? label : null}
    </Button>
  );
}
