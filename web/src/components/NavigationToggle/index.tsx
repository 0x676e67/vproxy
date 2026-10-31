import {
  MenuFoldOutlined,
  MenuOutlined,
  MenuUnfoldOutlined,
} from "@ant-design/icons";
import { Button } from "antd";
import { useMessages } from "../../hooks/useMessages";

/** One header control binds ProLayout's desktop rail or mobile drawer action. */
export default function NavigationToggle({
  collapsed,
  className,
  onClick,
  isMobile = false,
}: {
  collapsed: boolean;
  className?: string;
  onClick: () => void;
  isMobile?: boolean;
}) {
  const { t } = useMessages();
  const label = t(
    !isMobile
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
      className={["management-header-action", className]
        .filter(Boolean)
        .join(" ")}
      onClick={onClick}
      aria-label={label}
      aria-expanded={!collapsed}
      title={label}
      icon={
        !isMobile ? (
          collapsed ? (
            <MenuUnfoldOutlined aria-hidden />
          ) : (
            <MenuFoldOutlined aria-hidden />
          )
        ) : (
          <MenuOutlined aria-hidden />
        )
      }
    />
  );
}
