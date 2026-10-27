import type { RunTimeLayoutConfig, RuntimeAntdConfig } from "@umijs/max";
import { theme } from "antd";
import type { ReactNode } from "react";
import { ManagementProvider } from "./auth/context";
import AccountActions from "./components/AccountActions";
import LanguageSwitch from "./components/LanguageSwitch";
import AlertInbox from "./components/AlertInbox";
import ProjectLink from "./components/ProjectLink";
import ManagementShell from "./components/ManagementShell";
import ManagementBoundary from "./components/ManagementBoundary";
import { ScopeMenuLink } from "./routing/ScopeNavigation";
import defaultSettings from "../config/defaultSettings";

export const antd: RuntimeAntdConfig = (memo) => ({
  ...memo,
  theme: { ...memo.theme, algorithm: theme.darkAlgorithm, cssVar: {} },
});

// Umi's locale provider wraps innerProvider; rootContainer sits outside Intl.
export function innerProvider(container: ReactNode) {
  return __VPROXY_DEMO__ ? (
    container
  ) : (
    <ManagementProvider>
      <ManagementBoundary>
        <ManagementShell>{container}</ManagementShell>
      </ManagementBoundary>
    </ManagementProvider>
  );
}

export const layout: RunTimeLayoutConfig = () => ({
  ...defaultSettings,
  logo: false,
  actionsRender: () => [
    ...(__VPROXY_DEMO__ ? [] : [<AlertInbox key="alerts" />]),
    ...(__VPROXY_DEMO__ ? [] : [<AccountActions key="account" />]),
    <ProjectLink key="project" />,
    <LanguageSwitch key="language" />,
  ],
  footerRender: false,
  rightContentRender: false,
  menu: { locale: true },
  menuItemRender: (item, dom) => (
    <ScopeMenuLink path={item.path}>{dom}</ScopeMenuLink>
  ),
});
