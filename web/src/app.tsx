import type { RunTimeLayoutConfig, RuntimeAntdConfig } from "@umijs/max";
import type { ReactNode } from "react";
import { ManagementProvider } from "./auth/context";
import AccountActions from "./components/AccountActions";
import LanguageSwitch from "./components/LanguageSwitch";
import AlertInbox from "./components/AlertInbox";
import ProjectLink from "./components/ProjectLink";
import ThemeSwitch from "./components/ThemeSwitch";
import NavigationToggle from "./components/NavigationToggle";
import ManagementShell from "./components/ManagementShell";
import ManagementBoundary from "./components/ManagementBoundary";
import { PageScrollReset, ScopeMenuLink } from "./routing/ScopeNavigation";
import defaultSettings from "../config/defaultSettings";
import { consolePalettes } from "../config/theme";
import {
  applyConsoleMode,
  consoleTheme,
  ConsoleThemeProvider,
  readConsoleMode,
  useConsoleTheme,
} from "./theme";

export const antd: RuntimeAntdConfig = (memo) => {
  const mode = readConsoleMode();
  applyConsoleMode(mode);
  return {
    ...memo,
    form: {
      ...memo.form,
      // Dialog bodies can scroll independently on short screens. Keep failed
      // validation at the offending field instead of stranding focus at Save.
      scrollToFirstError: memo.form?.scrollToFirstError ?? { focus: true },
    },
    theme: consoleTheme(mode, memo.theme),
  };
};

// Umi's locale provider wraps innerProvider; rootContainer sits outside Intl.
export function innerProvider(container: ReactNode) {
  return (
    <ConsoleThemeProvider>
      {__VPROXY_DEMO__ ? (
        container
      ) : (
        <ManagementProvider>
          <ManagementBoundary>
            <ManagementShell>{container}</ManagementShell>
          </ManagementBoundary>
        </ManagementProvider>
      )}
    </ConsoleThemeProvider>
  );
}

export const layout: RunTimeLayoutConfig = () => {
  const { mode } = useConsoleTheme();
  const consolePalette = consolePalettes[mode];
  return {
    ...defaultSettings,
    navTheme: mode === "dark" ? "realDark" : "light",
    colorPrimary: consolePalette.accent,
    logo: false,
    // A custom collapsedButtonRender replaces the default action; it is not
    // wrapped in ProLayout's click handler. Keep one explicit action at the top.
    collapsedButtonRender: false,
    menuExtraRender: (props) =>
      props.isMobile ? null : (
        <NavigationToggle
          sidebar
          collapsed={Boolean(props.collapsed)}
          onClick={() => props.onCollapse?.(!props.collapsed)}
        />
      ),
    // ProLayout 3.1.14's mobile GlobalHeader ignores collapsedButtonRender.
    // Keep its header/actions but replace its inaccessible span toggle.
    headerContentRender: (props) =>
      props.isMobile ? (
        <NavigationToggle
          className="management-mobile-navigation"
          collapsed={Boolean(props.collapsed)}
          onClick={() => props.onCollapse?.(!props.collapsed)}
        />
      ) : null,
    token: {
      bgLayout: consolePalette.canvas,
      header: {
        colorBgHeader: consolePalette.surface,
        colorTextMenu: consolePalette.text,
        colorTextMenuItemHover: consolePalette.text,
        colorTextMenuSelected: consolePalette.accent,
        colorBgMenuItemSelected: consolePalette.selected,
      },
      sider: {
        colorMenuBackground: consolePalette.surface,
        colorTextMenu: consolePalette.text,
        colorTextMenuItemHover: consolePalette.text,
        colorTextMenuSelected: consolePalette.accent,
        colorBgMenuItemSelected: consolePalette.selected,
      },
      pageContainer: {
        paddingInlinePageContainerContent: 24,
        paddingBlockPageContainerContent: 24,
      },
    },
    actionsRender: () => [
      ...(__VPROXY_DEMO__ ? [] : [<AlertInbox key="alerts" />]),
      ...(__VPROXY_DEMO__ ? [] : [<AccountActions key="account" />]),
      <ThemeSwitch key="theme" />,
      <ProjectLink key="project" />,
      <LanguageSwitch key="language" />,
    ],
    footerRender: false,
    childrenRender: (children) => <PageScrollReset>{children}</PageScrollReset>,
    rightContentRender: false,
    menu: { locale: true },
    menuItemRender: (item, dom) => (
      <ScopeMenuLink
        path={item.path}
        label={item.name}
        messageId={typeof item.locale === "string" ? item.locale : undefined}
        onNavigate={item.isMobile ? item.onClick : undefined}
      >
        {dom}
      </ScopeMenuLink>
    ),
  };
};
