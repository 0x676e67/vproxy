import type { RunTimeLayoutConfig, RuntimeAntdConfig } from "@umijs/max";
import type { ReactNode } from "react";
import { ManagementProvider } from "./auth/context";
import AccountActions from "./components/AccountActions";
import AlertInbox from "./components/AlertInbox";
import HeaderTools from "./components/HeaderTools";
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
    className: "management-layout",
    siderWidth: 256,
    headerTitleRender: false,
    logoStyle: {
      height: 56,
      paddingBlock: 12,
      justifyContent: "center",
      cursor: "default",
    },
    menuHeaderRender: (_logo, _title, props) =>
      // The mobile header also calls this renderer, without rail props.
      props ? (
        <span className="management-brand" aria-label="vproxy">
          {props.collapsed && !props.isMobile ? "v" : "vproxy"}
        </span>
      ) : null,
    // The wordmark is identity, not an unlabelled, mouse-only home action.
    onMenuHeaderClick: undefined,
    // Keep navigation controls in the header rather than among destinations.
    collapsedButtonRender: false,
    menuExtraRender: false,
    // ProLayout 3.1.14's mobile GlobalHeader ignores collapsedButtonRender.
    // Keep its header/actions but replace its inaccessible span toggle.
    headerContentRender: (props) => (
      <NavigationToggle
        className={props.isMobile ? "management-mobile-navigation" : undefined}
        isMobile={Boolean(props.isMobile)}
        collapsed={Boolean(props.collapsed)}
        onClick={() => props.onCollapse?.(!props.collapsed)}
      />
    ),
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
        colorMenuBackground: consolePalette.sidebar,
        colorTextMenu: consolePalette.sidebarText,
        colorTextMenuSecondary: consolePalette.sidebarText,
        colorTextMenuItemHover: consolePalette.sidebarText,
        colorTextMenuSelected: consolePalette.sidebarAccent,
        colorBgMenuItemHover: consolePalette.sidebarHover,
        colorBgMenuItemSelected: consolePalette.sidebarSelected,
      },
      pageContainer: {
        paddingInlinePageContainerContent: 24,
        paddingBlockPageContainerContent: 24,
      },
    },
    actionsRender: (props) => [
      <HeaderTools key="tools" compact={Boolean(props.isMobile)} />,
      ...(__VPROXY_DEMO__ ? [] : [<AlertInbox key="alerts" />]),
      ...(__VPROXY_DEMO__ ? [] : [<AccountActions key="account" />]),
    ],
    footerRender: false,
    childrenRender: (children) => <PageScrollReset>{children}</PageScrollReset>,
    rightContentRender: false,
    menu: { locale: true, collapsedWidth: 64 },
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
