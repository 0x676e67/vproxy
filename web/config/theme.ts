export type ConsoleMode = "light" | "dark";

// mdBook Rust's warm ground and brown rail; Ayu remains the dark alternative.
// Status colors remain Ant Design semantics, not additional brand accents.
export const consolePalettes = {
  light: {
    canvas: "#e1e1db",
    surface: "#eeeee8",
    elevated: "#f6f6f0",
    text: "#262625",
    secondary: "#626259",
    accent: "#9b4500",
    onAccent: "#ffffff",
    // The guide's #2b79a2 is below 4.5:1 on its warm ground at UI text sizes.
    link: "#246787",
    linkHover: "#1b4d66",
    linkActive: "#1b4d66",
    border: "#7c7c71",
    separator: "#c8c8bf",
    selected: "#e7d8c7",
    selection: "#e6c19c",
    onSelection: "#262625",
    sidebar: "#3b2e2a",
    sidebarText: "#c8c9db",
    sidebarAccent: "#e69f67",
    sidebarSelected: "#4b3a31",
    sidebarHover: "#493c36",
  },
  dark: {
    canvas: "#0f1419",
    surface: "#14191f",
    elevated: "#191f26",
    text: "#c5c5c5",
    secondary: "#a7b1bc",
    accent: "#ffb454",
    onAccent: "#0f1419",
    link: "#59c2e6",
    linkHover: "#84d3ec",
    linkActive: "#59c2e6",
    border: "#657380",
    separator: "#303b46",
    selected: "#191f26",
    selection: "#ffb454",
    onSelection: "#0f1419",
    sidebar: "#14191f",
    sidebarText: "#c5c5c5",
    sidebarAccent: "#ffb454",
    sidebarSelected: "#191f26",
    sidebarHover: "#191f26",
  },
} satisfies Record<ConsoleMode, Record<string, string>>;

export const consolePalette = consolePalettes.light;

// Keep Ant Design's status hues, but use legible text on their light fills.
// These are component-level Tag overrides, not a second global brand palette.
export const consoleTagTokens = {
  light: {
    green7: "#237804",
    gold7: "#874d00",
    orange7: "#ad4e00",
    colorSuccess: "#237804",
    colorWarning: "#874d00",
    colorError: "#a8071a",
    colorInfo: "#0958d9",
  },
  dark: {
    green7: "#95de64",
    gold7: "#ffd666",
    orange7: "#ffc069",
    colorSuccess: "#95de64",
    colorWarning: "#ffd666",
    colorError: "#ff7875",
    colorInfo: "#69b1ff",
  },
};

export function consoleTokens(mode: ConsoleMode = "light") {
  const palette = consolePalettes[mode];
  return {
    colorPrimary: palette.accent,
    colorLink: palette.link,
    colorLinkHover: palette.linkHover,
    colorLinkActive: palette.linkActive,
    colorBgBase: palette.canvas,
    colorBgLayout: palette.canvas,
    colorBgContainer: palette.surface,
    colorBgElevated: palette.elevated,
    colorTextBase: palette.text,
    colorText: palette.text,
    colorTextSecondary: palette.secondary,
    colorTextDescription: palette.secondary,
    colorTextTertiary: palette.secondary,
    colorTextLabel: palette.text,
    colorTextPlaceholder: palette.secondary,
    colorBorder: palette.border,
    colorBorderSecondary: palette.separator,
    borderRadius: 6,
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  };
}
