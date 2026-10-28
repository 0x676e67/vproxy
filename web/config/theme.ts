export type ConsoleMode = "light" | "dark";

// rustdoc Light/Ayu surface roles, with a rust-colored action in the light theme.
// Status colors remain Ant Design semantics, not additional brand accents.
export const consolePalettes = {
  light: {
    canvas: "#f5f5f5",
    surface: "#ffffff",
    elevated: "#ffffff",
    text: "#353535",
    secondary: "#646464",
    accent: "#9b4500",
    onAccent: "#ffffff",
    link: "#3873ad",
    linkHover: "#254e78",
    linkActive: "#254e78",
    border: "#858585",
    separator: "#e0e0e0",
    selected: "#fff0df",
    selection: "#ffdfb5",
    onSelection: "#353535",
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
