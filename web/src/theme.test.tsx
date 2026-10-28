// @vitest-environment jsdom
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { theme, type ConfigProviderProps } from "antd";
import { consolePalettes, consoleTagTokens } from "../config/theme";
import ThemeSwitch from "./components/ThemeSwitch";
import {
  applyConsoleMode,
  ConsoleThemeProvider,
  consoleTheme,
  readConsoleMode,
  THEME_STORAGE_KEY,
} from "./theme";

const { setter } = vi.hoisted(() => ({ setter: vi.fn() }));
vi.mock("@umijs/max", () => ({ useAntdConfigSetter: () => setter }));
vi.mock("./hooks/useMessages", () => ({
  useMessages: () => ({
    t: (key: string) =>
      ({
        "theme.title": "Theme",
        "theme.current": "Current theme",
        "theme.light": "Light",
        "theme.dark": "Dark",
      })[key] ?? key,
  }),
}));

let config: ConfigProviderProps;
beforeEach(() => {
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  config = {};
  setter.mockImplementation(
    (update: (previous: ConfigProviderProps) => ConfigProviderProps) => {
      config = update(config);
    },
  );
  document.head.innerHTML = '<meta name="theme-color" content="#f5f5f5">';
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  setter.mockClear();
  document.documentElement.removeAttribute("style");
  delete document.documentElement.dataset.consoleTheme;
});

it("starts light, accepts only the two preferences and tolerates inaccessible storage", () => {
  expect(readConsoleMode()).toBe("light");
  window.localStorage.setItem(THEME_STORAGE_KEY, "dark");
  expect(readConsoleMode()).toBe("dark");
  window.localStorage.setItem(THEME_STORAGE_KEY, "system");
  expect(readConsoleMode()).toBe("light");
  vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
    throw new DOMException("Blocked", "SecurityError");
  });
  expect(readConsoleMode()).toBe("light");
});

it("switches in place, retains a draft and restores the preference after a fresh mount", async () => {
  const view = render(
    <ConsoleThemeProvider>
      <ThemeSwitch />
      <input aria-label="Draft" />
    </ConsoleThemeProvider>,
  );
  const input = screen.getByRole("textbox", { name: "Draft" });
  fireEvent.change(input, { target: { value: "unsaved configuration" } });
  expect(document.documentElement.dataset.consoleTheme).toBe("light");
  fireEvent.click(screen.getByRole("button", { name: "Theme: Light" }));
  const menu = await screen.findByRole("menu", { name: "Theme" });
  expect(within(menu).getByRole("img", { name: "Current theme" })).toBeTruthy();
  fireEvent.click(within(menu).getByRole("menuitem", { name: "Dark" }));
  expect(
    await screen.findByRole("button", { name: "Theme: Dark" }),
  ).toBeTruthy();
  expect(screen.getByRole("textbox", { name: "Draft" })).toBe(input);
  expect((input as HTMLInputElement).value).toBe("unsaved configuration");
  expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
  expect(document.documentElement.style.colorScheme).toBe("dark");
  expect(
    document.querySelector('meta[name="theme-color"]')?.getAttribute("content"),
  ).toBe(consolePalettes.dark.canvas);
  expect(config.theme?.algorithm).toBe(theme.darkAlgorithm);
  expect(config.theme?.components?.Button?.primaryColor).toBe(
    consolePalettes.dark.onAccent,
  );
  view.unmount();
  render(
    <ConsoleThemeProvider>
      <ThemeSwitch />
    </ConsoleThemeProvider>,
  );
  expect(screen.getByRole("button", { name: "Theme: Dark" })).toBeTruthy();
});

it("changes theme even when preference writes are denied and syncs only local theme changes", async () => {
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
    throw new DOMException("Full", "QuotaExceededError");
  });
  render(
    <ConsoleThemeProvider>
      <ThemeSwitch />
    </ConsoleThemeProvider>,
  );
  fireEvent.click(screen.getByRole("button", { name: "Theme: Light" }));
  fireEvent.click(
    within(await screen.findByRole("menu", { name: "Theme" })).getByRole(
      "menuitem",
      { name: "Dark" },
    ),
  );
  expect(
    await screen.findByRole("button", { name: "Theme: Dark" }),
  ).toBeTruthy();
  act(() =>
    window.dispatchEvent(
      new StorageEvent("storage", {
        key: THEME_STORAGE_KEY,
        storageArea: window.sessionStorage,
      }),
    ),
  );
  expect(document.documentElement.dataset.consoleTheme).toBe("dark");
  act(() =>
    window.dispatchEvent(
      new StorageEvent("storage", {
        key: "unrelated",
        storageArea: window.localStorage,
      }),
    ),
  );
  expect(document.documentElement.dataset.consoleTheme).toBe("dark");
  act(() =>
    window.dispatchEvent(
      new StorageEvent("storage", {
        key: null,
        storageArea: window.localStorage,
      }),
    ),
  );
  expect(document.documentElement.dataset.consoleTheme).toBe("light");
  expect(config.theme?.algorithm).toBe(theme.defaultAlgorithm);
  expect(config.theme?.components?.Button?.primaryColor).toBe(
    consolePalettes.light.onAccent,
  );
  expect(
    document.documentElement.style.getPropertyValue("--console-selection"),
  ).toBe(consolePalettes.light.selection);
});

function luminance(hex: string) {
  const rgb = hex
    .replace("#", "")
    .match(/../g)!
    .map((pair) => {
      const value = Number.parseInt(pair, 16) / 255;
      return value <= 0.04045
        ? value / 12.92
        : ((value + 0.055) / 1.055) ** 2.4;
    });
  return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
}
function contrast(a: string, b: string) {
  const values = [luminance(a), luminance(b)].sort((x, y) => x - y);
  return (values[1] + 0.05) / (values[0] + 0.05);
}

it.each(["light", "dark"] as const)(
  "keeps %s text, selection, action states and controls legible",
  (mode) => {
    const palette = consolePalettes[mode],
      tokens = theme.getDesignToken(consoleTheme(mode));
    for (const background of [
      palette.canvas,
      palette.surface,
      palette.elevated,
    ]) {
      for (const text of [
        tokens.colorText,
        tokens.colorTextSecondary,
        tokens.colorTextDescription,
        tokens.colorTextTertiary,
        tokens.colorTextLabel,
        tokens.colorTextPlaceholder,
        tokens.colorLink,
        tokens.colorLinkHover,
        tokens.colorLinkActive,
      ]) {
        expect(
          contrast(text, background),
          `${mode}: ${text} on ${background}`,
        ).toBeGreaterThanOrEqual(4.5);
      }
      expect(contrast(tokens.colorBorder, background)).toBeGreaterThanOrEqual(
        3,
      );
    }
    for (const background of [
      tokens.colorPrimary,
      tokens.colorPrimaryHover,
      tokens.colorPrimaryActive,
    ]) {
      expect(
        contrast(palette.onAccent, background),
        `${mode} action: ${background}`,
      ).toBeGreaterThanOrEqual(4.5);
    }
    expect(contrast(palette.accent, palette.selected)).toBeGreaterThanOrEqual(
      4.5,
    );
    expect(
      contrast(palette.onSelection, palette.selection),
    ).toBeGreaterThanOrEqual(4.5);
    const tag = consoleTagTokens[mode];
    for (const [foreground, background] of [
      [tag.green7, tokens.green1],
      [tag.gold7, tokens.gold1],
      [tag.orange7, tokens.orange1],
      [tag.colorSuccess, tokens.colorSuccessBg],
      [tag.colorWarning, tokens.colorWarningBg],
      [tag.colorError, tokens.colorErrorBg],
      [tag.colorInfo, tokens.colorInfoBg],
    ]) {
      expect(
        contrast(foreground, background),
        `${mode} status: ${foreground} on ${background}`,
      ).toBeGreaterThanOrEqual(4.5);
    }
    expect(consoleTheme(mode).components?.Tag).toMatchObject(tag);
    expect(consoleTheme(mode).components?.Form).toMatchObject({
      colorError: tag.colorError,
      colorWarning: tag.colorWarning,
    });
    for (const text of [tag.colorError, tag.colorWarning]) {
      for (const background of [
        palette.canvas,
        palette.surface,
        palette.elevated,
      ]) {
        expect(
          contrast(text, background),
          `${mode} validation: ${text} on ${background}`,
        ).toBeGreaterThanOrEqual(4.5);
      }
    }
    applyConsoleMode(mode);
    expect(
      document.documentElement.style.getPropertyValue("--console-canvas"),
    ).toBe(palette.canvas);
  },
);
