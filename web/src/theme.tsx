import { useAntdConfigSetter } from "@umijs/max";
import { theme, type ThemeConfig } from "antd";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  consolePalettes,
  consoleTagTokens,
  consoleTokens,
  type ConsoleMode,
} from "../config/theme";

export const THEME_STORAGE_KEY = "vproxy.console.theme";

/** A missing, invalid or unavailable browser preference always starts light. */
export function readConsoleMode(): ConsoleMode {
  try {
    return window.localStorage.getItem(THEME_STORAGE_KEY) === "dark"
      ? "dark"
      : "light";
  } catch {
    return "light";
  }
}

export function consoleTheme(
  mode: ConsoleMode,
  previous: ThemeConfig = {},
): ThemeConfig {
  const palette = consolePalettes[mode];
  return {
    ...previous,
    algorithm: mode === "dark" ? theme.darkAlgorithm : theme.defaultAlgorithm,
    cssVar: previous.cssVar || {},
    token: { ...previous.token, ...consoleTokens(mode) },
    components: {
      ...previous.components,
      Button: {
        ...previous.components?.Button,
        primaryColor: palette.onAccent,
      },
      Checkbox: {
        ...previous.components?.Checkbox,
        colorWhite: palette.onAccent,
      },
      Tag: {
        ...previous.components?.Tag,
        ...consoleTagTokens[mode],
      },
      Menu: {
        ...previous.components?.Menu,
        itemColor: palette.text,
        itemHoverColor: palette.text,
        itemSelectedBg: palette.selected,
        itemSelectedColor: palette.accent,
        darkItemColor: palette.text,
        darkItemHoverColor: palette.text,
        darkItemSelectedBg: palette.selected,
        darkItemSelectedColor: palette.accent,
      },
    },
  };
}

/** Keep native controls and the page canvas in sync with Ant Design's portals. */
export function applyConsoleMode(mode: ConsoleMode) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.dataset.consoleTheme = mode;
  root.style.colorScheme = mode;
  for (const [name, value] of Object.entries(consolePalettes[mode])) {
    root.style.setProperty(`--console-${name}`, value);
  }
  document
    .querySelector('meta[name="theme-color"]')
    ?.setAttribute("content", consolePalettes[mode].canvas);
}

const ConsoleThemeContext = createContext<{
  mode: ConsoleMode;
  select: (mode: ConsoleMode) => void;
} | null>(null);

export function ConsoleThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState(readConsoleMode);
  const setAntdConfig = useAntdConfigSetter();
  // Umi creates its setter on each provider render. Depending on that identity
  // would repeatedly update the provider; only a mode change should do so.
  const setter = useRef(setAntdConfig);
  setter.current = setAntdConfig;
  useLayoutEffect(() => {
    applyConsoleMode(mode);
    setter.current((previous) => ({
      ...previous,
      theme: consoleTheme(mode, previous.theme),
    }));
  }, [mode]);
  useEffect(() => {
    const sync = (event: StorageEvent) => {
      if (event.key !== null && event.key !== THEME_STORAGE_KEY) return;
      try {
        if (event.storageArea && event.storageArea !== window.localStorage)
          return;
        setMode(readConsoleMode());
      } catch {
        // Storage being blocked must not disable the current tab's controls.
      }
    };
    window.addEventListener("storage", sync);
    return () => window.removeEventListener("storage", sync);
  }, []);
  const select = useCallback((next: ConsoleMode) => {
    setMode(next);
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // Theme choice is cosmetic; an unavailable preference store is not fatal.
    }
  }, []);
  const value = useMemo(() => ({ mode, select }), [mode, select]);
  return (
    <ConsoleThemeContext.Provider value={value}>
      {children}
    </ConsoleThemeContext.Provider>
  );
}

export function useConsoleTheme() {
  const value = useContext(ConsoleThemeContext);
  if (!value) throw new Error("Console theme provider is missing");
  return value;
}
