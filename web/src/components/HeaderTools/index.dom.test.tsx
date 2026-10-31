// @vitest-environment jsdom
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ConsoleThemeProvider, THEME_STORAGE_KEY } from "../../theme";
import en from "../../locales/en-US";
import zh from "../../locales/zh-CN";
import HeaderTools from ".";

const fixture = vi.hoisted(() => ({ locale: "en-US", setLocale: vi.fn() }));
vi.mock("@umijs/max", () => ({
  getLocale: () => fixture.locale,
  setLocale: fixture.setLocale,
  useAntdConfigSetter: () => () => {},
  useIntl: () => ({
    formatMessage: ({ id }: { id: keyof typeof en }) =>
      (fixture.locale === "zh-CN" ? zh : en)[id],
  }),
}));
vi.mock("../../hooks/useMessages", () => ({
  useMessages: () => ({
    t: (id: keyof typeof en) => (fixture.locale === "zh-CN" ? zh : en)[id],
  }),
}));
beforeEach(() => {
  fixture.setLocale.mockReset();
  window.localStorage.clear();
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("orders desktop tools as project, theme and language without an overflow trigger", () => {
  fixture.locale = "en-US";
  render(
    <ConsoleThemeProvider>
      <HeaderTools compact={false} />
    </ConsoleThemeProvider>,
  );
  const group = screen.getByRole("group", { name: "Tools" });
  expect(
    Array.from(group.querySelectorAll("a,button")).map((element) =>
      element.getAttribute("aria-label"),
    ),
  ).toEqual([
    "GitHub repository",
    "Theme: Light",
    "Interface language: English",
  ]);
  expect(screen.queryByRole("button", { name: "Tools" })).toBeNull();
});

it.each(["en-US", "zh-CN"])(
  "keeps compact tools usable without nested menus or losing a draft (%s)",
  async (locale) => {
    fixture.locale = locale;
    const messages = locale === "zh-CN" ? zh : en;
    const view = () => (
      <ConsoleThemeProvider>
        <HeaderTools compact />
        <input aria-label="Draft" defaultValue="unsaved settings" />
      </ConsoleThemeProvider>
    );
    const rendered = render(view());
    const draft = screen.getByRole("textbox", { name: "Draft" });
    expect(screen.getAllByRole("button")).toHaveLength(1);
    fireEvent.click(
      screen.getByRole("button", { name: messages["app.tools"] }),
    );
    let menu = await screen.findByRole("menu", { name: messages["app.tools"] });
    const project = within(menu).getByRole("link", {
      name: messages["app.projectRepository"],
    });
    expect(project.getAttribute("href")).toBe(
      "https://github.com/0x676e67/vproxy",
    );
    expect(project.getAttribute("rel")).toBe("noopener noreferrer");
    expect(within(menu).queryByRole("button")).toBeNull();
    fireEvent.click(
      within(menu).getByRole("menuitem", { name: messages["theme.dark"] }),
    );
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    expect(fixture.setLocale).not.toHaveBeenCalled();
    expect(screen.getByRole("textbox", { name: "Draft" })).toBe(draft);
    fireEvent.click(
      screen.getByRole("button", { name: messages["app.tools"] }),
    );
    menu = await screen.findByRole("menu", { name: messages["app.tools"] });
    const next = locale === "zh-CN" ? "en-US" : "zh-CN";
    fireEvent.click(
      within(menu).getByRole("menuitem", {
        name: next === "en-US" ? "English" : "简体中文",
      }),
    );
    expect(fixture.setLocale).toHaveBeenCalledExactlyOnceWith(next, false);
    fixture.locale = next;
    rendered.rerender(view());
    expect(document.documentElement.lang).toBe(next);
    expect(screen.getByRole("textbox", { name: "Draft" })).toBe(draft);
    expect((draft as HTMLInputElement).value).toBe("unsaved settings");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
  },
);
