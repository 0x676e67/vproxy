// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { layout } from "./app";
import { ConsoleThemeProvider } from "./theme";
import messages from "./locales/en-US";

vi.mock("@umijs/max", () => ({
  useAntdConfigSetter: () => () => {},
  Link: () => null,
  useIntl: vi.fn(),
  useLocation: vi.fn(),
  useNavigate: vi.fn(),
}));
vi.mock("./hooks/useMessages", () => ({
  useMessages: () => ({
    t: (key: keyof typeof messages) => messages[key],
  }),
}));

beforeEach(() => vi.stubGlobal("__VPROXY_DEMO__", false));
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it.each([false, true])(
  "binds the actual layout's navigation action in place (mobile=%s)",
  (mobile) => {
    function Harness() {
      const config = layout({});
      const [collapsed, setCollapsed] = useState(mobile);
      const props = {
        collapsed,
        isMobile: mobile,
        onCollapse: setCollapsed,
      };
      expect(config.collapsedButtonRender).toBe(false);
      const sidebar =
        typeof config.menuExtraRender === "function"
          ? config.menuExtraRender(props)
          : null;
      const header =
        typeof config.headerContentRender === "function"
          ? config.headerContentRender(props, null)
          : null;
      return (
        <>
          <input aria-label="Draft" defaultValue="unsaved settings" />
          {sidebar}
          {header}
        </>
      );
    }
    render(
      <ConsoleThemeProvider>
        <Harness />
      </ConsoleThemeProvider>,
    );
    const before =
      messages[mobile ? "layout.openNavigation" : "layout.collapseNavigation"];
    const after =
      messages[mobile ? "layout.closeNavigation" : "layout.expandNavigation"];
    const draft = screen.getByRole("textbox", { name: "Draft" });
    expect(screen.getAllByRole("button")).toHaveLength(1);
    const button = screen.getByRole("button", { name: before });
    expect(button.getAttribute("aria-expanded")).toBe(String(!mobile));
    fireEvent.click(button);
    const changed = screen.getByRole("button", { name: after });
    expect(changed.getAttribute("aria-expanded")).toBe(String(mobile));
    expect(screen.getByRole("textbox", { name: "Draft" })).toBe(draft);
    expect((draft as HTMLInputElement).value).toBe("unsaved settings");
    fireEvent.click(changed);
    expect(screen.getByRole("button", { name: before })).toBe(button);
  },
);
