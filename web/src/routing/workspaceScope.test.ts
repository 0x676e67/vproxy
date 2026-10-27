import { createElement } from "react";
import { renderToString } from "react-dom/server";
import { StaticRouter } from "react-router-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import UsersPage from "../pages/Users";
import ResourcesPage from "../pages/Resources";
import TrafficPage from "../pages/Traffic";
import AlertsPage from "../pages/Alerts";

const management = vi.hoisted(() =>
  vi.fn(() => {
    throw new Error("management workspace mounted");
  }),
);
vi.mock("../auth/context", () => ({ useManagement: management }));
vi.mock("../hooks/useMessages", () => ({
  useMessages: () => ({ t: (id: string) => id }),
}));
vi.mock("@umijs/max", async () => {
  const router = await import("react-router");
  const dom = await import("react-router-dom");
  return {
    history: { action: "POP" },
    Link: dom.Link,
    useLocation: router.useLocation,
    useNavigate: router.useNavigate,
  };
});
afterEach(() => management.mockClear());
afterEach(() => vi.unstubAllGlobals());

describe("invalid URL scope workspace boundary", () => {
  it("does not mount Users, Resources or Traffic management work for rejected queries", () => {
    for (const [pathname, Page] of [
      ["/users", UsersPage],
      ["/resources", ResourcesPage],
      ["/traffic", TrafficPage],
      ["/alerts", AlertsPage],
    ] as const) {
      for (const search of [
        "?target=",
        "?target=A&target=A",
        "?unknown=",
        "?address=",
      ]) {
        const html = renderToString(
          createElement(
            StaticRouter,
            { location: pathname + search },
            createElement(Page),
          ),
        );
        expect(html).toContain("control.invalidScope");
        expect(html).toContain('href="/nodes"');
        expect(management).not.toHaveBeenCalled();
      }
      // The guard is real: a valid location proceeds to the protected workspace.
      vi.stubGlobal("__VPROXY_DEMO__", false);
      expect(() =>
        renderToString(
          createElement(
            StaticRouter,
            { location: pathname },
            createElement(Page),
          ),
        ),
      ).toThrow("management workspace mounted");
      expect(management).toHaveBeenCalled();
      management.mockClear();
    }
  });
});
