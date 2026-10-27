import { createElement } from "react";
import { renderToString } from "react-dom/server";
import { StaticRouter } from "react-router-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useLocation, useNavigate } from "@umijs/max";
import { ScopeMenuLink, useScopeNavigation } from "./ScopeNavigation";
import routes from "../../config/routes";

// Use the installed Router 7 context for links. Only the focused hook unit
// substitutes its two inputs; production continues to use Umi's one Router.
vi.mock("@umijs/max", async () => {
  const router = await import("react-router");
  const dom = await import("react-router-dom");
  return {
    Link: dom.Link,
    useLocation: vi.fn(router.useLocation),
    useNavigate: vi.fn(router.useNavigate),
  };
});
afterEach(() => vi.mocked(useLocation).mockReset());
afterEach(() => vi.mocked(useNavigate).mockReset());

const target = "A".repeat(22);

describe("scope-aware ProLayout navigation adapter", () => {
  it("renders same-context internal links and leaves ambiguous scope recovery global", async () => {
    const router = await import("react-router");
    vi.mocked(useLocation).mockImplementation(router.useLocation);
    const render = (location: string, path: string) =>
      renderToString(
        createElement(
          StaticRouter,
          { location },
          createElement(ScopeMenuLink, { path, children: "destination" }),
        ),
      );
    expect(render(`/users?target=${target}`, "/resources")).toContain(
      `href="/resources?target=${target}"`,
    );
    expect(render(`/resources?target=${target}`, "/traffic")).toContain(
      `href="/traffic?target=${target}"`,
    );
    expect(render(`/traffic?target=${target}`, "/nodes")).toContain(
      'href="/nodes"',
    );
    expect(render("/nodes", "/users")).toContain('href="/users"');
    for (const route of routes.filter((entry) => entry.name))
      expect(render("/nodes", route.path)).toContain(`href="${route.path}"`);
    expect(render(`/users?target=${target}`, "/service")).toContain(
      'href="/service"',
    );
    expect(
      render(`/alerts?view=history&target=${target}`, "/service"),
    ).toContain('href="/service"');
    expect(render("/service", "/users")).toContain('href="/users"');
    expect(render("/users?target=", "/users")).toContain(
      'aria-disabled="true"',
    );
    expect(render("/users?target=", "/resources")).not.toContain("href=");
    expect(render("/users?target=", "/service")).not.toContain("href=");
    expect(render("/users?target=", "/nodes")).toContain('href="/nodes"');
  });

  it("pushes only checked changed locations, not a replacement, request or saved last target", () => {
    const navigate = vi.fn();
    vi.mocked(useNavigate).mockReturnValue(navigate);
    vi.mocked(useLocation).mockReturnValue({
      pathname: "/users",
      search: `?target=${target}`,
      hash: "",
      state: null,
      key: "fixture",
    });
    const select = useScopeNavigation();
    select(`/users?target=${target}`);
    expect(navigate).not.toHaveBeenCalled();
    select("/users");
    expect(navigate).toHaveBeenLastCalledWith("/users");
    expect(() => select("/users?target=")).toThrow();
    expect(() => select("https://outside.invalid")).toThrow();
    expect(navigate).toHaveBeenCalledTimes(1);
  });

  it("preserves a navigation rejection for callers without treating dispatch as commit", async () => {
    const failure = new Error("navigation rejected");
    const navigate = vi.fn(() => Promise.reject(failure));
    vi.mocked(useNavigate).mockReturnValue(navigate);
    vi.mocked(useLocation).mockReturnValue({
      pathname: "/users",
      search: "",
      hash: "",
      state: null,
      key: "source",
    });
    await expect(useScopeNavigation()(`/users?target=${target}`)).rejects.toBe(
      failure,
    );
    expect(navigate).toHaveBeenCalledOnce();
  });
});
