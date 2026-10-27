import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { PassThrough } from "node:stream";
import { createElement, lazy, type ComponentType } from "react";
import { renderToPipeableStream, renderToString } from "react-dom/server";
import {
  createBrowserHistory,
  createHashHistory,
  createMemoryHistory,
  type History,
} from "history";
import * as router from "react-router";
import * as dom from "react-router-dom";
import * as umi from "@umijs/renderer-react";
import { afterEach, describe, expect, it, vi } from "vitest";
import configureRouter from "../../config/router";
import { StaticRouter, type StaticRouterProps } from "react-router-dom/server";

const require = createRequire(import.meta.url);
const target = "-" + "A".repeat(21);
afterEach(() => vi.unstubAllGlobals());

/** Only the platform history surface is faked. Routing, context, path parsing,
 * Umi route construction and history@5 remain the actual installed modules.
 */
function browserWindow(initial: string) {
  const events = new EventTarget();
  const entries = [{ url: new URL(initial), state: null as unknown }];
  let index = 0;
  const current = () => entries[index];
  const window = {
    get location() {
      return current().url;
    },
    document: { querySelector: () => null },
    addEventListener: events.addEventListener.bind(events),
    removeEventListener: events.removeEventListener.bind(events),
    history: {
      get state() {
        return current().state;
      },
      get length() {
        return entries.length;
      },
      pushState(state: unknown, _unused: string, to?: string | URL | null) {
        const base = current().url;
        entries.splice(index + 1, entries.length, {
          url: new URL(to ?? base, base),
          state,
        });
        index++;
      },
      replaceState(state: unknown, _unused: string, to?: string | URL | null) {
        entries[index] = {
          url: new URL(to ?? current().url, current().url),
          state,
        };
      },
      go(delta: number) {
        const next = index + delta;
        if (next < 0 || next >= entries.length) return;
        index = next;
        events.dispatchEvent(new Event("popstate"));
      },
    },
  };
  vi.stubGlobal("window", window);
  vi.stubGlobal("document", window.document);
  return window;
}

function locationProbe() {
  const location = router.useLocation();
  return createElement(
    "section",
    null,
    location.pathname + location.search,
    createElement(umi.Link, { to: "/resources?target=" + target }, "resources"),
  );
}

function application(
  history: History,
  component: ComponentType = locationProbe,
  basename = "/",
) {
  const routes = {
    users: { id: "users", path: "/users" },
    resources: { id: "resources", path: "/resources" },
  };
  const Browser = umi.renderClient({
    routes,
    routeComponents: { users: component, resources: component },
    history,
    basename,
    rootElement: {} as HTMLElement,
    components: true,
    pluginManager: {
      applyPlugins: ({ initialValue }: { initialValue?: unknown }) =>
        initialValue,
    },
    __INTERNAL_DO_NOT_USE_OR_YOU_WILL_BE_FIRED: { pureApp: true },
  });
  if (!Browser)
    throw new Error("Umi did not return its testable browser component");
  return createElement(Browser);
}

describe("Umi Router 7 compatibility", () => {
  it("resolves Umi and DOM exports to one exact patched Router package", () => {
    expect(dom.Router).toBe(router.Router);
    expect(dom.useLocation).toBe(router.useLocation);
    expect(umi.useLocation).toBe(router.useLocation);
    for (const owner of [
      "@umijs/preset-umi",
      "@umijs/renderer-react",
      "@umijs/server",
    ]) {
      const fromOwner = createRequire(require.resolve(owner + "/package.json"));
      for (const name of ["react-router", "react-router-dom"])
        expect(fromOwner.resolve(name + "/package.json")).toBe(
          require.resolve(name + "/package.json"),
        );
    }
    expect(require("react-router/package.json").version).toBe("7.18.4");
    expect(require("react-router-dom/package.json").version).toBe("7.18.4");
    expect(require("history/package.json").version).toBe("5.3.0");
  });

  it("places the exact server adapter before package aliases and retains generated TS paths", () => {
    const callbacks: Record<
      string,
      (value: Record<string, unknown>) => Record<string, unknown>
    > = {};
    configureRouter({
      cwd: process.cwd(),
      modifyConfig(
        callback: (value: Record<string, unknown>) => Record<string, unknown>,
      ) {
        callbacks.config = callback;
      },
      modifyDefaultConfig(
        callback: (value: Record<string, unknown>) => Record<string, unknown>,
      ) {
        callbacks.defaults = callback;
      },
      modifyTSConfig(
        callback: (value: Record<string, unknown>) => Record<string, unknown>,
      ) {
        callbacks.ts = callback;
      },
    } as unknown as Parameters<typeof configureRouter>[0]);
    const domRoot = path.dirname(
      require.resolve("react-router-dom/package.json"),
    );
    const coreRoot = path.dirname(require.resolve("react-router/package.json"));
    const defaults = callbacks.defaults({
      alias: {
        "react-router": coreRoot,
        "react-router-dom": domRoot,
        umi: "@@/exports",
      },
    });
    const configured = require("@umijs/utils").lodash.merge(
      defaults,
      callbacks.config({ alias: { "@": "/src", "@@": "/tmp" } }),
    );
    const aliases = configured.alias as Record<string, string>;
    expect(Object.keys(aliases)).toEqual([
      "react-router-dom/server$",
      "react-router$",
      "react-router-dom$",
      "umi",
      "@",
      "@@",
    ]);
    expect(aliases["react-router-dom/server$"]).toBe(
      path.join(process.cwd(), "src/routing/server.ts"),
    );
    // Exercise Webpack's resolver, not just the spelling of an alias key. A
    // prefix-first map loses /server to the package directory before our shim.
    const resolve = require("enhanced-resolve").create.sync({
      alias: aliases,
      extensions: [".ts", ".js", ".json"],
      conditionNames: ["module", "import", "default"],
      mainFields: ["browser", "module", "main"],
    });
    expect(resolve(process.cwd(), "react-router-dom/server")).toBe(
      aliases["react-router-dom/server$"],
    );
    expect(resolve(process.cwd(), "react-router/dom")).toBe(
      path.join(coreRoot, "dist/development/dom-export.mjs"),
    );
    expect(resolve(process.cwd(), "react-router")).toBe(
      path.join(coreRoot, require("react-router/package.json").module),
    );
    expect(resolve(process.cwd(), "react-router-dom")).toBe(
      path.join(domRoot, require("react-router-dom/package.json").module),
    );
    expect(aliases).not.toHaveProperty("react-router");
    expect(aliases).not.toHaveProperty("react-router-dom");
    for (const unknown of [
      "react-router-dom/server/unknown",
      "react-router-dom/serverish",
      "react-router/unknown",
    ])
      expect(() => resolve(process.cwd(), unknown)).toThrow();
    expect(() => require.resolve("react-router-dom/server")).toThrow();
    const ts = callbacks.ts({
      compilerOptions: {
        paths: { "@/*": ["src/*"], "@@/*": ["src/.umi/*"] },
        strict: true,
      },
    });
    expect(ts.compilerOptions).toEqual({
      strict: true,
      paths: {
        "@/*": ["src/*"],
        "@@/*": ["src/.umi/*"],
        "react-router-dom/server": [aliases["react-router-dom/server$"]],
      },
    });
  });

  it("keeps the generated history bridge and TS aliases without editing generated output", () => {
    const generated = JSON.parse(
      readFileSync("src/.umi/tsconfig.json", "utf8"),
    );
    expect(generated.compilerOptions.paths).toHaveProperty("@/*");
    expect(generated.compilerOptions.paths).toHaveProperty("@@/*");
    expect(generated.compilerOptions.paths).toHaveProperty("@umijs/max");
    expect(generated.compilerOptions.paths).not.toHaveProperty("react-router$");
    expect(generated.compilerOptions.paths).not.toHaveProperty(
      "react-router-dom$",
    );
    expect(generated.compilerOptions.paths["react-router-dom/server"]).toEqual([
      path.join(process.cwd(), "src/routing/server.ts"),
    ]);
  });

  it("renders the actual Umi Router/useRoutes bridge with public Router hooks and Link", () => {
    browserWindow("https://management.test/");
    const history = createMemoryHistory({
      initialEntries: ["/users?target=" + target],
    });
    const navigator: router.Navigator = history;
    expect(navigator.createHref("/users")).toBe("/users");
    const html = renderToString(application(history));
    expect(html).toContain("/users?target=" + target);
    expect(html).toContain('href="/resources?target=' + target + '"');
    expect(html).not.toContain("/login");
  });

  it("retains real memory history push, replace, back and forward query locations", () => {
    browserWindow("https://management.test/");
    const history = createMemoryHistory({
      initialEntries: ["/users?target=" + target],
    });
    const observed: string[] = [];
    const unlisten = history.listen(({ action, location }) =>
      observed.push(action + " " + location.pathname + location.search),
    );
    history.push("/resources?target=" + target);
    history.replace({
      pathname: "/resources",
      search: "?target=" + "A".repeat(22),
    });
    expect(renderToString(application(history))).toContain(
      "/resources?target=" + "A".repeat(22),
    );
    history.back();
    expect(renderToString(application(history))).toContain(
      "/users?target=" + target,
    );
    history.forward();
    expect(renderToString(application(history))).toContain(
      "/resources?target=" + "A".repeat(22),
    );
    unlisten();
    expect(observed.map((value) => value.split(" ")[0])).toEqual([
      "PUSH",
      "REPLACE",
      "POP",
      "POP",
    ]);
  });

  for (const type of ["browser", "hash"] as const) {
    it(`keeps actual history@5 ${type} locations, hrefs and POP notifications`, () => {
      const window = browserWindow(
        "https://management.test/" +
          (type === "hash" ? "#/users?target=" : "users?target=") +
          target,
      );
      const history =
        type === "hash"
          ? createHashHistory({ window: window as unknown as Window })
          : createBrowserHistory({ window: window as unknown as Window });
      expect(history.location.pathname).toBe("/users");
      expect(renderToString(application(history))).toContain(
        'href="' +
          (type === "hash" ? "#" : "") +
          "/resources?target=" +
          target +
          '"',
      );
      history.push("/resources?target=" + target);
      history.replace("/resources?target=" + "A".repeat(22));
      expect(window.location.origin).toBe("https://management.test");
      history.back();
      expect(history.location.pathname + history.location.search).toBe(
        "/users?target=" + target,
      );
      history.forward();
      expect(history.location.pathname + history.location.search).toBe(
        "/resources?target=" + "A".repeat(22),
      );
      expect(window.history.length).toBe(2);
    });
  }

  it("reexports the real v7 StaticRouter and preserves basename/object links", () => {
    expect(StaticRouter).toBe(router.StaticRouter);
    const props: StaticRouterProps = {
      basename: "/console",
      location: "/console/users?target=" + target,
    };
    function page() {
      return createElement(
        router.Link,
        { to: { pathname: "../resources", search: "?target=" + target } },
        router.useLocation().search,
      );
    }
    const html = renderToString(
      createElement(
        StaticRouter,
        props,
        createElement(
          router.Routes,
          null,
          createElement(router.Route, {
            path: "/users",
            element: createElement(page),
          }),
        ),
      ),
    );
    expect(html).toContain('href="/console/resources?target=' + target + '"');
    expect(html).toContain("?target=" + target);
  });

  it("normalizes all four leading separator combinations without a protocol-relative path", () => {
    // Fixed security regression from the v7.18 navigation hardening. Explicit
    // external Link URLs remain a separate public API, disallowed by our app's
    // existing navigation-source allowlist rather than redefined here.
    for (const separators of ["//", "/\\", "\\/", "\\\\"]) {
      const resolved = router.resolvePath(
        separators + "outside.invalid/path",
        "/users",
      );
      expect(resolved.pathname).toBe("/outside.invalid/path");
      expect(
        new URL(resolved.pathname, "https://management.test/").origin,
      ).toBe("https://management.test");
    }
    expect(
      router.resolvePath("../resources/./", "/users/details").pathname,
    ).toBe("/users/resources/");
  });

  it("streams a lazy route through the unchanged Umi route factory", async () => {
    browserWindow("https://management.test/");
    const loaded = vi.fn(async () => ({ default: locationProbe }));
    const Lazy = lazy(loaded);
    const history = createMemoryHistory({
      initialEntries: ["/users?target=" + target],
    });
    const html = await new Promise<string>((resolve, reject) => {
      const output = new PassThrough();
      let html = "";
      output.setEncoding("utf8");
      output.on("data", (part: string) => {
        html += part;
      });
      output.on("end", () => resolve(html));
      const stream = renderToPipeableStream(application(history, Lazy), {
        onAllReady() {
          stream.pipe(output);
        },
        onError: reject,
        onShellError: reject,
      });
    });
    expect(loaded).toHaveBeenCalledOnce();
    expect(html).toContain("/users?target=" + target);
    expect(html).toContain('href="/resources?target=' + target + '"');
  });
});
