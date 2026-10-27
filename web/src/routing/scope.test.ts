import { createMemoryHistory } from "history";
import { describe, expect, it } from "vitest";
import { ApiError } from "../api/error";
import { trafficHref, trafficLocation } from "../api/traffic";
import { resourcesHref } from "../api/targets";
import {
  checkedScopeHref,
  menuScopeHref,
  scopeHref,
  scopeLocation,
  resourceLocation,
  alertLocation,
  alertHistoryHref,
  type ScopedPath,
} from "./scope";

const first = "A".repeat(22);
const second = "B".repeat(21) + "A";
const subject = "C".repeat(21) + "A";
const paths: ScopedPath[] = ["/users", "/traffic", "/resources", "/alerts"];

describe("URL-owned management node scope", () => {
  it("owns local history/event selection only on Alerts without widening other workspace queries", () => {
    expect(alertHistoryHref()).toBe("/alerts?view=history");
    expect(alertLocation("?view=history&event=1")).toEqual({
      peer: null,
      history: true,
      eventId: "1",
    });
    expect(alertHistoryHref(first, "1")).toBe(
      `/alerts?view=history&target=${first}&event=1`,
    );
    expect(checkedScopeHref(alertHistoryHref(first, "1"))).toBe(
      alertHistoryHref(first, "1"),
    );
    expect(
      menuScopeHref("/users", {
        pathname: "/alerts",
        search: "?view=history&event=1",
      }),
    ).toBe("/users");
    for (const search of [
      "?view=other",
      "?event=1",
      "?view=history&event=0",
      "?view=history&event=01",
      "?view=history&event=9223372036854775808",
      "?view=history&event=1&event=2",
      "?view=history&event=1&%65vent=2",
      "?view=history&redirect=https://outside.invalid",
    ])
      expect(() => alertLocation(search)).toThrow(ApiError);
    for (const pathname of ["/users", "/resources"])
      expect(() =>
        scopeLocation({ pathname, search: "?view=history" }),
      ).toThrow(ApiError);
  });
  it("owns exact address selection only on Resources and clears it across nodes and workspaces", () => {
    for (const peer of [null, first]) {
      const href = resourcesHref(peer, subject);
      const search = href.slice(href.indexOf("?"));
      expect(resourceLocation(search)).toEqual({ peer, address: subject });
      expect(checkedScopeHref(href)).toBe(href);
      expect(scopeLocation({ pathname: "/resources", search })).toBe(peer);
      for (const path of paths)
        expect(menuScopeHref(path, { pathname: "/resources", search })).toBe(
          scopeHref(path, peer),
        );
      expect(scopeHref("/resources", second)).toBe(
        `/resources?target=${second}`,
      );
    }
    for (const search of [
      "?address=",
      "?address=192.0.2.1",
      "?address=invalid",
      `?address=${subject}&address=${subject}`,
      `?address=${subject}&%61ddress=${subject}`,
      `?target=${first}&%74arget=${first}&address=${subject}`,
      `?target=&address=${subject}`,
      `?address=${subject}&kind=addresses`,
      `?address=${subject}&redirect=https://outside.invalid`,
    ]) {
      expect(() => resourceLocation(search)).toThrow(ApiError);
      expect(() => checkedScopeHref(`/resources${search}`)).toThrow(ApiError);
      expect(
        menuScopeHref("/users", { pathname: "/resources", search }),
      ).toBeNull();
    }
    for (const pathname of ["/users", "/alerts"])
      expect(() =>
        scopeLocation({ pathname, search: `?address=${subject}` }),
      ).toThrow(ApiError);
    expect(() => resourcesHref(first, "invalid")).toThrow(ApiError);
  });
  it("treats absent target as explicit local and preserves only target across workspaces", () => {
    for (const pathname of paths) {
      expect(scopeLocation({ pathname, search: "" })).toBeNull();
      expect(scopeLocation({ pathname, search: `?target=${first}` })).toBe(
        first,
      );
      expect(scopeHref(pathname, null)).toBe(pathname);
      const source =
        pathname === "/traffic"
          ? {
              pathname,
              search: trafficHref({ kind: "user", id: subject }, first, {
                protocol: "socks5",
                resolution: "day",
              }).split("?")[1],
            }
          : { pathname, search: `?target=${first}` };
      for (const destination of paths)
        expect(menuScopeHref(destination, source)).toBe(
          `${destination}?target=${first}`,
        );
      expect(menuScopeHref("/nodes", source)).toBe("/nodes");
    }
    // Returning from the global node overview never silently restores a peer.
    expect(menuScopeHref("/users", { pathname: "/nodes", search: "" })).toBe(
      "/users",
    );
    expect(menuScopeHref("/users", { pathname: "/alerts", search: "" })).toBe(
      "/users",
    );
    expect(
      menuScopeHref("/resources", {
        pathname: "/nodes",
        search: `?target=${first}`,
      }),
    ).toBe("/resources");
    expect(
      menuScopeHref("https://outside.invalid", {
        pathname: "/users",
        search: "",
      }),
    ).toBeNull();
  });

  it("rejects ambiguous, empty, unknown, external and oversized scopes without choosing local", () => {
    for (const pathname of paths)
      for (const search of [
        "?target=",
        "?target=not-a-node",
        "?target=https://outside.invalid",
        `?target=${first}&target=${second}`,
        `?target=${first}&%74arget=${first}`,
        `?target=${first}&redirect=/nodes`,
        `?target=${first}&unknown=`,
        "?" + "x".repeat(1024),
      ]) {
        const current = { pathname, search };
        expect(() => scopeLocation(current)).toThrow(ApiError);
        for (const destination of paths)
          expect(menuScopeHref(destination, current)).toBeNull();
        expect(menuScopeHref("/nodes", current)).toBe("/nodes");
      }
    for (const pathname of ["/users", "/resources", "/alerts"])
      for (const search of [
        "?scope=node",
        "?protocol=http",
        "?resolution=hour",
      ])
        expect(() => scopeLocation({ pathname, search })).toThrow(ApiError);
    for (const search of [
      "?scope=",
      "?scope=user",
      `?scope=node&id=${subject}`,
      "?protocol=",
      "?resolution=",
      "?scope=node&scope=node",
    ])
      expect(() => scopeLocation({ pathname: "/traffic", search })).toThrow(
        ApiError,
      );
    for (const href of [
      "/nodes",
      "/users\n",
      "/users#remote",
      "//outside.invalid/users",
      "https://outside.invalid/users",
      "/users/../resources",
      "/:id(.*)*",
      "/users?target=",
    ])
      expect(() => checkedScopeHref(href)).toThrow(ApiError);
    for (const target of ["", "../users", "A".repeat(21) + "B"])
      expect(() => scopeHref("/users", target)).toThrow(ApiError);
  });

  it("makes selection, history, reload and copied deep links identify the same node", () => {
    const history = createMemoryHistory({
      initialEntries: [scopeHref("/users", first)],
    });
    history.push(checkedScopeHref(scopeHref("/users", second)));
    history.push(checkedScopeHref(scopeHref("/resources", second)));
    history.push(checkedScopeHref(scopeHref("/resources", null)));
    expect(scopeLocation(history.location)).toBeNull();
    history.back();
    expect(scopeLocation(history.location)).toBe(second);
    history.back();
    expect(history.location.pathname).toBe("/users");
    expect(scopeLocation(history.location)).toBe(second);
    history.back();
    expect(scopeLocation(history.location)).toBe(first);
    history.forward();
    expect(scopeLocation(history.location)).toBe(second);
    const copied = history.location.pathname + history.location.search;
    const reloaded = createMemoryHistory({ initialEntries: [copied] });
    expect(scopeLocation(reloaded.location)).toBe(second);
  });

  it("round-trips committed traffic filters and clears entity selection on a node change", () => {
    const details = { protocol: "http", resolution: "minute" } as const;
    const history = createMemoryHistory({
      initialEntries: [
        trafficHref({ kind: "user", id: subject }, first, details),
      ],
    });
    const original = trafficLocation(history.location.search);
    expect(original).toEqual({
      peer: first,
      scope: { kind: "user", id: subject },
      ...details,
    });
    history.push(
      checkedScopeHref(
        trafficHref({ kind: "node", id: null }, second, details),
      ),
    );
    expect(trafficLocation(history.location.search)).toEqual({
      peer: second,
      scope: { kind: "node", id: null },
      ...details,
    });
    history.back();
    expect(trafficLocation(history.location.search)).toEqual(original);
    const sidebar = menuScopeHref("/traffic", history.location)!;
    expect(trafficLocation(sidebar.split("?")[1])).toEqual({
      peer: first,
      scope: { kind: "node", id: null },
      resolution: "hour",
      protocol: undefined,
    });
  });
});
