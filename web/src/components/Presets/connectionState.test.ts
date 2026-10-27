import { describe, expect, it } from "vitest";
import type { RoutePermission } from "../../api/routing";
import type { PolicyStatus } from "../../api/proxy";
import {
  connectionPolicyState,
  connectionRoutes,
  reconcileConnectionRoute,
} from "./connectionState";

const permission = (): RoutePermission => ({
  user_id: "A".repeat(22),
  legacy_allowed: false,
  exits: ["Q".repeat(22)],
  pools: ["g".repeat(22)],
});

describe("connection form route reconciliation", () => {
  it("does not mistake saved policy or a historical receipt for a currently applied runtime", () => {
    const policy: PolicyStatus = {
      saved_revision: "27",
      applied_revision: null,
      durable_applied_revision: "27",
      proxy_running: false,
      user_count: 1,
      credential_count: 1,
    };
    expect(connectionPolicyState(policy)).toBe("users.apiOnly");
    expect(connectionPolicyState({ ...policy, proxy_running: true })).toBe(
      "users.degraded",
    );
    expect(
      connectionPolicyState({
        ...policy,
        proxy_running: true,
        applied_revision: "26",
      }),
    ).toBe("users.pending");
    expect(
      connectionPolicyState({
        ...policy,
        proxy_running: true,
        applied_revision: "27",
      }),
    ).toBe("users.running");
  });

  it("clears the initial legacy default for restricted users without choosing an exit or pool", () => {
    expect(connectionRoutes(permission())).toEqual(["exit", "pool"]);
    for (const kind of ["default", "session", "range", "ttl"] as const)
      expect(reconcileConnectionRoute(permission(), kind, "old")).toEqual({
        route_kind: undefined,
        route_value: "",
      });
    expect(reconcileConnectionRoute(permission(), undefined, "")).toEqual({
      route_kind: undefined,
      route_value: "",
    });
  });

  it("keeps a permitted deliberate choice and clears a removed grant, never substituting another resource", () => {
    for (const kind of ["exit", "pool"] as const) {
      const value =
        kind === "exit" ? permission().exits[0] : permission().pools[0];
      expect(reconcileConnectionRoute(permission(), kind, value)).toEqual({
        route_kind: kind,
        route_value: value,
      });
      expect(reconcileConnectionRoute(permission(), kind, "old-id")).toEqual({
        route_kind: kind,
        route_value: "",
      });
    }
    const empty = { ...permission(), exits: [], pools: [] };
    expect(connectionRoutes(empty)).toEqual([]);
    expect(
      reconcileConnectionRoute(empty, "exit", permission().exits[0]),
    ).toEqual({
      route_kind: undefined,
      route_value: "",
    });
    const legacy = { ...empty, legacy_allowed: true };
    expect(reconcileConnectionRoute(legacy, "default", "")).toEqual({
      route_kind: "default",
      route_value: "",
    });
    expect(reconcileConnectionRoute(legacy, "session", "my_session")).toEqual({
      route_kind: "session",
      route_value: "my_session",
    });
  });
});
