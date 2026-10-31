import { describe, expect, it, vi } from "vitest";
import type { ManagementClient } from "../../api/client";
import type {
  Address,
  PermissionView,
  Pool,
  RoutingPage,
} from "../../api/routing";
import { readConnectionLabels } from "./connectionLabels";

const granted = "A".repeat(22),
  outside = "Q".repeat(22),
  other = "g".repeat(22);
const permission: PermissionView = {
  revision: "7",
  permission: {
    user_id: granted,
    legacy_allowed: false,
    exits: [granted, outside],
    pools: [granted],
  },
};
const address: Address = {
  id: granted,
  name: "Named exit",
  ip: "192.0.2.1",
  prefix_id: null,
  state: "draining",
  revision: "6",
};
const pool: Pool = {
  id: granted,
  name: "Named pool",
  family: "v6",
  state: "active",
  member_count: 1,
  revision: "7",
};
const signal = new AbortController().signal;

describe("optional bounded connection resource labels", () => {
  it("does not start a second resource read after cancellation, even when the first transport returns a page", async () => {
    const request = new AbortController();
    const remote = vi.fn(async () => {
      request.abort();
      return { revision: "7", items: [address], next_cursor: null };
    });
    const client = {
      targetRoutingCatalog: remote,
    } as unknown as ManagementClient;
    await expect(
      readConnectionLabels(client, other, permission, request.signal),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(remote).toHaveBeenCalledTimes(1);
    remote.mockClear();
    await expect(
      readConnectionLabels(client, other, permission, request.signal),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(remote).not.toHaveBeenCalled();
  });
  it("reads sequentially once per granted kind and retains only same-revision authorized labels", async () => {
    const routingCatalog = vi.fn(
      async (kind: string): Promise<RoutingPage<Address | Pool>> => ({
        revision: "7",
        items:
          kind === "addresses"
            ? [address, { ...address, id: other, name: "Not granted" }]
            : [pool],
        next_cursor: kind === "addresses" ? other : granted,
      }),
    );
    const client = { routingCatalog } as unknown as ManagementClient;
    const result = await readConnectionLabels(client, null, permission, signal);
    expect(result).toEqual({
      revision: "7",
      addresses: [address],
      pools: [pool],
    });
    expect(routingCatalog.mock.calls).toEqual([
      ["addresses", { limit: 50 }, signal],
      ["pools", { limit: 50 }, signal],
    ]);
    // A cursor never causes another page or removes a grant outside this page.
    expect(permission.permission.exits).toEqual([granted, outside]);
  });

  it("uses only the requested remote node and skips resource kinds without grants", async () => {
    const local = vi.fn();
    const remote = vi.fn(async () => ({
      revision: "7",
      items: [pool],
      next_cursor: null,
    }));
    const client = {
      routingCatalog: local,
      targetRoutingCatalog: remote,
    } as unknown as ManagementClient;
    const result = await readConnectionLabels(
      client,
      other,
      { ...permission, permission: { ...permission.permission, exits: [] } },
      signal,
    );
    expect(result.pools).toEqual([pool]);
    expect(remote).toHaveBeenCalledExactlyOnceWith(
      other,
      "pools",
      { limit: 50 },
      signal,
    );
    expect(local).not.toHaveBeenCalled();
  });

  it("rejects mixed policy revisions and remote failure rather than publishing partial labels or falling back", async () => {
    const local = vi.fn();
    for (const failure of ["revision", "network"] as const) {
      const remote = vi.fn(async (_peer: string, kind: string) => {
        if (kind === "addresses")
          return { revision: "7", items: [address], next_cursor: null };
        if (failure !== "revision") throw new Error(failure);
        return { revision: "8", items: [pool], next_cursor: null };
      });
      await expect(
        readConnectionLabels(
          {
            routingCatalog: local,
            targetRoutingCatalog: remote,
          } as unknown as ManagementClient,
          other,
          permission,
          signal,
        ),
      ).rejects.toThrow();
      expect(remote).toHaveBeenCalledTimes(2);
    }
    expect(local).not.toHaveBeenCalled();
  });
});
