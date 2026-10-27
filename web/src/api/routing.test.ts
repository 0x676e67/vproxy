import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse, sessionFixture } from "./client.fixtures";
import { endpointStatus } from "./proxy";
import {
  address,
  equivalentCidr,
  permissionInput,
  permissionView,
  pool,
  prefix,
  routingChange,
  routingEntity,
  routingPage,
  routingQuery,
  routingToken,
  validCidr,
  validIp,
} from "./routing";
import { SessionController } from "../auth/session";

const ID = "A".repeat(22);
const SECOND = "AQEBAQEBAQEBAQEBAQEBAQ";
const THIRD = "AgICAgICAgICAgICAgICAg";
const signal = () => new AbortController().signal;
const prefixFact = (revision = "2") => ({
  id: ID,
  name: "Local network",
  cidr: "192.0.2.0/24",
  retired: false,
  revision,
});
const addressFact = (revision = "2") => ({
  id: SECOND,
  name: "Local address",
  ip: "192.0.2.1",
  prefix_id: ID,
  state: "active",
  revision,
});
const poolFact = (revision = "2") => ({
  id: THIRD,
  name: "Shared pool",
  family: "v4",
  state: "active",
  member_count: 1,
  revision,
});
const grant = () => ({
  user_id: ID,
  legacy_allowed: false,
  exits: [SECOND],
  pools: [THIRD],
});
const changed = (
  kind = "prefix",
  data: unknown = prefixFact(),
  revision = "2",
) => ({ revision, entity: { kind, data } });

describe("local finite routing management", () => {
  it("keeps a fixed method/status vocabulary, including bounded cursor queries and no child-node IPAM", () => {
    for (const list of ["prefixes", "addresses", "pools"]) {
      expect(endpointStatus(`/proxy/${list}?after=${ID}&limit=25`, "GET")).toBe(
        200,
      );
      expect(endpointStatus(`/proxy/${list}`, "POST")).toBe(201);
    }
    expect(endpointStatus(`/proxy/pools/${ID}/members?limit=25`, "GET")).toBe(
      200,
    );
    expect(endpointStatus(`/proxy/users/${ID}/routing`, "PUT")).toBe(200);
    for (const path of [
      `/proxy/pools/${ID}/members?limit=0`,
      `/proxy/pools/${ID}/members?limit=51`,
      "/proxy/addresses?__proto__=x",
      "/proxy/prefixes?include_deleted=true",
      `/proxy/addresses?after=${ID}&after=${ID}`,
      `/targets/${ID}/prefixes`,
      "/proxy/addresses/192.0.2.1/state",
      `/proxy/users/${ID}/routing?limit=25`,
    ]) {
      expect(() => endpointStatus(path, "GET"), path).toThrow(ApiError);
    }
    expect(() => endpointStatus(`/proxy/prefixes/${ID}/retire`, "PUT")).toThrow(
      ApiError,
    );
    expect(() => endpointStatus(`/proxy/users/${ID}/routing`, "POST")).toThrow(
      ApiError,
    );
    expect(() => routingQuery({ include_retired: true } as never)).toThrow(
      ApiError,
    );
  });
  it("checks IP syntax without claiming ownership, health or route installation", () => {
    for (const ip of ["192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"])
      expect(validIp(ip)).toBe(true);
    for (const ip of [
      "192.0.2.1:80",
      "999.0.0.1",
      "01.2.3.4",
      "fe80::1%eth0",
      "example.com",
      "::1/128",
      "[::1]",
    ])
      expect(validIp(ip)).toBe(false);
    expect(validCidr("2001:db8::/64")).toBe(true);
    expect(validCidr("192.0.2.0/24")).toBe(true);
    expect(validCidr("192.0.2.0/33")).toBe(false);
    expect(validCidr("::/129")).toBe(false);
    expect(validCidr("192.0.2.0/024")).toBe(false);
    expect(validCidr("127.0.0.1")).toBe(false);
    expect(validCidr("::1")).toBe(false);
  });
  it.each([
    ["127.0.0.1", "32"],
    ["::1", "128"],
    ["2001:0db8:0000:0000:0000:0000:0000:0001", "128"],
    ["::ffff:192.0.2.1", "128"],
  ])(
    "decodes the returned host %s without rewriting its address text",
    (ip, bits) => {
      const fact = { ...prefixFact(), cidr: ip };
      const decoded = prefix(fact);
      expect(decoded.cidr).toBe(`${ip}/${bits}`);
      expect(fact.cidr).toBe(ip);
      expect(prefix(decoded)).toEqual(decoded);
      const entity = routingEntity({ kind: "prefix", data: fact });
      expect(
        routingChange({ revision: "2", entity }, "prefix", "1").entity,
      ).toEqual({ kind: "prefix", data: decoded });
      expect(
        routingPage(
          { revision: "2", items: [fact], next_cursor: null },
          prefix,
          (item) => item.id,
        ).items,
      ).toEqual([decoded]);
    },
  );
  it("compares CIDR address, family and mask without masking host bits", () => {
    expect(equivalentCidr("127.0.0.1", "127.0.0.1/32")).toBe(true);
    expect(equivalentCidr("2001:0db8::1/128", "2001:db8::1")).toBe(true);
    expect(equivalentCidr("::ffff:192.0.2.1", "::ffff:c000:201/128")).toBe(
      true,
    );
    for (const [left, right] of [
      ["127.0.0.1", "127.0.0.2/32"],
      ["127.0.0.1", "127.0.0.1/31"],
      ["192.0.2.1/24", "192.0.2.0/24"],
      ["192.0.2.1/32", "::ffff:192.0.2.1/128"],
      ["0.0.0.0/0", "0.0.0.0"],
      ["::/0", "::"],
    ])
      expect(equivalentCidr(left, right)).toBe(false);
    for (const cidr of ["0.0.0.0/0", "::/0", "192.0.2.1/24"])
      expect(prefix({ ...prefixFact(), cidr }).cidr).toBe(cidr);
    for (const cidr of ["127.0.0.1/33", "::1/129", "127.0.0.1/032", "[::1]"])
      expect(() => prefix({ ...prefixFact(), cidr })).toThrow(ApiError);
  });
  it.each([
    ["127.0.0.1", "32"],
    ["::1", "128"],
  ])(
    "reads and creates local host prefixes for %s through the client",
    async (ip, bits) => {
      const cidr = `${ip}/${bits}`;
      const fact = { ...prefixFact(), cidr: ip };
      const fetcher = vi
        .fn<typeof fetch>()
        .mockResolvedValueOnce(
          jsonResponse({
            revision: "2",
            items: [fact],
            next_cursor: null,
          }),
        )
        .mockResolvedValueOnce(jsonResponse(changed("prefix", fact), 201));
      const client = new ManagementClient(fetcher, () => true);
      expect(
        (await client.routingCatalog("prefixes", {}, signal())).items,
      ).toEqual([{ ...fact, cidr }]);
      expect(
        (
          await client.createPrefix(
            { name: fact.name, cidr },
            "1",
            "csrf",
            signal(),
          )
        ).entity,
      ).toEqual({ kind: "prefix", data: { ...fact, cidr } });
      expect(fetcher.mock.calls[1]?.[1]?.body).toBe(
        JSON.stringify({
          expected_revision: "1",
          name: fact.name,
          cidr,
        }),
      );
      await expect(
        client.createPrefix(
          { name: fact.name, cidr: ip },
          "1",
          "csrf",
          signal(),
        ),
      ).rejects.toMatchObject({ kind: "format" });
      expect(fetcher).toHaveBeenCalledTimes(2);
    },
  );
  it("validates exact resource shapes and keeps member pages bounded and ordered", () => {
    expect(prefix(prefixFact()).retired).toBe(false);
    expect(address(addressFact()).prefix_id).toBe(ID);
    expect(pool(poolFact()).member_count).toBe(1);
    expect(() => pool({ ...poolFact(), members: [SECOND] })).toThrow(ApiError);
    expect(() => pool({ ...poolFact(), family: "dual" })).toThrow(ApiError);
    expect(() => address({ ...addressFact(), state: "healthy" })).toThrow(
      ApiError,
    );
    expect(() =>
      prefix({ ...prefixFact(), id: `${ID.slice(0, -1)}B` }),
    ).toThrow(ApiError);
    expect(
      routingPage(
        { revision: "2", items: [ID, SECOND], next_cursor: SECOND },
        (value) => String(value),
        (value) => value,
      ).items,
    ).toHaveLength(2);
    expect(() =>
      routingPage(
        { revision: "2", items: [SECOND, ID], next_cursor: null },
        String,
        String,
      ),
    ).toThrow(ApiError);
    expect(() =>
      routingPage(
        { revision: "2", items: [ID], next_cursor: SECOND },
        String,
        String,
      ),
    ).toThrow(ApiError);
    expect(() =>
      routingPage(
        { revision: "2", items: [ID], next_cursor: null },
        String,
        String,
        { after: ID },
      ),
    ).toThrow(ApiError);
    expect(() =>
      routingPage(
        { revision: "2", items: [ID, SECOND], next_cursor: null },
        String,
        String,
        { limit: 1 },
      ),
    ).toThrow(ApiError);
  });
  it("rejects catalog entities newer than the returned policy snapshot", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(
      jsonResponse({
        revision: "2",
        items: [addressFact("3")],
        next_cursor: null,
      }),
    );
    const client = new ManagementClient(fetcher, () => true);
    await expect(
      client.routingCatalog("addresses", { limit: 25 }, signal()),
    ).rejects.toMatchObject({ kind: "format" });
  });
  it("requires a matching entity, exact next bigint revision and no credential-secret fields", () => {
    expect(routingChange(changed(), "prefix", "1").revision).toBe("2");
    expect(
      routingChange(
        changed("prefix", prefixFact("9007199254740994"), "9007199254740994"),
        "prefix",
        "9007199254740993",
      ).revision,
    ).toBe("9007199254740994");
    for (const response of [
      changed("address", addressFact()),
      changed("prefix", prefixFact("1")),
      changed("prefix", prefixFact(), "3"),
      { ...changed(), secret: "must-not-enter-routing-state" },
    ]) {
      expect(() => routingChange(response, "prefix", "1")).toThrow(ApiError);
    }
    expect(() => routingChange(changed(), "prefix", "1", SECOND)).toThrow(
      ApiError,
    );
    expect(() =>
      routingChange(changed(), "prefix", "9223372036854775807"),
    ).toThrow(ApiError);
    expect(
      routingChange(changed("permission", grant()), "permission", "1", ID)
        .entity.kind,
    ).toBe("permission");
  });
  it("never manufactures a compatibility grant and rejects excess, duplicate or raw-IP grants", () => {
    expect(
      permissionView({ revision: "2", permission: grant() }, ID).permission
        .legacy_allowed,
    ).toBe(false);
    expect(() => permissionView({ revision: "2" }, ID)).toThrow(ApiError);
    expect(() =>
      permissionView({ revision: "2", permission: grant() }, SECOND),
    ).toThrow(ApiError);
    expect(permissionInput({ ...grant(), exits: [], pools: [] })).toEqual({
      user_id: ID,
      legacy_allowed: false,
      exits: [],
      pools: [],
    });
    expect(() =>
      permissionInput({ ...grant(), exits: [SECOND, SECOND] }),
    ).toThrow(ApiError);
    expect(() => permissionInput({ ...grant(), exits: ["192.0.2.1"] })).toThrow(
      ApiError,
    );
    expect(() =>
      permissionInput({ ...grant(), pools: new Array(33).fill(THIRD) }),
    ).toThrow(ApiError);
    expect(
      permissionInput({
        user_id: ID,
        legacy_allowed: true,
        exits: [],
        pools: [],
      }).legacy_allowed,
    ).toBe(true);
    expect(routingToken(ID)).toBe("00".repeat(16));
    expect(routingToken(SECOND)).toBe("01".repeat(16));
    expect(() => routingToken("192.0.2.1")).toThrow(ApiError);
  });
  it("uses only local allowlisted endpoints with session CSRF, exact creation status and global CAS", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(changed(), 201))
      .mockResolvedValueOnce(jsonResponse(changed("permission", grant(), "3")))
      .mockResolvedValueOnce(jsonResponse(changed()));
    const client = new ManagementClient(fetcher, () => true);
    await client.createPrefix(
      { name: "Local network", cidr: "192.0.2.0/24" },
      "1",
      "memory-csrf",
      signal(),
    );
    expect(fetcher).toHaveBeenNthCalledWith(
      1,
      "/api/v1/proxy/prefixes",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        headers: expect.objectContaining({ "X-CSRF-Token": "memory-csrf" }),
        body: JSON.stringify({
          expected_revision: "1",
          name: "Local network",
          cidr: "192.0.2.0/24",
        }),
      }),
    );
    await client.setRoutePermission(grant(), "2", "csrf", signal());
    expect(fetcher.mock.calls[1]?.[0]).toBe(
      `/api/v1/proxy/users/${ID}/routing`,
    );
    expect(fetcher.mock.calls[1]?.[1]?.method).toBe("PUT");
    await expect(
      client.createPrefix(
        { name: "Local network", cidr: "192.0.2.0/24" },
        "1",
        "csrf",
        signal(),
      ),
    ).rejects.toMatchObject({ kind: "format" });
  });
  it("does not replace a missing permission or conflict with defaults or leak server detail", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: "resource_not_found" } }, 404),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          {
            error: { code: "policy_conflict", detail: "sensitive-test-string" },
          },
          409,
        ),
      );
    const client = new ManagementClient(fetcher, () => true);
    await expect(client.routePermission(ID, signal())).rejects.toMatchObject({
      status: 404,
      code: "resource_not_found",
    });
    const error = await client
      .routingState("addresses", SECOND, "draining", "1", "csrf", signal())
      .catch((failure) => failure);
    expect(error).toMatchObject({ status: 409, code: "policy_conflict" });
    expect(JSON.stringify(error)).not.toContain("sensitive-test-string");
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it("saves an explicit deny-all grant with exact false and empty arrays, never a compatibility fallback", async () => {
    const denyAll = {
      user_id: ID,
      legacy_allowed: false,
      exits: [],
      pools: [],
    };
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(changed("permission", denyAll)));
    const client = new ManagementClient(fetcher, () => true);
    const result = await client.setRoutePermission(
      denyAll,
      "1",
      "csrf",
      signal(),
    );
    expect(result.entity).toEqual({ kind: "permission", data: denyAll });
    expect(fetcher).toHaveBeenCalledExactlyOnceWith(
      `/api/v1/proxy/users/${ID}/routing`,
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({
          expected_revision: "1",
          legacy_allowed: false,
          exits: [],
          pools: [],
        }),
      }),
    );
  });
  it("cancels a protected routing write on session rotation and rejects an abort-ignoring late reply", async () => {
    let resolveWrite: (response: Response) => void = () => {};
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(sessionFixture()))
      .mockImplementationOnce(
        () =>
          new Promise<Response>((resolve) => {
            resolveWrite = resolve;
          }),
      )
      .mockResolvedValueOnce(jsonResponse(sessionFixture("second-admin")));
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.login("operator", "password");
    const current = controller.snapshot().session!;
    const result = controller.resource(current, (client, csrf, signal) =>
      client.setRoutePermission(grant(), "1", csrf, signal),
    );
    const rejected = expect(result).rejects.toMatchObject({
      name: "AbortError",
    });
    await controller.login("second-admin", "other-password");
    resolveWrite(jsonResponse(changed("permission", grant())));
    await rejected;
    expect(fetcher.mock.calls[1]?.[1]?.signal?.aborted).toBe(true);
    expect(controller.snapshot().session?.administrator.username).toBe(
      "second-admin",
    );
  });
});
