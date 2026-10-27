import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import {
  canonicalId,
  changeResult,
  endpointStatus,
  page,
  policyStatus,
  proxyCredential,
  proxyUser,
} from "./proxy";

const USER = "A".repeat(22);
const CREDENTIAL = "Q".repeat(22);
const user = () => ({
  id: USER,
  name: "Proxy user",
  active: true,
  deleted: false,
  protocols: ["http"],
  concurrent_limit: 32,
  revision: "1",
});
const credential = () => ({
  id: CREDENTIAL,
  user_id: USER,
  login: `vp2_${"0".repeat(32)}`,
  syntax_version: 2,
  active: true,
  revoked: false,
  verifier_revision: "1",
});
const issued = () => ({
  revision: "2",
  user: user(),
  credential: credential(),
  secret: "A".repeat(43),
});
const signal = () => new AbortController().signal;

describe("proxy policy API boundary", () => {
  it("validates canonical IDs, lossless revisions and historical status without inventing a running proxy", () => {
    expect(canonicalId(USER)).toBe(true);
    expect(canonicalId(`${"A".repeat(21)}B`)).toBe(false);
    const policy = {
      saved_revision: "9223372036854775807",
      applied_revision: null,
      durable_applied_revision: "9007199254740993",
      proxy_running: false,
      user_count: 0,
      credential_count: 0,
    };
    expect(policyStatus(policy)).toEqual(policy);
    for (const value of [
      { ...policy, saved_revision: 1 },
      { ...policy, saved_revision: "01" },
      { ...policy, saved_revision: "9223372036854775808" },
      { ...policy, applied_revision: "1" },
      { ...policy, saved_revision: "1", durable_applied_revision: "2" },
      {
        ...policy,
        saved_revision: "1",
        proxy_running: true,
        applied_revision: "2",
      },
    ])
      expect(() => policyStatus(value)).toThrow(ApiError);
  });
  it("bounds pages and rejects wrong DTOs and secret-bearing list projections", () => {
    expect(
      page({ revision: "1", items: [user()], next_cursor: USER }, proxyUser)
        .items,
    ).toHaveLength(1);
    for (const item of [
      { ...user(), secret_digest: "sensitive-fixture" },
      { ...user(), concurrent_limit: 0 },
      { ...user(), protocols: ["http", "http"] },
      { ...user(), name: " name " },
    ])
      expect(() => proxyUser(item)).toThrow(ApiError);
    expect(() =>
      proxyCredential({ ...credential(), secret: "sensitive-fixture" }),
    ).toThrow(ApiError);
    for (const value of [
      { revision: "1", items: Array(51).fill(user()), next_cursor: null },
      { revision: "1", items: [user(), user()], next_cursor: null },
      { revision: "1", items: [user()], next_cursor: CREDENTIAL },
    ])
      expect(() => page(value, proxyUser)).toThrow(ApiError);
    expect(() =>
      changeResult({ ...issued(), secret: "not canonical" }, "secret"),
    ).toThrow(ApiError);
    expect(() => changeResult(issued(), "credential")).toThrow(ApiError);
    expect(() =>
      changeResult(
        { ...issued(), credential: { ...credential(), user_id: CREDENTIAL } },
        "secret",
      ),
    ).toThrow(ApiError);
  });
  it("only admits fixed method/path/query contracts", () => {
    expect(endpointStatus(`/proxy/users/${USER}`, "PUT")).toBe(200);
    expect(endpointStatus(`/proxy/users/${USER}/credentials`, "POST")).toBe(
      201,
    );
    for (const [path, method] of [
      ["https://other.example/", "GET"],
      ["/proxy/users/../../auth/login", "POST"],
      [`/proxy/users/${"A".repeat(21)}B`, "PUT"],
      ["/proxy/users?limit=51", "GET"],
      ["/proxy/users?limit=1&limit=2", "GET"],
      ["/proxy/users?url=https://other.example", "GET"],
      ["/proxy/users?__proto__=x", "GET"],
      ["/proxy/users?constructor=x", "GET"],
      ["/proxy/credentials?include_deleted=true", "GET"],
      ["/proxy/users", "PUT"],
    ] as const)
      expect(() => endpointStatus(path, method)).toThrow(ApiError);
  });
  it("keeps user state and routing endpoint classifications disjoint", () => {
    for (const [path, method, status] of [
      [`/proxy/users/${USER}/state`, "POST", 200],
      [`/proxy/users/${USER}/delete`, "POST", 200],
      [`/proxy/users/${USER}/credentials`, "POST", 201],
      [`/proxy/credentials/${CREDENTIAL}/state`, "POST", 200],
      [`/proxy/credentials/${CREDENTIAL}/rotate`, "POST", 200],
      [`/proxy/credentials/${CREDENTIAL}/revoke`, "POST", 200],
      [`/proxy/users/${USER}/routing`, "GET", 200],
      [`/proxy/users/${USER}/routing`, "PUT", 200],
      [`/proxy/prefixes/${USER}/retire`, "POST", 200],
      [`/proxy/addresses/${USER}/state`, "POST", 200],
      [`/proxy/pools/${USER}/state`, "POST", 200],
      [`/proxy/pools/${USER}/members`, "GET", 200],
      [`/proxy/pools/${USER}/members`, "POST", 200],
      [`/proxy/pools/${USER}/members/remove`, "POST", 200],
    ] as const)
      expect(endpointStatus(path, method), `${method} ${path}`).toBe(status);
    for (const [path, method] of [
      [`/proxy/users/${USER}/state`, "GET"],
      [`/proxy/users/${USER}/state`, "PUT"],
      [`/proxy/users/${USER}/state?limit=1`, "POST"],
      [`/proxy/users/${"A".repeat(21)}B/state`, "POST"],
      [`/proxy/users/${USER}/unknown`, "POST"],
      [`/proxy/users/${USER}/routing`, "POST"],
      [`/proxy/users/${USER}/retire`, "POST"],
      [`/proxy/users/${USER}/members`, "POST"],
      [`/proxy/prefixes/${USER}/state`, "POST"],
      [`/proxy/prefixes/${USER}/routing`, "PUT"],
      [`/proxy/addresses/${USER}/retire`, "POST"],
      [`/proxy/pools/${USER}/delete`, "POST"],
      [`/proxy/credentials/${CREDENTIAL}/routing`, "PUT"],
    ] as const)
      expect(() => endpointStatus(path, method), `${method} ${path}`).toThrow(
        ApiError,
      );
  });
  it("sends local user disable and enable with CSRF and global CAS", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({
          revision: "4",
          user: { ...user(), active: false, revision: "3" },
          credential: null,
          secret: null,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          revision: "5",
          user: { ...user(), active: true, revision: "4" },
          credential: null,
          secret: null,
        }),
      );
    const client = new ManagementClient(fetcher, () => true);
    const disabled = await client.userState(USER, false, "3", "csrf", signal());
    expect(disabled.user?.active).toBe(false);
    expect(disabled.revision).toBe("4");
    const enabled = await client.userState(USER, true, "4", "csrf", signal());
    expect(enabled.user?.active).toBe(true);
    expect(enabled.revision).toBe("5");
    for (const [index, active, revision] of [
      [1, false, "3"],
      [2, true, "4"],
    ] as const)
      expect(fetcher).toHaveBeenNthCalledWith(
        index,
        `/api/v1/proxy/users/${USER}/state`,
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({ "X-CSRF-Token": "csrf" }),
          body: JSON.stringify({ active, expected_revision: revision }),
        }),
      );
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it("keeps user-state response validation and never retries mutation failures", async () => {
    const changed = {
      revision: "4",
      user: { ...user(), active: false, revision: "3" },
      credential: null,
      secret: null,
    };
    for (const [body, status, failure] of [
      [changed, 201, { kind: "format" }],
      [
        { ...changed, user: { ...changed.user, id: CREDENTIAL } },
        200,
        { kind: "format" },
      ],
      [
        { error: { code: "policy_busy" } },
        503,
        { kind: "server", code: "policy_busy", status: 503 },
      ],
    ] as const) {
      const fetcher = vi
        .fn<typeof fetch>()
        .mockResolvedValue(jsonResponse(body, status));
      const client = new ManagementClient(fetcher, () => true);
      await expect(
        client.userState(USER, false, "3", "csrf", signal()),
      ).rejects.toMatchObject(failure);
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
  });
  it("sends explicit POST/PUT, CSRF, decimal CAS and validates 201 rather than allowing arbitrary success", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse(
          { revision: "2", user: user(), credential: null, secret: null },
          201,
        ),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          revision: "3",
          user: user(),
          credential: null,
          secret: null,
        }),
      )
      .mockResolvedValueOnce(jsonResponse(issued(), 201));
    const client = new ManagementClient(fetcher, () => true);
    const input = {
      name: "Proxy user",
      protocols: ["http" as const],
      concurrent_limit: 32,
    };
    await client.createUser(
      input,
      "9007199254740993",
      "in-memory-csrf",
      signal(),
    );
    expect(fetcher).toHaveBeenNthCalledWith(
      1,
      "/api/v1/proxy/users",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        headers: expect.objectContaining({ "X-CSRF-Token": "in-memory-csrf" }),
        body: JSON.stringify({
          ...input,
          expected_revision: "9007199254740993",
        }),
      }),
    );
    await client.updateUser(USER, input, "2", "csrf", signal());
    expect(fetcher.mock.calls[1]?.[1]?.method).toBe("PUT");
    expect(
      (await client.createCredential(USER, "3", "csrf", signal())).secret,
    ).toBe("A".repeat(43));
    fetcher.mockResolvedValueOnce(jsonResponse(issued()));
    await expect(
      client.createCredential(USER, "4", "csrf", signal()),
    ).rejects.toMatchObject({ kind: "format" });
  });
  it("rejects invalid dynamic IDs/pages before fetch and never puts mutation data into URLs or errors", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "policy_conflict",
            detail: "one-time-sensitive-fixture",
          },
        },
        409,
      ),
    );
    const client = new ManagementClient(fetcher, () => true);
    await expect(
      client.revokeCredential("../auth/login", "1", "csrf", signal()),
    ).rejects.toThrow(ApiError);
    await expect(client.users({ limit: 51 }, signal())).rejects.toThrow(
      ApiError,
    );
    expect(fetcher).not.toHaveBeenCalled();
    const error = await client
      .rotateCredential(CREDENTIAL, "1", "csrf", signal())
      .catch((error) => error);
    expect(error).toMatchObject({ status: 409, code: "policy_conflict" });
    expect(String(error)).not.toContain("one-time-sensitive-fixture");
    expect(JSON.stringify(error)).not.toContain("one-time-sensitive-fixture");
    expect(fetcher.mock.calls[0]?.[0]).toBe(
      `/api/v1/proxy/credentials/${CREDENTIAL}/rotate`,
    );
  });
  it("requests only a bounded cursor page and rejects a wrong credential owner", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({ revision: "1", items: [user()], next_cursor: null }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          revision: "1",
          items: [credential()],
          next_cursor: null,
        }),
      );
    const client = new ManagementClient(fetcher, () => true);
    await client.users(
      { after: USER, limit: 25, include_deleted: true },
      signal(),
    );
    expect(fetcher.mock.calls[0]?.[0]).toBe(
      `/api/v1/proxy/users?after=${USER}&limit=25&include_deleted=true`,
    );
    await expect(
      client.credentials({ user_id: CREDENTIAL, limit: 25 }, signal()),
    ).rejects.toMatchObject({ kind: "format" });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
