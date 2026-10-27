import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse, sessionFixture } from "./client.fixtures";
import { endpointStatus } from "./proxy";
import { proxyOperations, scopeAccess, type ProxyScope } from "./scope";
import {
  canonicalOrigin,
  deliveryAction,
  job,
  nextCommand,
  owner,
  remotePolicy,
  submission,
  target,
  targetPage,
  targetListQuery,
  userResult,
  type CommandInput,
  type PolicyJob,
} from "./targets";
import { SessionController } from "../auth/session";

const NODE = "A".repeat(22);

describe("registered target filters", () => {
  it("encodes literal global filters with the same page and retirement options", async () => {
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        jsonResponse({
          items: [],
          next_cursor: null,
          controller_available: false,
        }),
    );
    const client = new ManagementClient(fetcher, () => true);
    await client.targets(
      { after: NODE, limit: 1, include_retired: true, q: "  West %_ 节点  " },
      signal(),
    );
    const url = new URL(
      String(fetcher.mock.calls[0]?.[0]),
      "https://manager.example",
    );
    expect(url.pathname).toBe("/api/v1/targets");
    expect(Object.fromEntries(url.searchParams)).toEqual({
      after: NODE,
      limit: "1",
      include_retired: "true",
      q: "West %_ 节点",
    });
    expect(targetListQuery({ q: "  " })).toBe("");
    expect(endpointStatus("/targets?q=%25_", "GET")).toBe(200);
  });
  it("rejects oversized, control, duplicate and malformed encoded filters before dispatch", async () => {
    const fetcher = vi.fn();
    const client = new ManagementClient(fetcher, () => true);
    for (const q of ["界".repeat(86), "x".repeat(257), "x\u0085y", "x\0y"]) {
      await expect(client.targets({ q }, signal())).rejects.toBeInstanceOf(
        ApiError,
      );
    }
    for (const query of ["q=%FF", "q=%", "q=a&%71=b", "q=%00", "q=%C2%85"]) {
      expect(() => endpointStatus(`/targets?${query}`, "GET")).toThrow(
        ApiError,
      );
    }
    expect(fetcher).not.toHaveBeenCalled();
  });
});
const USER = "AQEBAQEBAQEBAQEBAQEBAQ";
const CREDENTIAL = "AgICAgICAgICAgICAgICAg";
const SECRET = "A".repeat(43);
const signal = () => new AbortController().signal;
const targetFact = () => ({
  node_id: NODE,
  name: "Registered node",
  origin: "https://node.example:9443",
  active: true,
  retired: false,
  revision: "3",
  observed_epoch: "2",
  observed_command: "9007199254740993",
  observed_policy_revision: "9007199254740993",
  rollback_detected: false,
});
const policyFact = () => ({
  controller_node_id: USER,
  controller_epoch: "2",
  last_terminal_command: "9007199254740993",
  saved_revision: "9007199254740993",
  applied_revision: null,
  durable_applied_revision: null,
  proxy_running: false,
  user_count: 1,
  credential_count: 0,
});
const command = (): CommandInput => ({
  expected_target_revision: "3",
  controller_epoch: "2",
  command_id: "9007199254740994",
  expected_policy_revision: "9007199254740993",
  mutation: { action: "create_credential", user_id: USER },
});
const ticket = () => ({
  node_id: NODE,
  job_id: CREDENTIAL,
  controller_epoch: "2",
  command_id: "9007199254740994",
  expected_policy_revision: "9007199254740993",
  state: "pending",
  policy_revision: null,
  outcome_code: null,
  attempts: 0,
  next_attempt: "0",
});
const firstReply = () => ({
  job: ticket(),
  response: {
    receipt: {
      controller_epoch: "2",
      command_id: "9007199254740994",
      status: "applied",
      policy_revision: "9007199254740994",
      rejection: null,
      user_id: USER,
      credential_id: CREDENTIAL,
    },
    replayed: false,
    user: {
      id: USER,
      name: "User",
      active: true,
      deleted: false,
      protocols: ["http"],
      concurrent_limit: 1,
      revision: "1",
    },
    credential: {
      id: CREDENTIAL,
      user_id: USER,
      login: `vp2_${"02".repeat(16)}`,
      syntax_version: 2,
      active: true,
      revoked: false,
      verifier_revision: "1",
    },
    secret: SECRET,
    secret_available: true,
  },
});
const scope = (): ProxyScope => ({
  kind: "target",
  target: target(targetFact()),
  policy: remotePolicy(policyFact()),
});

describe("registered node control boundary", () => {
  it("keeps old tickets readable and binds a user result to one advertised create intent", () => {
    expect(job(ticket(), NODE)).toEqual(ticket());
    expect(
      job({ ...ticket(), user_creation: false }, NODE)?.user_creation,
    ).toBe(false);
    const expected: PolicyJob = {
      ...ticket(),
      state: "pending",
      user_creation: true,
    };
    const saved = {
      ...expected,
      state: "saved",
      policy_revision: "9007199254740994",
    };
    const value = { job: saved, user_id: USER };
    expect(userResult(value, NODE, expected)).toEqual(value);
    for (const user_creation of [null, undefined, 1, "true"])
      expect(() => job({ ...ticket(), user_creation }, NODE)).toThrow(ApiError);
    for (const extra of [
      { routing: { kind: "pool", id: USER } },
      { preset: { kind: "user", id: USER } },
    ])
      expect(() => job({ ...expected, ...extra }, NODE)).toThrow(ApiError);
    const metadata = {
      ...ticket(),
      resource: "proxy_endpoints",
      expected_policy_revision: null,
      expected_metadata_revision: "1",
      metadata_revision: null,
      endpoint: { listener_id: USER, generation: "a".repeat(64) },
    };
    expect(
      job({ ...metadata, user_creation: false }, NODE)?.user_creation,
    ).toBe(false);
    expect(() => job({ ...metadata, user_creation: true }, NODE)).toThrow(
      ApiError,
    );
    for (const invalid of [
      { ...value, secret: SECRET },
      { ...value, user_id: "not-an-id" },
      { ...value, job: { ...saved, node_id: USER } },
      { ...value, job: { ...saved, job_id: USER } },
      { ...value, job: { ...saved, controller_epoch: "3" } },
      { ...value, job: { ...saved, command_id: "3" } },
      {
        ...value,
        job: { ...saved, expected_policy_revision: "2", policy_revision: "3" },
      },
      { ...value, job: { ...expected } },
      { ...value, job: { ...saved, user_creation: false } },
      { ...value, job: { ...saved, outcome_code: "node_unavailable" } },
      { ...value, job: { ...saved, next_attempt: "1" } },
    ])
      expect(() => userResult(invalid, NODE, expected)).toThrow(ApiError);
    expect(() =>
      userResult(value, NODE, { ...expected, user_creation: false }),
    ).toThrow(ApiError);
    expect(() =>
      userResult(value, NODE, {
        ...expected,
        state: "applied",
        policy_revision: saved.policy_revision,
      }),
    ).toThrow(ApiError);
  });

  it("requests the exact job with session CSRF and neither retries nor accepts unrelated result data", async () => {
    const expected: PolicyJob = {
      ...ticket(),
      state: "pending",
      user_creation: true,
    };
    const result = {
      job: { ...expected, state: "saved", policy_revision: "9007199254740994" },
      user_id: USER,
    };
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(result));
    const client = new ManagementClient(fetcher, () => true);
    expect(
      await client.targetUserResult(
        NODE,
        expected,
        "memory-only-csrf",
        signal(),
      ),
    ).toEqual(result);
    expect(fetcher.mock.calls[0]).toMatchObject([
      `/api/v1/targets/${NODE}/command/user-result`,
      {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        headers: { "X-CSRF-Token": "memory-only-csrf" },
        body: JSON.stringify({ job_id: expected.job_id }),
      },
    ]);
    await expect(
      client.targetUserResult(
        NODE,
        { ...expected, user_creation: false },
        "csrf",
        signal(),
      ),
    ).rejects.toMatchObject({ kind: "format" });
    expect(fetcher).toHaveBeenCalledTimes(1);
    fetcher.mockResolvedValueOnce(
      jsonResponse({ error: { code: "receipt_expired" } }, 409),
    );
    await expect(
      client.targetUserResult(NODE, expected, "csrf", signal()),
    ).rejects.toMatchObject({ code: "receipt_expired" });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(endpointStatus(`/targets/${NODE}/command/user-result`, "POST")).toBe(
      200,
    );
    for (const method of ["GET", "PUT"] as const)
      expect(() =>
        endpointStatus(`/targets/${NODE}/command/user-result`, method),
      ).toThrow(ApiError);
    expect(() =>
      endpointStatus(
        `/targets/${NODE}/command/user-result?job_id=${USER}`,
        "POST",
      ),
    ).toThrow(ApiError);
  });

  it("accepts only numeric server-IP metadata while keeping old DTOs and unknown-field rejection", () => {
    const legacy = targetFact();
    expect(target(legacy).server_ip).toBeNull();
    expect(legacy).not.toHaveProperty("server_ip");
    for (const server_ip of [
      null,
      "192.0.2.8",
      "127.0.0.1",
      "10.0.0.8",
      "2001:db8::8",
      "2001:0DB8:0:0:0:0:0:8",
      "FD00:0:0:0:0:0:0:7",
      "::1",
      "::ffff:192.0.2.8",
      "::FFFF:7f00:1",
    ])
      expect(target({ ...legacy, server_ip }).server_ip).toBe(server_ip);
    for (const server_ip of [
      undefined,
      "",
      "node.example",
      "192.0.2.8:443",
      "https://192.0.2.8",
      "192.0.2.8/24",
      "01.2.3.4",
      "[2001:db8::8]",
      "fe80::1%eth0",
      "0.0.0.0",
      "255.255.255.255",
      "224.0.0.1",
      "239.255.255.255",
      "::",
      "0:0:0:0:0:0:0:0",
      "FF02::1",
      "::ffff:0.0.0.0",
      "::ffff:255.255.255.255",
      "::FFFF:224.0.0.1",
      "::ffff:efff:ffff",
      123,
    ])
      expect(() => target({ ...legacy, server_ip })).toThrow(ApiError);
    expect(() =>
      target({ ...legacy, server_ip: null, public_egress: "192.0.2.8" }),
    ).toThrow(ApiError);
    expect(() => target(null)).toThrow(ApiError);
  });
  it("preserves omitted metadata, explicitly clears null and keeps server IP separate from the TLS origin", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const client = new ManagementClient(fetcher, () => true);
    const origin = targetFact().origin;
    for (const serverIp of [undefined, null, "192.0.2.8", "2001:db8::8"]) {
      fetcher.mockResolvedValueOnce(
        jsonResponse({
          ...targetFact(),
          ...(serverIp === undefined ? {} : { server_ip: serverIp }),
        }),
      );
      const result = await client.configureTarget(
        NODE,
        origin,
        true,
        "3",
        "csrf",
        signal(),
        serverIp,
      );
      expect(result.origin).toBe(origin);
      expect(result.server_ip).toBe(serverIp ?? null);
      const call = fetcher.mock.calls.at(-1);
      expect(call?.[0]).toBe(`/api/v1/targets/${NODE}`);
      expect(call?.[1]).toMatchObject({
        method: "PUT",
        credentials: "same-origin",
        redirect: "error",
        headers: { "X-CSRF-Token": "csrf" },
        body: JSON.stringify({
          expected_revision: "3",
          origin,
          active: true,
          ...(serverIp === undefined ? {} : { server_ip: serverIp }),
        }),
      });
    }
    fetcher.mockResolvedValueOnce(
      jsonResponse({ ...targetFact(), server_ip: "192.0.2.8" }, 201),
    );
    await client.configureTarget(
      NODE,
      origin,
      true,
      null,
      "csrf",
      signal(),
      "192.0.2.8",
    );
    expect(fetcher.mock.calls.at(-1)?.[0]).toBe("/api/v1/targets");
    expect(fetcher.mock.calls.at(-1)?.[1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({
        node_id: NODE,
        origin,
        active: true,
        server_ip: "192.0.2.8",
      }),
    });
    const sent = fetcher.mock.calls.length;
    for (const ip of [
      "example.com",
      "192.0.2.8:443",
      "[::1]",
      "::1/128",
      "0.0.0.0",
      "224.0.0.1",
      "255.255.255.255",
      "::",
      "ff02::1",
      "::ffff:239.255.255.255",
    ])
      await expect(
        client.configureTarget(NODE, origin, true, "3", "csrf", signal(), ip),
      ).rejects.toThrow(ApiError);
    expect(fetcher).toHaveBeenCalledTimes(sent);
  });
  it("keeps local credential inspection available under remote ownership while blocking every local mutation", () => {
    const local: ProxyScope = { kind: "local" };
    const remoteOwner = {
      controller_node_id: NODE,
      epoch: "2",
      last_terminal_command: "0",
    };
    expect(scopeAccess(local, remoteOwner, false)).toEqual({
      readDisabled: false,
      writeDisabled: true,
    });
    expect(scopeAccess(local, null, false)).toEqual({
      readDisabled: false,
      writeDisabled: true,
    });
    expect(
      scopeAccess(local, { ...remoteOwner, controller_node_id: null }, false),
    ).toEqual({ readDisabled: false, writeDisabled: false });
    expect(scopeAccess(local, remoteOwner, true)).toEqual({
      readDisabled: true,
      writeDisabled: true,
    });
    expect(scopeAccess(null, remoteOwner, false)).toEqual({
      readDisabled: true,
      writeDisabled: true,
    });
  });
  it("reactivates a retired target through its state CAS without resetting identity or rollback floors", async () => {
    const retired = target({
      ...targetFact(),
      active: false,
      retired: true,
      rollback_detected: true,
    });
    expect(deliveryAction(retired)).toBe("reactivate");
    expect(deliveryAction({ active: false, retired: false })).toBe("resume");
    expect(deliveryAction({ active: true, retired: false })).toBe("pause");
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({
        ...retired,
        active: true,
        retired: false,
        revision: "4",
      }),
    );
    const client = new ManagementClient(fetcher, () => true);
    const result = await client.targetState(
      NODE,
      retired.revision,
      true,
      false,
      "csrf",
      signal(),
    );
    expect(fetcher.mock.calls[0]?.[0]).toBe(`/api/v1/targets/${NODE}/state`);
    expect(fetcher.mock.calls[0]?.[1]).toMatchObject({
      method: "POST",
      body: JSON.stringify({ expected_revision: "3", active: true }),
    });
    expect(result).toMatchObject({
      node_id: NODE,
      observed_epoch: retired.observed_epoch,
      observed_command: retired.observed_command,
      observed_policy_revision: retired.observed_policy_revision,
      rollback_detected: true,
    });
    expect(JSON.stringify(fetcher.mock.calls[0]?.[1]?.body)).not.toContain(
      "command_id",
    );
  });
  it("preserves lossless sequence/epoch strings and rejects unsafe origins or invented facts", () => {
    expect(nextCommand("9007199254740993")).toBe("9007199254740994");
    expect(nextCommand("0")).toBe("1");
    for (const input of [
      "01",
      "-1",
      "9223372036854775807",
      "9223372036854775808",
    ])
      expect(() => nextCommand(input)).toThrow(ApiError);
    expect(
      owner({
        controller_node_id: null,
        epoch: "1",
        last_terminal_command: "0",
      }).controller_node_id,
    ).toBeNull();
    for (const value of [
      "http://node.example",
      "https://node.example/",
      "https://node.example/path",
      "https://user@node.example",
      "https://node.example:0",
      "https://node.example?x=1",
    ])
      expect(canonicalOrigin(value)).toBe(false);
    expect(canonicalOrigin("https://[::1]:9443")).toBe(true);
    expect(() => target({ ...targetFact(), healthy: true })).toThrow(ApiError);
    expect(() => target({ ...targetFact(), observed_command: null })).toThrow(
      ApiError,
    );
    expect(() =>
      targetPage({
        items: Array(26).fill(targetFact()),
        next_cursor: null,
        controller_available: true,
      }),
    ).toThrow(ApiError);
    expect(() =>
      remotePolicy({
        ...policyFact(),
        proxy_running: false,
        applied_revision: "1",
      }),
    ).toThrow(ApiError);
  });
  it("only admits the fixed endpoint/method/query vocabulary", () => {
    expect(endpointStatus("/proxy/owner", "PUT")).toBe(200);
    expect(endpointStatus(`/targets/${NODE}/commands`, "POST")).toEqual([
      200, 202,
    ]);
    expect(endpointStatus(`/targets/${NODE}/command/refresh`, "POST")).toBe(
      200,
    );
    for (const [path, method] of [
      ["/targets?limit=26", "GET"],
      ["/targets?limit=1&limit=2", "GET"],
      ["/targets?__proto__=x", "GET"],
      [`/targets/${NODE}/users?origin=https://other.example`, "GET"],
      [`/targets/${NODE}/command/retry`, "GET"],
      [`/targets/${NODE}/commands?secret=x`, "POST"],
      [`/targets/../auth/login`, "POST"],
    ] as const)
      expect(() => endpointStatus(path, method)).toThrow(ApiError);
  });
  it("treats 202 as saved intent without secret and accepts a historical pending ticket with an immediate valid receipt", () => {
    expect(
      submission({ job: ticket(), response: null }, NODE, command(), 202)
        .response,
    ).toBeNull();
    expect(
      submission(firstReply(), NODE, command(), 200).response?.secret,
    ).toBe(SECRET);
    for (const [value, status] of [
      [{ job: ticket(), response: null }, 200],
      [firstReply(), 202],
      [{ ...firstReply(), job: { ...ticket(), command_id: "1" } }, 200],
      [
        {
          ...firstReply(),
          response: { ...firstReply().response, replayed: true },
        },
        200,
      ],
      [
        {
          ...firstReply(),
          response: {
            ...firstReply().response,
            credential: { ...firstReply().response.credential, user_id: NODE },
          },
        },
        200,
      ],
    ] as const)
      expect(() => submission(value, NODE, command(), status)).toThrow(
        ApiError,
      );
  });
  it("uses same-origin CSRF POSTs, validates status contracts and never persists or automatically retries uncertain actions", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({ job: ticket(), response: null }, 202),
      );
    const client = new ManagementClient(fetcher, () => true);
    const result = await proxyOperations(client, scope()).createCredential(
      USER,
      "9007199254740993",
      "memory-only-csrf",
      signal(),
    );
    expect(result.secret).toBeNull();
    expect(result.submission?.response).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0]?.[0]).toBe(`/api/v1/targets/${NODE}/commands`);
    expect(fetcher.mock.calls[0]?.[1]).toMatchObject({
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers: { "X-CSRF-Token": "memory-only-csrf" },
      body: JSON.stringify(command()),
    });
    const forged = { ...command(), source_administrator_id: USER };
    await expect(
      client.targetCommand(NODE, forged, "csrf", signal()),
    ).rejects.toThrow(ApiError);
    await expect(
      client.targetCommand("../node", command(), "csrf", signal()),
    ).rejects.toThrow(ApiError);
    await expect(
      proxyOperations(client, scope()).createCredential(
        USER,
        "2",
        "csrf",
        signal(),
      ),
    ).rejects.toMatchObject({ status: 409 });
    expect(fetcher).toHaveBeenCalledTimes(1);
    fetcher.mockResolvedValueOnce(jsonResponse(firstReply(), 201));
    await expect(
      client.targetCommand(NODE, command(), "csrf", signal()),
    ).rejects.toMatchObject({ kind: "format" });
  });
  it("retains a first secret only in the operation result, never in ticket metadata", async () => {
    const client = new ManagementClient(
      vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(firstReply())),
      () => true,
    );
    const result = await proxyOperations(client, scope()).createCredential(
      USER,
      "9007199254740993",
      "csrf",
      signal(),
    );
    expect(result.secret).toBe(SECRET);
    expect(JSON.stringify(result.submission)).not.toContain(SECRET);
    result.secret = null;
    expect(JSON.stringify(result)).not.toContain(SECRET);
  });
  it("does not deliver a late remote secret across session generations", async () => {
    let resolve!: (response: Response) => void;
    const pending = new Promise<Response>((accept) => {
      resolve = accept;
    });
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementation(async (url) =>
        String(url).includes("/commands")
          ? pending
          : jsonResponse(
              sessionFixture(String(url).includes("login") ? "new" : "old"),
            ),
      );
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const issued = controller
      .resource(controller.snapshot().session!, (client, csrf, signal) =>
        proxyOperations(client, scope()).createCredential(
          USER,
          "9007199254740993",
          csrf,
          signal,
        ),
      )
      .catch((error) => error);
    await controller.login("new", "fixture password");
    resolve(jsonResponse(firstReply()));
    expect(await issued).toMatchObject({ name: "AbortError" });
    expect(JSON.stringify(controller.snapshot())).not.toContain(SECRET);
    expect(controller.snapshot().session?.administrator.username).toBe("new");
  });
});
