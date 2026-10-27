import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse, sessionFixture } from "./client.fixtures";
import { endpointStatus } from "./proxy";
import {
  readRoutingView,
  routingReadDisabled,
  routingOperations,
  routingSubmission,
  routingWritable,
  shapeRoutingCommand,
  type RoutingCommandInput,
} from "./remoteRouting";
import { shapeCommandInput, submission } from "./targets";
import { SessionController } from "../auth/session";

const PEER = "A".repeat(22);
const LOCAL = "AQEBAQEBAQEBAQEBAQEBAQ";
const RESOURCE = "AgICAgICAgICAgICAgICAg";
const signal = () => new AbortController().signal;
const command = (): RoutingCommandInput => ({
  expected_target_revision: "1",
  controller_epoch: "2",
  command_id: "9007199254740994",
  expected_policy_revision: "9007199254740993",
  mutation: {
    action: "create_prefix",
    name: "Remote prefix",
    cidr: "192.0.2.0/24",
  },
});
const ticket = () => ({
  node_id: PEER,
  job_id: LOCAL,
  controller_epoch: "2",
  command_id: "9007199254740994",
  expected_policy_revision: "9007199254740993",
  state: "pending",
  policy_revision: null,
  outcome_code: null,
  attempts: 0,
  next_attempt: "0",
});
const entity = () => ({
  kind: "prefix",
  data: {
    id: RESOURCE,
    name: "Remote prefix",
    cidr: "192.0.2.0/24",
    retired: false,
    revision: "9007199254740994",
  },
});
const first = () => ({
  job: ticket(),
  response: {
    receipt: {
      controller_epoch: "2",
      command_id: "9007199254740994",
      status: "saved",
      policy_revision: "9007199254740994",
      rejection: null,
      user_id: null,
      credential_id: null,
      routing: { kind: "prefix", id: RESOURCE },
    },
    replayed: false,
    user: null,
    credential: null,
    secret: null,
    secret_available: false,
    routing: entity(),
  },
});
const target = () => ({
  node_id: PEER,
  name: "Child",
  origin: "https://child.example",
  active: true,
  retired: false,
  revision: "1",
  observed_epoch: "2",
  observed_command: "0",
  observed_policy_revision: "1",
  rollback_detected: false,
});
const policy = () => ({
  controller_node_id: LOCAL,
  controller_epoch: "2",
  last_terminal_command: "0",
  saved_revision: "1",
  applied_revision: null,
  durable_applied_revision: null,
  proxy_running: false,
  user_count: 0,
  credential_count: 0,
});
const facts = (url: string): unknown =>
  url === "/api/v1/node"
    ? {
        node_id: LOCAL,
        name: "Parent",
        version: "1",
        os: "linux",
        arch: "x86_64",
        capabilities: [],
      }
    : url === `/api/v1/targets/${PEER}`
      ? target()
      : url.endsWith("/command")
        ? null
        : url.endsWith("/policy")
          ? policy()
          : { revision: "1", items: [], next_cursor: null };

describe("versioned remote IPAM boundary", () => {
  it("blocks replacing an active remote read until it settles, without adding a mutation retry", () => {
    expect(routingReadDisabled(PEER, true, false)).toBe(true);
    expect(routingReadDisabled(PEER, false, false)).toBe(false);
    expect(routingReadDisabled(null, true, false)).toBe(false);
    expect(routingReadDisabled(null, false, true)).toBe(true);
  });
  it("keeps old eight actions closed and accepts only nine fixed routing actions on a distinct endpoint", () => {
    expect(() => shapeRoutingCommand(command())).not.toThrow();
    expect(() => shapeCommandInput(command() as never)).toThrow(ApiError);
    expect(() =>
      shapeRoutingCommand({
        ...command(),
        mutation: { action: "delete_user", id: RESOURCE },
      } as never),
    ).toThrow(ApiError);
    expect(() =>
      shapeRoutingCommand({ ...command(), actor: LOCAL } as never),
    ).toThrow(ApiError);
    expect(() =>
      shapeRoutingCommand({
        ...command(),
        mutation: {
          action: "set_route_permission",
          user_id: RESOURCE,
          legacy_allowed: true,
          exits: [],
          pools: [],
        },
      } as never),
    ).toThrow(ApiError);
    shapeRoutingCommand({
      ...command(),
      mutation: {
        action: "set_route_permission",
        permission: {
          user_id: RESOURCE,
          legacy_allowed: false,
          exits: [],
          pools: [],
        },
      },
    });
    expect(endpointStatus(`/targets/${PEER}/routing/commands`, "POST")).toEqual(
      [200, 202],
    );
    expect(
      endpointStatus(
        `/targets/${PEER}/proxy/pools/${RESOURCE}/members?limit=25`,
        "GET",
      ),
    ).toBe(200);
    expect(
      endpointStatus(`/targets/${PEER}/proxy/health?limit=16`, "GET"),
    ).toBe(200);
    for (const [path, method] of [
      [`/targets/${PEER}/proxy/prefixes`, "POST"],
      [`/targets/${PEER}/proxy/health?limit=17`, "GET"],
      [`/targets/${PEER}/proxy/users/${RESOURCE}/routing?limit=10`, "GET"],
      [`/targets/${PEER}/routing/commands?actor=x`, "POST"],
      [`/targets/${PEER}/proxy/pools?__proto__=x`, "GET"],
      [
        `/targets/${PEER}/proxy/pools?after=${RESOURCE}&after=${RESOURCE}`,
        "GET",
      ],
    ] as const)
      expect(() => endpointStatus(path, method)).toThrow(ApiError);
  });
  it("associates first entity/ref/next bigint CAS without demanding the historical ticket be terminal", () => {
    expect(
      routingSubmission(first(), PEER, command(), 200).response?.routing,
    ).toEqual(entity());
    for (const mutate of [
      (value: ReturnType<typeof first>) => {
        value.response.receipt.routing.id = LOCAL;
      },
      (value: ReturnType<typeof first>) => {
        value.response.routing.data.revision = "9007199254740993";
      },
      (value: ReturnType<typeof first>) => {
        value.response.receipt.policy_revision = "9007199254740995";
      },
      (value: ReturnType<typeof first>) => {
        value.response.secret = "must-not-enter-ipam" as never;
      },
    ]) {
      const value = first();
      mutate(value);
      expect(() => routingSubmission(value, PEER, command(), 200)).toThrow(
        ApiError,
      );
    }
    expect(() =>
      submission(
        first(),
        PEER,
        {
          ...command(),
          mutation: {
            action: "create_user",
            name: "User",
            protocols: [],
            concurrent_limit: 1,
          },
        },
        200,
      ),
    ).toThrow(ApiError);
  });
  it.each([
    ["127.0.0.1/32", "127.0.0.1"],
    ["::1/128", "::1"],
    ["2001:0db8::1/128", "2001:db8::1"],
    ["::ffff:192.0.2.1/128", "::ffff:c000:201"],
  ])(
    "reads and correlates remote host prefix %s with legacy text %s",
    async (cidr, wireCidr) => {
      const input = command();
      input.mutation = { action: "create_prefix", name: "Remote prefix", cidr };
      const response = first();
      response.response.routing.data.cidr = wireCidr;
      const data = response.response.routing.data;
      const decoded = {
        ...data,
        cidr: `${wireCidr}/${wireCidr.includes(":") ? 128 : 32}`,
      };
      const fetcher = vi
        .fn<typeof fetch>()
        .mockResolvedValueOnce(
          jsonResponse({
            revision: data.revision,
            items: [data],
            next_cursor: null,
          }),
        )
        .mockResolvedValueOnce(jsonResponse(response));
      const client = new ManagementClient(fetcher, () => true);
      expect(
        (await client.targetRoutingCatalog(PEER, "prefixes", {}, signal()))
          .items,
      ).toEqual([decoded]);
      expect(
        (await client.targetRoutingCommand(PEER, input, "csrf", signal()))
          .response?.routing,
      ).toEqual({ kind: "prefix", data: decoded });
      expect(fetcher.mock.calls[1]?.[1]?.body).toBe(JSON.stringify(input));
      expect(response.response.routing.data.cidr).toBe(wireCidr);
      await expect(
        client.targetRoutingCommand(
          PEER,
          {
            ...input,
            mutation: {
              action: "create_prefix",
              name: "Remote prefix",
              cidr: wireCidr,
            },
          },
          "csrf",
          signal(),
        ),
      ).rejects.toMatchObject({ kind: "format" });
      expect(fetcher).toHaveBeenCalledTimes(2);
    },
  );
  it.each([
    ["127.0.0.1/32", "127.0.0.2"],
    ["127.0.0.1/32", "127.0.0.1/31"],
    ["127.0.0.1/32", "::ffff:127.0.0.1"],
    ["192.0.2.0/24", "192.0.2.1/24"],
    ["0.0.0.0/0", "0.0.0.0"],
    ["::/0", "::"],
    ["::1/128", "::2"],
    ["::1/128", "::1/127"],
    ["::1/128", "::1/129"],
  ])(
    "rejects created prefix %s when the receipt returns %s",
    (cidr, wireCidr) => {
      const input = command();
      input.mutation = { action: "create_prefix", name: "Remote prefix", cidr };
      const response = first();
      response.response.routing.data.cidr = wireCidr;
      expect(() => routingSubmission(response, PEER, input, 200)).toThrow(
        ApiError,
      );
    },
  );
  it("keeps replay references but no reconstructed entity, and distinguishes rejection and 202 without retrying", () => {
    const { routing: _unused, ...reply } = first().response;
    const replay = {
      job: { ...ticket(), routing: { kind: "prefix", id: RESOURCE } },
      response: { ...reply, replayed: true },
    };
    expect(
      routingSubmission(replay, PEER, command(), 200).response?.routing,
    ).toBeUndefined();
    expect(() =>
      routingSubmission(
        { ...replay, response: { ...replay.response, routing: entity() } },
        PEER,
        command(),
        200,
      ),
    ).toThrow(ApiError);
    const { routing: _ref, ...receipt } = reply.receipt;
    const rejected = {
      job: ticket(),
      response: {
        ...reply,
        receipt: {
          ...receipt,
          status: "rejected",
          policy_revision: null,
          rejection: "policy_conflict",
        },
        replayed: false,
      },
    };
    expect(
      routingSubmission(rejected, PEER, command(), 200).response?.receipt
        .status,
    ).toBe("rejected");
    expect(
      routingSubmission({ job: ticket(), response: null }, PEER, command(), 202)
        .response,
    ).toBeNull();
    expect(() =>
      routingSubmission(
        { job: ticket(), response: null },
        PEER,
        command(),
        200,
      ),
    ).toThrow(ApiError);
    expect(() => routingSubmission(first(), PEER, command(), 202)).toThrow(
      ApiError,
    );
  });
  it("correlates created fields and accepts semantically identical IPv6 address text", () => {
    const wrongPrefix = first();
    wrongPrefix.response.routing.data.retired = true;
    expect(() => routingSubmission(wrongPrefix, PEER, command(), 200)).toThrow(
      ApiError,
    );
    const wrongName = first();
    wrongName.response.routing.data.name = "Other";
    expect(() => routingSubmission(wrongName, PEER, command(), 200)).toThrow(
      ApiError,
    );
    const addressInput: RoutingCommandInput = {
      ...command(),
      mutation: {
        action: "create_address",
        name: "Address",
        ip: "2001:0db8:0000:0000:0000:0000:0000:0001",
        prefix_id: null,
      },
    };
    const accepted = {
      job: ticket(),
      response: {
        ...first().response,
        receipt: {
          ...first().response.receipt,
          routing: { kind: "address", id: RESOURCE },
        },
        routing: {
          kind: "address",
          data: {
            id: RESOURCE,
            name: "Address",
            ip: "2001:db8::1",
            prefix_id: null,
            state: "active",
            revision: "9007199254740994",
          },
        },
      },
    };
    expect(
      routingSubmission(accepted, PEER, addressInput, 200).response?.routing
        ?.kind,
    ).toBe("address");
    accepted.response.routing.data.ip = "2001:db8::2";
    expect(() => routingSubmission(accepted, PEER, addressInput, 200)).toThrow(
      ApiError,
    );
    const poolInput: RoutingCommandInput = {
      ...command(),
      mutation: { action: "create_pool", name: "Pool", family: "v6" },
    };
    const acceptedPool = {
      job: ticket(),
      response: {
        ...first().response,
        receipt: {
          ...first().response.receipt,
          routing: { kind: "pool", id: RESOURCE },
        },
        routing: {
          kind: "pool",
          data: {
            id: RESOURCE,
            name: "Pool",
            family: "v6",
            state: "active",
            member_count: 0,
            revision: "9007199254740994",
          },
        },
      },
    };
    expect(
      routingSubmission(acceptedPool, PEER, poolInput, 200).response?.routing
        ?.kind,
    ).toBe("pool");
    acceptedPool.response.routing.data.member_count = 1;
    expect(() => routingSubmission(acceptedPool, PEER, poolInput, 200)).toThrow(
      ApiError,
    );
  });
  it("observes target/job/policy/catalog sequentially and grants writes only after v2 data and actual ownership", async () => {
    let active = 0;
    let maximum = 0;
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (url) => {
      active++;
      maximum = Math.max(maximum, active);
      await Promise.resolve();
      const response = jsonResponse(facts(String(url)));
      active--;
      return response;
    });
    const client = new ManagementClient(fetcher, () => true);
    const observed = await readRoutingView(
      client,
      PEER,
      (read, signal) => read.routingCatalog("prefixes", { limit: 25 }, signal),
      (page) => page.revision,
      signal(),
    );
    expect(maximum).toBe(1);
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      "/api/v1/node",
      `/api/v1/targets/${PEER}`,
      `/api/v1/targets/${PEER}/command`,
      `/api/v1/targets/${PEER}/policy`,
      `/api/v1/targets/${PEER}/proxy/prefixes?limit=25`,
    ]);
    expect(routingWritable(observed.context)).toBe(true);
    expect(routingWritable({ ...observed.context, supported: false })).toBe(
      false,
    );
    expect(
      routingWritable({ ...observed.context, localNodeId: RESOURCE }),
    ).toBe(false);
    expect(
      routingWritable({
        ...observed.context,
        job: {
          ...ticket(),
          expected_policy_revision: "1",
          command_id: "1",
        } as never,
      }),
    ).toBe(false);
    const denied = routingOperations(client, {
      ...observed.context,
      localNodeId: RESOURCE,
    });
    await expect(
      denied.retirePrefix(RESOURCE, "1", "csrf", signal()),
    ).rejects.toMatchObject({ code: "node_control_denied" });
    expect(fetcher).toHaveBeenCalledTimes(5);
  });
  it("does not fallback unsupported child reads into local resources or compare health’s old catalog to policy", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementation(async (url) =>
        String(url).includes("/proxy/prefixes")
          ? jsonResponse({ error: { code: "node_protocol_unsupported" } }, 502)
          : jsonResponse(facts(String(url))),
      );
    const client = new ManagementClient(fetcher, () => true);
    await expect(
      readRoutingView(
        client,
        PEER,
        (read, signal) => read.routingCatalog("prefixes", {}, signal),
        (page) => page.revision,
        signal(),
      ),
    ).rejects.toMatchObject({ code: "node_protocol_unsupported" });
    expect(fetcher.mock.calls.map(([url]) => url)).not.toContain(
      "/api/v1/proxy/prefixes",
    );
    fetcher.mockImplementation(async (url) =>
      String(url).includes("/proxy/health")
        ? jsonResponse({
            boot_id: RESOURCE,
            sequence: "0",
            catalog_revision: null,
            catalog_loaded: false,
            catalog_error: null,
            catalog_observed_at_unix_ms: null,
            catalog_age_millis: null,
            in_flight: 0,
            entries: [],
            next_cursor: null,
          })
        : jsonResponse(facts(String(url))),
    );
    const health = await readRoutingView(
      client,
      PEER,
      (read, signal) => read.health({ limit: 10 }, signal),
      null,
      signal(),
    );
    expect(health.data.catalog_revision).toBeNull();
    expect(health.context.supported).toBe(true);
  });
  it("uses only the distinct mutation endpoint, nested permission and one 202 submission without a second command", async () => {
    const input: RoutingCommandInput = {
      ...command(),
      mutation: {
        action: "set_route_permission",
        permission: {
          user_id: RESOURCE,
          legacy_allowed: false,
          exits: [],
          pools: [],
        },
      },
    };
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({ job: ticket(), response: null }, 202),
      );
    const client = new ManagementClient(fetcher, () => true);
    const result = await client.targetRoutingCommand(
      PEER,
      input,
      "memory-csrf",
      signal(),
    );
    expect(result.response).toBeNull();
    expect(fetcher).toHaveBeenCalledExactlyOnceWith(
      `/api/v1/targets/${PEER}/routing/commands`,
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(input),
        headers: expect.objectContaining({ "X-CSRF-Token": "memory-csrf" }),
      }),
    );
  });
  it("cancels v2 late replies on administrator rotation without carrying result/ref into the new session", async () => {
    let resolve: (value: Response) => void = () => {};
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(sessionFixture()))
      .mockImplementationOnce(
        () =>
          new Promise<Response>((ready) => {
            resolve = ready;
          }),
      )
      .mockResolvedValueOnce(jsonResponse(sessionFixture("next")));
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.login("operator", "password");
    const current = controller.snapshot().session!;
    const result = controller.resource(current, (client, csrf, signal) =>
      client.targetRoutingCommand(PEER, command(), csrf, signal),
    );
    const rejected = expect(result).rejects.toMatchObject({
      name: "AbortError",
    });
    await controller.login("next", "password");
    resolve(jsonResponse(first()));
    await rejected;
    expect(fetcher.mock.calls[1]?.[1]?.signal?.aborted).toBe(true);
    expect(controller.snapshot().session?.administrator.username).toBe("next");
  });
});
