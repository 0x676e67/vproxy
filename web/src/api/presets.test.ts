import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse, sessionFixture } from "./client.fixtures";
import { endpointStatus } from "./proxy";
import { presetCapability, userPreset, poolPreset } from "./presets";
import {
  presetSubmission,
  shapePresetCommand,
  readPresetView,
} from "./remotePresets";
import { routingSubmission, shapeRoutingCommand } from "./remoteRouting";
import { job, shapeCommandInput, submission } from "./targets";
import { SessionController } from "../auth/session";
import {
  NODE,
  USER,
  POOL,
  capabilityFixture,
  userPresetFixture,
  poolPresetFixture,
  presetCommandFixture,
  presetReplyFixture,
  presetTicketFixture,
} from "./presets.fixtures";
const signal = () => new AbortController().signal;

describe("finite managed preset API", () => {
  it("requires actual bounded backend facts, not a platform heuristic", () => {
    expect(
      presetCapability(capabilityFixture(), NODE).available_presets,
    ).toHaveLength(5);
    expect(
      presetCapability({
        ...capabilityFixture(),
        backend_state: "disabled",
        reason_code: "not_configured",
        available_presets: [],
        operations: [],
        abi_version: null,
        observed_at_unix_ms: null,
      }).available_presets,
    ).toEqual([]);
    for (const invalid of [
      { ...capabilityFixture(), capability_version: 2 },
      { ...capabilityFixture(), node_id: USER },
      { ...capabilityFixture(), backend_state: "disabled" },
      { ...capabilityFixture(), available_presets: ["native"] },
      { ...capabilityFixture(), reason_code: "kernel path secret" },
      {
        ...capabilityFixture(),
        backend_state: "disabled",
        reason_code: "not_configured",
        available_presets: [],
        operations: [],
      },
      {
        ...capabilityFixture(),
        backend_state: "unsupported",
        reason_code: "feature_disabled",
        available_presets: [],
        operations: [],
        abi_version: null,
      },
      { ...capabilityFixture(), operations: ["masque_udp"] },
    ])
      expect(() => presetCapability(invalid, NODE)).toThrow(ApiError);
  });
  it("validates explicit native rows, finite unique permissions and matching owners", () => {
    expect(
      userPreset({ user_id: USER, default_preset: null, allowed_presets: [] }),
    ).toMatchObject({ default_preset: null, allowed_presets: [] });
    expect(poolPreset(poolPresetFixture(), POOL).default_preset).toBe(
      "windows",
    );
    for (const invalid of [
      { ...userPresetFixture(), default_preset: "ios" },
      { ...userPresetFixture(), allowed_presets: ["linux", "linux"] },
      { ...userPresetFixture(), allowed_presets: ["native"] },
      { ...userPresetFixture(), secret: "private" },
    ])
      expect(() => userPreset(invalid)).toThrow(ApiError);
    expect(() => userPreset(userPresetFixture(), POOL)).toThrow(ApiError);
  });
  it("keeps endpoint/method/version vocabularies separate", () => {
    for (const path of [
      "/proxy/presets",
      `/proxy/users/${USER}/presets`,
      `/targets/${NODE}/proxy/presets`,
      `/targets/${NODE}/proxy/pools/${POOL}/presets`,
    ])
      expect(endpointStatus(path, "GET")).toBe(200);
    expect(endpointStatus(`/proxy/pools/${POOL}/presets`, "PUT")).toBe(200);
    expect(endpointStatus(`/targets/${NODE}/preset/commands`, "POST")).toEqual([
      200, 202,
    ]);
    for (const [path, method] of [
      ["/proxy/presets?x=1", "GET"],
      ["/proxy/presets?", "GET"],
      [`/targets/${NODE}/proxy/users/${USER}/presets`, "PUT"],
      [`/targets/${NODE}/preset/commands`, "GET"],
      [`/proxy/users/${USER}/presets`, "POST"],
    ] as const)
      expect(() => endpointStatus(path, method)).toThrow(ApiError);
    expect(() => shapeCommandInput(presetCommandFixture() as never)).toThrow(
      ApiError,
    );
    expect(() => shapeRoutingCommand(presetCommandFixture() as never)).toThrow(
      ApiError,
    );
    expect(() =>
      shapePresetCommand({
        ...presetCommandFixture(),
        source_administrator_id: USER,
      } as never),
    ).toThrow(ApiError);
  });
  it("uses exact same-origin PUT/CSRF/CAS bodies and correlates accepted entities", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(
        jsonResponse({ revision: "6", presets: userPresetFixture() }),
      );
    const client = new ManagementClient(fetcher, () => true);
    await client.setUserPresets(
      userPresetFixture(),
      "5",
      "c".repeat(43),
      signal(),
    );
    expect(fetcher).toHaveBeenCalledWith(
      `/api/v1/proxy/users/${USER}/presets`,
      expect.objectContaining({
        method: "PUT",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        body: JSON.stringify({
          expected_revision: "5",
          presets: userPresetFixture(),
        }),
      }),
    );
    expect(
      new Headers(fetcher.mock.calls[0][1]?.headers).get("X-CSRF-Token"),
    ).toBe("c".repeat(43));
    for (const invalid of [
      { revision: "5", presets: userPresetFixture() },
      {
        revision: "6",
        presets: { ...userPresetFixture(), default_preset: null },
      },
      { revision: "6", presets: { ...userPresetFixture(), user_id: POOL } },
    ]) {
      fetcher.mockResolvedValue(jsonResponse(invalid));
      await expect(
        client.setUserPresets(
          userPresetFixture(),
          "5",
          "c".repeat(43),
          signal(),
        ),
      ).rejects.toBeInstanceOf(ApiError);
    }
  });
  it("validates v3 first answers/replays/202 without confusing historical ticket state or leaking secrets", () => {
    const input = presetCommandFixture();
    expect(
      presetSubmission(presetReplyFixture(), NODE, input, 200).response?.receipt
        .status,
    ).toBe("applied");
    expect(
      presetSubmission(
        { job: presetTicketFixture(), response: null },
        NODE,
        input,
        202,
      ).response,
    ).toBeNull();
    const first = presetReplyFixture();
    const { presets: _entity, ...replay } = first.response;
    expect(
      presetSubmission(
        { job: first.job, response: { ...replay, replayed: true } },
        NODE,
        input,
        200,
      ).response?.replayed,
    ).toBe(true);
    const rejected = {
      job: first.job,
      response: {
        ...replay,
        receipt: {
          controller_epoch: "3",
          command_id: "4",
          status: "rejected",
          policy_revision: null,
          rejection: "invalid_policy",
          user_id: null,
          credential_id: null,
        },
      },
    };
    expect(
      presetSubmission(rejected, NODE, input, 200).response?.receipt.status,
    ).toBe("rejected");
    for (const invalid of [
      {
        ...first,
        response: {
          ...first.response,
          secret: "PRIVATE",
          secret_available: true,
        },
      },
      {
        ...first,
        response: {
          ...first.response,
          presets: { kind: "pool", value: poolPresetFixture() },
        },
      },
      {
        ...first,
        response: { ...first.response, preset: poolPresetFixture() },
      },
      { ...first, response: { ...first.response, replayed: true } },
      { ...first, job: { ...first.job, preset: { kind: "user", id: POOL } } },
    ])
      expect(() => presetSubmission(invalid, NODE, input, 200)).toThrow(
        ApiError,
      );
    expect(() =>
      submission(
        {
          job: { ...first.job, preset: { kind: "user", id: USER } },
          response: null,
        },
        NODE,
        { ...input, mutation: { action: "delete_user", id: USER } },
        202,
      ),
    ).toThrow(ApiError);
    expect(() =>
      routingSubmission(
        {
          job: { ...first.job, preset: { kind: "user", id: USER } },
          response: null,
        },
        NODE,
        {
          ...input,
          mutation: { action: "set_pool_state", id: POOL, state: "active" },
        },
        202,
      ),
    ).toThrow(ApiError);
    expect(
      job({ ...first.job, preset: { kind: "user", id: USER } }, NODE)?.preset
        ?.id,
    ).toBe(USER);
    expect(() => job({ ...first.job, preset: null }, NODE)).toThrow(ApiError);
  });
  it("reads remote policy/catalog/entity sequentially and never falls back locally", async () => {
    const paths: string[] = [];
    const policy = {
      controller_node_id: USER,
      controller_epoch: "3",
      last_terminal_command: "3",
      saved_revision: "5",
      applied_revision: null,
      durable_applied_revision: null,
      proxy_running: false,
      user_count: 1,
      credential_count: 1,
    };
    const target = {
      node_id: NODE,
      name: "fixture",
      origin: "https://localhost:9443",
      active: true,
      retired: false,
      revision: "2",
      observed_epoch: null,
      observed_command: null,
      observed_policy_revision: null,
      rollback_detected: false,
    };
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (path) => {
      paths.push(String(path));
      if (String(path).endsWith("/node"))
        return jsonResponse({
          node_id: USER,
          name: "fixture",
          version: "1",
          os: "test",
          arch: "test",
          capabilities: [],
        });
      if (String(path).endsWith("/command")) return jsonResponse(null);
      if (String(path).endsWith("/policy")) return jsonResponse(policy);
      if (String(path).endsWith(`/targets/${NODE}`))
        return jsonResponse(target);
      if (String(path).endsWith(`/users/${USER}/presets`))
        return jsonResponse({ revision: "5", presets: userPresetFixture() });
      return jsonResponse(capabilityFixture());
    });
    await readPresetView(
      new ManagementClient(fetcher, () => true),
      NODE,
      (api, signal) => api.userPresets(USER, signal),
      (value) => value.revision,
      signal(),
    );
    expect(paths).toEqual([
      "/api/v1/node",
      `/api/v1/targets/${NODE}`,
      `/api/v1/targets/${NODE}/command`,
      `/api/v1/targets/${NODE}/policy`,
      `/api/v1/targets/${NODE}/proxy/presets`,
      `/api/v1/targets/${NODE}/proxy/users/${USER}/presets`,
    ]);
    fetcher.mockResolvedValue(
      jsonResponse({ error: { code: "node_protocol_unsupported" } }, 502),
    );
    await expect(
      new ManagementClient(fetcher, () => true).targetPresets(NODE, signal()),
    ).rejects.toMatchObject({ code: "node_protocol_unsupported" });
  });
  it("does not deliver a late v3 mutation across a session generation", async () => {
    let deliver!: (value: Response) => void;
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(sessionFixture()))
      .mockImplementation(
        () =>
          new Promise((resolve) => {
            deliver = resolve;
          }),
      );
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const pending = controller.resource(
      controller.snapshot().session!,
      (client, csrf, signal) =>
        client.targetPresetCommand(NODE, presetCommandFixture(), csrf, signal),
    );
    const rejected = expect(pending).rejects.toMatchObject({
      name: "AbortError",
    });
    controller.cancel();
    deliver(jsonResponse(presetReplyFixture()));
    await rejected;
    expect(controller.generation()).toBeGreaterThan(1);
  });
});
