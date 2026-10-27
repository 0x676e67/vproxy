import { describe, expect, it, vi } from "vitest";
import { ManagementClient, ApiError } from "./client";
import { jsonResponse, sessionFixture } from "./client.fixtures";
import { endpointStatus } from "./proxy";
import {
  maintenanceChange,
  maintenanceStatus,
  maintenanceSubmission,
  maintenanceJob,
} from "./maintenance";
import {
  LOCAL,
  PEER,
  JOB,
  maintenanceFixture,
  maintenanceCommandFixture,
  maintenanceJobFixture,
  maintenanceReplyFixture,
} from "./maintenance.fixtures";
import { job, submission } from "./targets";
import { routingSubmission } from "./remoteRouting";
import { presetSubmission } from "./remotePresets";
import {
  observedJob,
  ticketMetadata,
  matchesTicket,
} from "../auth/routing-changes";

describe("maintenance API facts and one-shot commands", () => {
  it("addresses receipt refresh by the exact retained job and refuses a replacement or non-maintenance reply without fallback", async () => {
    let value: unknown = maintenanceJobFixture();
    const fetcher = vi.fn(async () => jsonResponse(value));
    const client = new ManagementClient(fetcher, () => true),
      signal = new AbortController().signal,
      csrf = sessionFixture().csrf_token;
    expect(
      (await client.maintenanceRefresh(PEER, JOB, csrf, signal)).maintenance
        .accepting,
    ).toBe(false);
    expect(fetcher).toHaveBeenLastCalledWith(
      `/api/v1/targets/${PEER}/maintenance/commands/refresh`,
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ job_id: JOB }),
        redirect: "error",
      }),
    );
    value = { ...maintenanceJobFixture(), job_id: LOCAL };
    await expect(
      client.maintenanceRefresh(PEER, JOB, csrf, signal),
    ).rejects.toBeInstanceOf(ApiError);
    const other = { ...maintenanceJobFixture() };
    delete other.maintenance;
    value = other;
    await expect(
      client.maintenanceRefresh(PEER, JOB, csrf, signal),
    ).rejects.toBeInstanceOf(ApiError);
    await expect(
      client.maintenanceRefresh(PEER, "not-an-id", csrf, signal),
    ).rejects.toBeInstanceOf(ApiError);
    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(
      endpointStatus(`/targets/${PEER}/maintenance/commands/refresh`, "POST"),
    ).toBe(200);
    expect(() =>
      endpointStatus(`/targets/${PEER}/maintenance/commands/refresh`, "GET"),
    ).toThrow(ApiError);
  });
  it("binds the node, keeps full-u64 counts and requires a coherent optional runtime observation", () => {
    expect(
      maintenanceStatus(maintenanceFixture(), LOCAL).active_operations,
    ).toBe("3");
    expect(
      maintenanceStatus(
        { ...maintenanceFixture(), active_operations: "18446744073709551615" },
        LOCAL,
      ).active_operations,
    ).toBe("18446744073709551615");
    const unknown = {
      ...maintenanceFixture(),
      applied_revision: null,
      runtime_accepting: null,
      active_operations: null,
    };
    expect(maintenanceStatus(unknown, LOCAL)).toEqual(unknown);
    expect(
      maintenanceStatus({ ...unknown, running: false }, LOCAL).running,
    ).toBe(false);
    for (const patch of [
      { node_id: PEER },
      { saved_revision: "9223372036854775808" },
      { ownership: { ...unknown.ownership, epoch: "0" } },
      { ownership: { ...unknown.ownership, controller_node_id: LOCAL } },
      { active_operations: "00" },
      { active_operations: "-1" },
      { active_operations: "18446744073709551616" },
      { active_operations: 3 },
      { applied_revision: null },
      { runtime_accepting: null },
      { active_operations: null },
      { runtime_accepting: false },
      { applied_revision: "8" },
      { running: false },
      { durable_applied_revision: "10" },
      { drained: true },
    ])
      expect(() =>
        maintenanceStatus({ ...maintenanceFixture(), ...patch }, LOCAL),
      ).toThrow(ApiError);
  });
  it("separates a write acknowledgement from runtime/count observation and binds the original CAS", () => {
    const input = {
      expected_node_id: LOCAL,
      expected_revision: "9",
      expected_epoch: "2",
      accepting: false,
    };
    expect(
      maintenanceChange(
        { saved_revision: "10", applied_revision: "10", running: true },
        input,
      ),
    ).toEqual({ saved_revision: "10", applied_revision: "10", running: true });
    for (const value of [
      { saved_revision: "10", applied_revision: null, running: true },
      { saved_revision: "10", applied_revision: "9", running: true },
      { saved_revision: "9", applied_revision: null, running: true },
      { saved_revision: "10", applied_revision: "11", running: true },
      { saved_revision: "10", applied_revision: "10", running: false },
      {
        saved_revision: "10",
        applied_revision: null,
        running: true,
        active_operations: "0",
      },
    ])
      expect(() => maintenanceChange(value, input)).toThrow(ApiError);
  });
  it("retains false intent, rejects mixed command families and never exposes a credential result", () => {
    const raw = maintenanceJobFixture();
    expect(maintenanceJob(raw, PEER).maintenance.accepting).toBe(false);
    expect(observedJob(raw)?.maintenance).toEqual({ accepting: false });
    expect(ticketMetadata(raw)).toBeNull();
    const legacy = { ...raw };
    delete legacy.maintenance;
    const legacyTicket = ticketMetadata(legacy)!;
    expect(matchesTicket(legacyTicket, raw)).toBe(false);
    for (const patch of [
      { maintenance: null },
      { maintenance: { accepting: null } },
      { maintenance: { accepting: false, password: "not-retained" } },
      { user_creation: true },
      { routing: { kind: "pool", id: JOB } },
      { preset: { kind: "pool", id: JOB } },
    ])
      expect(() => job({ ...raw, ...patch }, PEER)).toThrow(ApiError);
    const input = maintenanceCommandFixture();
    expect(
      maintenanceSubmission({ job: raw, response: null }, PEER, input, 202)
        .response,
    ).toBeNull();
    expect(
      maintenanceSubmission(maintenanceReplyFixture(), PEER, input, 200)
        .response,
    ).toEqual({ status: "applied" });
    const value = { job: raw, response: null };
    expect(() =>
      submission(
        value,
        PEER,
        { ...input, mutation: { action: "delete_user", id: JOB } },
        202,
      ),
    ).toThrow(ApiError);
    expect(() =>
      routingSubmission(
        value,
        PEER,
        { ...input, mutation: { action: "retire_prefix", id: JOB } },
        202,
      ),
    ).toThrow(ApiError);
    expect(() =>
      presetSubmission(
        value,
        PEER,
        {
          ...input,
          mutation: {
            action: "set_pool_preset",
            preset: { pool_id: JOB, default_preset: null },
          },
        },
        202,
      ),
    ).toThrow(ApiError);
    for (const patch of [
      { controller_epoch: "3" },
      { command_id: "9" },
      { expected_policy_revision: "8" },
      { maintenance: { accepting: true } },
    ])
      expect(() =>
        maintenanceSubmission(
          { job: { ...raw, ...patch }, response: null },
          PEER,
          input,
          202,
        ),
      ).toThrow(ApiError);
    for (const secret of ["not-for-output", null]) {
      const reply = maintenanceReplyFixture();
      expect(() =>
        maintenanceSubmission(
          {
            ...reply,
            response: { ...reply.response, secret, secret_available: true },
          },
          PEER,
          input,
          200,
        ),
      ).toThrow(ApiError);
    }
    expect(() => maintenanceSubmission(value, PEER, input, 200)).toThrow(
      ApiError,
    );
    expect(() =>
      maintenanceSubmission(maintenanceReplyFixture(), PEER, input, 202),
    ).toThrow(ApiError);
  });
  it("uses fixed endpoints once, sends all CAS bindings, and refuses invalid input before fetch", async () => {
    const calls: { path: string; init?: RequestInit }[] = [];
    const fetcher = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input);
        calls.push({ path, init });
        if (path === "/api/v1/proxy/maintenance")
          return init?.method === "POST"
            ? jsonResponse({
                saved_revision: "10",
                applied_revision: "10",
                running: true,
              })
            : jsonResponse(maintenanceFixture());
        if (path === `/api/v1/targets/${PEER}/proxy/maintenance`)
          return jsonResponse(maintenanceFixture(true));
        return jsonResponse(
          { job: maintenanceJobFixture(), response: null },
          202,
        );
      },
    );
    const client = new ManagementClient(fetcher, () => true);
    const signal = new AbortController().signal,
      csrf = sessionFixture().csrf_token;
    await client.maintenance(LOCAL, null, signal);
    await client.maintenance(PEER, PEER, signal);
    await client.setMaintenance(
      {
        expected_node_id: LOCAL,
        expected_revision: "9",
        expected_epoch: "2",
        accepting: false,
      },
      csrf,
      signal,
    );
    await client.targetMaintenanceCommand(
      PEER,
      maintenanceCommandFixture(),
      csrf,
      signal,
    );
    expect(calls.map((value) => [value.path, value.init?.method])).toEqual([
      ["/api/v1/proxy/maintenance", "GET"],
      [`/api/v1/targets/${PEER}/proxy/maintenance`, "GET"],
      ["/api/v1/proxy/maintenance", "POST"],
      [`/api/v1/targets/${PEER}/maintenance/commands`, "POST"],
    ]);
    expect(JSON.parse(calls[3].init!.body as string)).toEqual(
      maintenanceCommandFixture(),
    );
    expect(calls[3].init!.headers).toMatchObject({ "X-CSRF-Token": csrf });
    await expect(
      client.maintenance(LOCAL, PEER, signal),
    ).rejects.toBeInstanceOf(ApiError);
    await expect(
      client.setMaintenance(
        {
          expected_node_id: LOCAL,
          expected_revision: "09",
          expected_epoch: "2",
          accepting: false,
        },
        csrf,
        signal,
      ),
    ).rejects.toBeInstanceOf(ApiError);
    await expect(
      client.targetMaintenanceCommand(
        PEER,
        {
          ...maintenanceCommandFixture(),
          mutation: {
            action: "set_admission",
            accepting: null as unknown as boolean,
          },
        },
        csrf,
        signal,
      ),
    ).rejects.toBeInstanceOf(ApiError);
    expect(fetcher).toHaveBeenCalledTimes(4);
    expect(
      endpointStatus(`/targets/${PEER}/maintenance/commands`, "POST"),
    ).toEqual([200, 202]);
  });
  it("does not fall back or repeat a failed write, including an older server's 404", async () => {
    for (const response of [
      () => jsonResponse({ error: { code: "resource_not_found" } }, 404),
      () => Promise.reject(new TypeError("private-network-marker")),
      () =>
        jsonResponse({
          ...maintenanceReplyFixture(),
          password: "private-response-marker",
        }),
    ]) {
      const fetcher = vi.fn(async () => response());
      const client = new ManagementClient(fetcher, () => true);
      await expect(
        client.targetMaintenanceCommand(
          PEER,
          maintenanceCommandFixture(),
          sessionFixture().csrf_token,
          new AbortController().signal,
        ),
      ).rejects.toBeInstanceOf(ApiError);
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
  });
});
