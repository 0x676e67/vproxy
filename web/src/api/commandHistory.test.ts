import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import {
  commandHistoryDate,
  commandHistoryEntry,
  commandHistoryPage,
  commandHistoryQuery,
} from "./commandHistory";
import {
  historyEntry,
  historyPage,
  HISTORY_LOCAL,
  HISTORY_PEER,
  HISTORY_JOB,
  HISTORY_USER,
  HISTORY_CREDENTIAL,
} from "./commandHistory.fixtures";
import { endpointStatus } from "./proxy";

describe("controller-local remote command history", () => {
  const entry = (value: unknown) =>
    commandHistoryEntry(value, HISTORY_PEER, HISTORY_LOCAL);
  const page = (value: unknown, options = {}) =>
    commandHistoryPage(value, HISTORY_PEER, HISTORY_LOCAL, options);
  it("binds exact job, peer and controller and rejects additional or malformed metadata", () => {
    const value = historyEntry();
    expect(
      commandHistoryEntry(value, HISTORY_PEER, HISTORY_LOCAL, HISTORY_JOB),
    ).toEqual(value);
    for (const patch of [
      { sequence: "0" },
      { sequence: "01" },
      { sequence: "9223372036854775808" },
      { controller_node_id: HISTORY_PEER },
      { administrator_id: "unknown" },
      { protocol_version: 0 },
      { protocol_version: 6 },
      { action: "enable_user" },
      { action: "create_prefix" },
      { protocol_version: 5, action: "set_admission" },
      { imported: "false" },
      { imported: true },
      { recorded_at_unix_s: -1 },
      { updated_at_unix_s: "00" },
      { recorded_at_unix_s: "9223372036854775808" },
      { credential_id: HISTORY_CREDENTIAL },
      { secret: "must-not-pass" },
      { user_id: undefined },
      { job: { ...value.job, password: "must-not-pass" } },
      { job: { ...value.job, node_id: HISTORY_LOCAL } },
      { job: { ...value.job, user_creation: false } },
    ])
      expect(() => entry({ ...value, ...patch })).toThrow(ApiError);
    expect(() =>
      commandHistoryEntry(value, HISTORY_PEER, HISTORY_LOCAL, HISTORY_USER),
    ).toThrow(ApiError);
    expect(
      entry({
        ...value,
        imported: true,
        recorded_at_unix_s: null,
        updated_at_unix_s: null,
        user_id: null,
      }).imported,
    ).toBe(true);
    expect(
      entry({
        ...value,
        recorded_at_unix_s: "0",
        updated_at_unix_s: "9223372036854775807",
      }).recorded_at_unix_s,
    ).toBe("0");
    expect(commandHistoryDate("0")?.toISOString()).toBe(
      "1970-01-01T00:00:00.000Z",
    );
    expect(commandHistoryDate("9223372036854775807")).toBeNull();
  });
  it("keeps typed resources distinct for all five versions, including pending commands without receipts", () => {
    const value = historyEntry();
    const pending = {
      ...value.job,
      user_creation: false,
      state: "pending",
      policy_revision: null,
    };
    for (const [version, action, extra] of [
      [2, "create_pool", {}],
      [3, "set_user_presets", {}],
      [5, "set_admission", { maintenance: { accepting: false } }],
    ] as const) {
      const row = {
        ...value,
        protocol_version: version,
        action,
        job: { ...pending, ...extra },
        user_id: null,
      };
      expect(entry(row).job.state).toBe("pending");
      expect(() => entry({ ...row, user_id: HISTORY_USER })).toThrow(ApiError);
    }
    const saved = { ...pending, state: "saved", policy_revision: "10" };
    for (const [version, action, extra] of [
      [2, "set_pool_state", { routing: { kind: "pool", id: HISTORY_USER } }],
      [3, "set_user_presets", { preset: { kind: "user", id: HISTORY_USER } }],
    ] as const) {
      const row = {
        ...value,
        protocol_version: version,
        action,
        job: { ...saved, ...extra },
        user_id: null,
      };
      expect(entry(row).job.state).toBe("saved");
      expect(() => entry({ ...row, job: saved })).toThrow(ApiError);
    }
    const metadata = {
      ...value,
      protocol_version: 4,
      action: "set_public_address",
      user_id: null,
      job: {
        ...pending,
        resource: "proxy_endpoints",
        expected_policy_revision: null,
        expected_metadata_revision: "3",
        metadata_revision: null,
        endpoint: { listener_id: HISTORY_USER, generation: "ab".repeat(32) },
      },
    };
    expect(entry(metadata).job.resource).toBe("proxy_endpoints");
    expect(() =>
      entry({ ...metadata, protocol_version: 1, action: "update_user" }),
    ).toThrow(ApiError);
  });
  it("checks descending exclusive pagination and the retained floor without inventing missing history", () => {
    const newer = historyEntry(),
      older = {
        ...historyEntry(),
        sequence: "6",
        job: { ...historyEntry().job, job_id: HISTORY_USER },
      };
    expect(page(historyPage()).items).toHaveLength(1);
    const first = {
      items: [newer],
      next_cursor: "7",
      oldest_sequence: "6",
      trimmed: true,
    };
    expect(page(first, { limit: 1 }).next_cursor).toBe("7");
    expect(
      page(
        { ...historyPage(), items: [older], oldest_sequence: "6" },
        { before: "7" },
      ).items[0].sequence,
    ).toBe("6");
    expect(
      page(
        { items: [], next_cursor: null, oldest_sequence: "6", trimmed: true },
        { before: "6" },
      ).items,
    ).toEqual([]);
    for (const value of [
      { ...first, next_cursor: "6" },
      { ...first, oldest_sequence: null },
      { ...first, trimmed: "true" },
      { ...historyPage(), oldest_sequence: "8" },
      { ...historyPage(), next_cursor: "7" },
      {
        items: [older, newer],
        next_cursor: null,
        oldest_sequence: "6",
        trimmed: false,
      },
      {
        items: [newer, { ...older, job: newer.job }],
        next_cursor: null,
        oldest_sequence: "6",
        trimmed: false,
      },
      { ...historyPage(), payload: {} },
    ])
      expect(() => page(value)).toThrow(ApiError);
    expect(() => page(first, { before: "7", limit: 1 })).toThrow(ApiError);
  });
  it("allows only canonical read-only history paths and bounded pagination", () => {
    const path = `/targets/${HISTORY_PEER}/commands/history`;
    expect(commandHistoryQuery({ before: "7", limit: 50 })).toBe(
      "?before=7&limit=50",
    );
    expect(endpointStatus(`${path}?before=7&limit=50`, "GET")).toBe(200);
    expect(endpointStatus(`${path}/${HISTORY_JOB}`, "GET")).toBe(200);
    for (const query of [
      "?",
      "?before=0",
      "?limit=51",
      "?limit=1&limit=2",
      "?before=7&%62efore=6",
      "?latest=true",
      "?limit=01",
    ]) {
      expect(() => endpointStatus(path + query, "GET")).toThrow(ApiError);
    }
    expect(() => endpointStatus(path, "POST")).toThrow(ApiError);
    expect(() =>
      endpointStatus(`${path}/${HISTORY_JOB}?limit=1`, "GET"),
    ).toThrow(ApiError);
    for (const options of [
      { before: "00" },
      { limit: 0 },
      { limit: 51 },
      { limit: 1.5 },
      { latest: true },
    ])
      expect(() => commandHistoryQuery(options)).toThrow(ApiError);
  });
  it("reads only the original local paths, keeps 404 unknown and rejects mismatched exact results", async () => {
    let response = jsonResponse(historyPage());
    const fetcher = vi.fn(async () => response),
      client = new ManagementClient(fetcher, () => true),
      signal = new AbortController().signal;
    await client.targetCommandHistory(
      HISTORY_PEER,
      HISTORY_LOCAL,
      { limit: 20 },
      signal,
    );
    expect(fetcher).toHaveBeenLastCalledWith(
      `/api/v1/targets/${HISTORY_PEER}/commands/history?limit=20`,
      expect.objectContaining({
        method: "GET",
        cache: "no-store",
        credentials: "same-origin",
        redirect: "error",
      }),
    );
    response = jsonResponse(historyEntry());
    await client.targetCommandHistoryEntry(
      HISTORY_PEER,
      HISTORY_LOCAL,
      HISTORY_JOB,
      signal,
    );
    expect(fetcher).toHaveBeenLastCalledWith(
      `/api/v1/targets/${HISTORY_PEER}/commands/history/${HISTORY_JOB}`,
      expect.objectContaining({ method: "GET" }),
    );
    response = jsonResponse({ error: { code: "resource_not_found" } }, 404);
    await expect(
      client.targetCommandHistoryEntry(
        HISTORY_PEER,
        HISTORY_LOCAL,
        HISTORY_JOB,
        signal,
      ),
    ).rejects.toMatchObject({ status: 404, code: "resource_not_found" });
    response = jsonResponse({
      ...historyEntry(),
      job: { ...historyEntry().job, job_id: HISTORY_USER },
    });
    await expect(
      client.targetCommandHistoryEntry(
        HISTORY_PEER,
        HISTORY_LOCAL,
        HISTORY_JOB,
        signal,
      ),
    ).rejects.toMatchObject({ kind: "format" });
    const calls = fetcher.mock.calls.length;
    await expect(
      client.targetCommandHistoryEntry(
        HISTORY_PEER,
        HISTORY_LOCAL,
        "invalid",
        signal,
      ),
    ).rejects.toBeInstanceOf(ApiError);
    expect(fetcher).toHaveBeenCalledTimes(calls);
  });
  it("admits a bounded 50-row history response above 32 KiB without raising other endpoint budgets", async () => {
    const items = Array.from({ length: 50 }, (_, index) => ({
      ...historyEntry(),
      // Use legitimate maximum-width metadata, not a secret or padding field.
      sequence: String(9_223_372_036_854_775_807n - BigInt(index)),
      recorded_at_unix_s: "9223372036854775807",
      updated_at_unix_s: "9223372036854775807",
      job: {
        ...historyEntry().job,
        job_id: `${String(index).padStart(21, "0")}A`,
        controller_epoch: "9223372036854775807",
        command_id: "9223372036854775807",
        expected_policy_revision: "9223372036854775806",
        policy_revision: "9223372036854775807",
        attempts: 4_294_967_295,
      },
    }));
    const value = {
      items,
      next_cursor: null,
      oldest_sequence: items.at(-1)!.sequence,
      trimmed: true,
    };
    expect(
      new TextEncoder().encode(JSON.stringify(value)).length,
    ).toBeGreaterThan(32_768);
    const client = new ManagementClient(
        async () => jsonResponse(value),
        () => true,
      ),
      signal = new AbortController().signal;
    expect(
      (
        await client.targetCommandHistory(
          HISTORY_PEER,
          HISTORY_LOCAL,
          { limit: 50 },
          signal,
        )
      ).items,
    ).toHaveLength(50);
    // A valid job with harmless JSON whitespace would parse successfully if
    // the ordinary endpoint's independent 32-KiB limit were accidentally raised.
    const ordinary = new ManagementClient(
      async () =>
        new Response(" ".repeat(32_768) + JSON.stringify(items[0].job), {
          headers: { "Content-Type": "application/json" },
        }),
      () => true,
    );
    await expect(
      ordinary.targetJob(HISTORY_PEER, signal),
    ).rejects.toMatchObject({
      kind: "format",
    });
    const oversized = new ManagementClient(
      async () => jsonResponse({ padding: "x".repeat(131_072) }),
      () => true,
    );
    await expect(
      oversized.targetCommandHistory(HISTORY_PEER, HISTORY_LOCAL, {}, signal),
    ).rejects.toMatchObject({ kind: "format" });
  });
});
