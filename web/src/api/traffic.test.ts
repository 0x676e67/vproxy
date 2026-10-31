import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse, sessionFixture } from "./client.fixtures";
import { endpointStatus } from "./proxy";
import { SessionController } from "../auth/session";
import {
  compactBytes,
  checkpointStages,
  exactBytes,
  readTrafficView,
  remoteTraffic,
  trafficHistory,
  trafficHref,
  trafficLocation,
  trafficQuery,
  trafficTotals,
  type TrafficScope,
} from "./traffic";

const NODE = "A".repeat(22);
const SUBJECT = "AQEBAQEBAQEBAQEBAQEBAQ";
const EPOCH = "AgICAgICAgICAgICAgICAg";
const node: TrafficScope = { kind: "node", id: null };
const metadata = () => ({
  definition: "accepted_effective_payload_v1",
  origin_node_id: NODE,
  meter_epoch: EPOCH,
  meter_started_at_unix_ms: 1,
  checkpoint_cursor: "9007199254740993",
  last_checkpoint_at_unix_ms: 60_000,
  last_run_clean: false,
  loss_possible: true,
  history_gap: true,
  time_uncertain: false,
  observed_at_unix_ms: 120_000,
  scope: node,
});
const totals = (active = false) => ({
  ...metadata(),
  active_run_id: active ? SUBJECT : null,
  checkpoint_error: false,
  last_completed_cycle_at_unix_ms: active ? 60_000 : null,
  last_completed_cycle_age_millis: active ? 5000 : null,
  items: (["http", "socks5", "masque"] as const).map((protocol) => ({
    protocol,
    durable_upload_bytes: "9007199254740993",
    durable_download_bytes: "0",
    durable_saturated: false,
    live_upload_bytes: active ? "9007199254740994" : null,
    live_download_bytes: active ? "0" : null,
    live_saturated: active ? false : null,
  })),
});
const history = () => ({
  ...metadata(),
  resolution: "minute",
  next_cursor: null,
  retention_floor: "0",
  retention_gap: false,
  items: [0, 120_000].map((window) => ({
    window_id: String(window),
    items: [
      {
        protocol: "http",
        upload_bytes: "0",
        download_bytes: "9007199254740993",
        saturated: false,
      },
    ],
  })),
});
const splitTotals = (active = false) => ({
  ...totals(active),
  http_split: true,
  items: ["http_legacy", "socks5", "masque", "http", "https"].map(
    (protocol) => ({ ...totals(active).items[0], protocol }),
  ),
});
const splitHistory = () => ({ ...history(), http_split: true });
const signal = () => new AbortController().signal;
const remote = (data: unknown, state = "ready", cached = true) => ({
  source: {
    origin_node_id: NODE,
    cached,
    collector_available: true,
    state,
    last_success_at_unix_ms: null,
    age_millis: null,
    target_revision: "1",
  },
  data,
});

describe("accepted-payload traffic contract", () => {
  it("requests split counters explicitly and keeps legacy totals separate from HTTP and HTTPS", () => {
    expect(trafficQuery(node, { protocol: "https" }, false, true)).toBe(
      "?scope=node&protocol_format=split&protocol=https",
    );
    expect(() => trafficQuery(node, { protocol: "https" })).toThrow(ApiError);
    for (const suffix of [
      "protocol_format=v2",
      "protocol_format=split&protocol_format=split",
      "protocol=http_legacy",
      "protocol=https",
    ])
      expect(() => endpointStatus(`/proxy/traffic?${suffix}`, "GET")).toThrow(
        ApiError,
      );
    const wire = splitTotals();
    wire.items = wire.items.map((row, index) => ({
      ...row,
      durable_upload_bytes: String(index + 1),
    }));
    const parsed = trafficTotals(wire, node, undefined, true);
    expect(
      parsed.items.map((row) => [row.protocol, row.durable_upload_bytes]),
    ).toEqual([
      ["http", "4"],
      ["https", "5"],
      ["socks5", "2"],
      ["masque", "3"],
      ["http_legacy", "1"],
    ]);
    expect(() =>
      trafficTotals({ ...wire, http_split: undefined }, node, undefined, true),
    ).toThrow(ApiError);
    expect(() =>
      trafficTotals(
        { ...wire, items: [wire.items[4], ...wire.items.slice(1)] },
        node,
        undefined,
        true,
      ),
    ).toThrow(ApiError);
    const legacy = {
      ...totals(),
      http_split: false,
      items: totals().items.map((row, index) => ({
        ...row,
        protocol: index === 0 ? "http_legacy" : row.protocol,
      })),
    };
    const old = trafficTotals(legacy, node, undefined, true);
    expect(old.http_split).toBe(false);
    expect(old.items.map((row) => row.protocol)).toEqual([
      "socks5",
      "masque",
      "http_legacy",
    ]);
    expect(
      trafficTotals({ ...legacy, items: [] }, node, "https", true).items,
    ).toEqual([]);
    expect(() =>
      trafficTotals({ ...legacy, items: wire.items }, node, undefined, true),
    ).toThrow(ApiError);
  });

  it("validates both history protocols without inventing unsupported legacy samples", () => {
    const wire = splitHistory();
    wire.items[0].items.push({
      ...wire.items[0].items[0],
      protocol: "https",
      upload_bytes: "17",
    });
    const parsed = trafficHistory(wire, node, { resolution: "minute" }, true);
    expect(parsed.items[0].items.map((row) => row.protocol)).toEqual([
      "http",
      "https",
    ]);
    expect(() =>
      trafficHistory(
        wire,
        node,
        { resolution: "minute", protocol: "http" },
        true,
      ),
    ).toThrow(ApiError);
    expect(() =>
      trafficHistory(
        { ...wire, http_split: false },
        node,
        { resolution: "minute" },
        true,
      ),
    ).toThrow(ApiError);
  });
  it("accepts optional bounded local stages without trusting remote process health", () => {
    expect(
      trafficTotals(totals(), node).checkpoint_failure_stage,
    ).toBeUndefined();
    expect(
      trafficTotals({ ...totals(), checkpoint_failure_stage: null }, node)
        .checkpoint_failure_stage,
    ).toBeNull();
    for (const stage of checkpointStages) {
      const value = {
        ...totals(),
        checkpoint_error: true,
        checkpoint_failure_stage: stage,
      };
      expect(trafficTotals(value, node).checkpoint_failure_stage).toBe(stage);
      expect(() =>
        remoteTraffic(remote(value), NODE, node, (data) =>
          trafficTotals(data, node),
        ),
      ).toThrow(ApiError);
      expect(() =>
        trafficTotals({ ...value, checkpoint_error: false }, node),
      ).toThrow(ApiError);
    }
    for (const stage of [
      "sqlite_busy",
      "private diagnostic",
      {},
      1,
      undefined,
    ]) {
      expect(() =>
        trafficTotals(
          {
            ...totals(),
            checkpoint_error: true,
            checkpoint_failure_stage: stage,
          },
          node,
        ),
      ).toThrow(ApiError);
    }
  });

  it("keeps exact cumulative strings, unknown live counters and persisted warnings separate", () => {
    const result = trafficTotals(totals(), node);
    expect(result.items[0].durable_upload_bytes).toBe("9007199254740993");
    expect(result.items[0].live_upload_bytes).toBeNull();
    expect(result.items[0].durable_download_bytes).toBe("0");
    expect(result.loss_possible).toBe(true);
    expect(trafficTotals(totals(true), node).items[0].live_upload_bytes).toBe(
      "9007199254740994",
    );
    for (const invalid of [
      { ...totals(), definition: "wire_bytes" },
      { ...totals(), scope: { kind: "user", id: SUBJECT } },
      { ...totals(), secret: "unexpected" },
      {
        ...totals(),
        items: [{ ...totals().items[0], live_upload_bytes: "0" }],
      },
      {
        ...totals(),
        items: totals().items.map((row) => ({
          ...row,
          durable_upload_bytes: 9007199254740992,
        })),
      },
      {
        ...totals(),
        items: totals().items.map((row) => ({
          ...row,
          durable_upload_bytes: "18446744073709551616",
        })),
      },
      {
        ...totals(true),
        items: totals(true).items.map((row) => ({
          ...row,
          live_upload_bytes: "1",
        })),
      },
    ])
      expect(() => trafficTotals(invalid, node)).toThrow(ApiError);
  });

  it("strictly limits methods, scope IDs, query vocabulary, windows and page sizes", () => {
    expect(trafficQuery(node)).toBe("?scope=node");
    expect(
      trafficQuery(
        { kind: "pool", id: SUBJECT },
        { resolution: "day", after: "0", limit: 50 },
        true,
      ),
    ).toContain("after=0");
    for (const endpoint of [
      "/proxy/traffic?scope=node&id=" + SUBJECT,
      "/proxy/traffic?scope=user",
      "/proxy/traffic?scope=unknown",
      "/proxy/traffic?scope=user&id=AAAAAAAAAAAAAAAAAAAAAB",
      "/proxy/traffic?scope=node&%73cope=node",
      "/proxy/traffic?__proto__=node",
      "/proxy/traffic?protocol=HTTP",
      "/proxy/traffic?limit=1",
      "/proxy/traffic?after=0",
      "/proxy/traffic/buckets?scope=credential&id=" + SUBJECT,
      "/proxy/traffic/buckets?limit=0",
      "/proxy/traffic/buckets?limit=51",
      "/proxy/traffic/buckets?after=01",
      "/proxy/traffic/buckets?after=9007199254740992",
      "/proxy/traffic/buckets?after=0&after=0",
      "/proxy/traffic/buckets?resolution=week",
      `/targets/${SUBJECT}/proxy/traffic`,
    ])
      expect(() => endpointStatus(endpoint, "GET"), endpoint).toThrow(ApiError);
    expect(() => endpointStatus("/proxy/traffic", "POST")).toThrow(ApiError);
    expect(() => trafficQuery(node, { limit: "1" } as never, true)).toThrow(
      ApiError,
    );
    expect(
      endpointStatus("/proxy/traffic/buckets?after=0&limit=50", "GET"),
    ).toBe(200);
  });

  it("does not invent a missing bucket or protocol, and validates cursor association", () => {
    const result = trafficHistory(history(), node, { resolution: "minute" });
    expect(result.items.map((row) => row.window_id)).toEqual(["0", "120000"]);
    expect(result.items[0].items).toHaveLength(1);
    expect(result.items[0].items[0].upload_bytes).toBe("0");
    const missing = {
      ...history(),
      items: [{ window_id: "120000", items: [] }],
    };
    expect(
      trafficHistory(missing, node, {
        resolution: "minute",
        protocol: "socks5",
      }).items[0].items,
    ).toEqual([]);
    for (const invalid of [
      { ...history(), next_cursor: "120000" },
      { ...history(), retention_gap: true },
      { ...history(), items: [history().items[1], history().items[0]] },
      { ...history(), items: [{ ...history().items[0], window_id: "1" }] },
      {
        ...history(),
        items: [
          {
            window_id: "0",
            items: [history().items[0].items[0], history().items[0].items[0]],
          },
        ],
      },
    ])
      expect(() =>
        trafficHistory(invalid, node, { resolution: "minute" }),
      ).toThrow(ApiError);
    expect(() =>
      trafficHistory(history(), node, { resolution: "minute", after: "0" }),
    ).toThrow(ApiError);
  });

  it("formats values above Number precision using BigInt and retains exact bytes", () => {
    expect(exactBytes("9007199254740993", "en-US")).toBe(
      "9,007,199,254,740,993 B",
    );
    expect(exactBytes("18446744073709551615", "en-US")).toBe(
      "18,446,744,073,709,551,615 B",
    );
    expect(compactBytes("16384", "en-US")).toBe("16.00 KiB");
    expect(compactBytes("16385", "en-US")).toBe("≈ 16.00 KiB");
    expect(compactBytes("0", "en-US")).toBe("0 B");
    expect(compactBytes(null, "en-US")).toBe("—");
    for (const value of ["-1", "01", "18446744073709551616"])
      expect(() => exactBytes(value, "en-US")).toThrow(ApiError);
  });

  it("uses fixed same-origin GETs and bounded maximum-size history responses", async () => {
    const maximum = {
      ...splitHistory(),
      next_cursor: "2940000",
      items: Array.from({ length: 50 }, (_, index) => ({
        window_id: String(index * 60_000),
        items: ["http_legacy", "socks5", "masque", "http", "https"].map(
          (protocol) => ({
            protocol,
            upload_bytes: "18446744073709551615",
            download_bytes: "18446744073709551615",
            saturated: true,
          }),
        ),
      })),
    };
    expect(
      new TextEncoder().encode(JSON.stringify(maximum)).length,
    ).toBeLessThan(64 * 1024);
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(maximum));
    const client = new ManagementClient(fetcher, () => true);
    const result = await client.trafficBuckets(
      node,
      { resolution: "minute", limit: 50 },
      signal(),
    );
    expect(result.items).toHaveLength(50);
    expect(result.items[49].items[0].upload_bytes).toBe("18446744073709551615");
    expect(fetcher).toHaveBeenCalledWith(
      "/api/v1/proxy/traffic/buckets?scope=node&protocol_format=split&resolution=minute&limit=50",
      expect.objectContaining({
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
      }),
    );
    expect(fetcher.mock.calls[0][1]?.headers).toEqual({
      Accept: "application/json",
    });
  });

  it("reads local and remote chains sequentially, never replacing a pending or failed peer with local data", async () => {
    const calls: string[] = [];
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (input) => {
      calls.push(String(input));
      return jsonResponse(
        String(input).includes("/buckets") ? splitHistory() : splitTotals(),
      );
    });
    const client = new ManagementClient(fetcher, () => true);
    await readTrafficView(
      client,
      null,
      node,
      { resolution: "minute" },
      signal(),
    );
    expect(calls).toEqual([
      "/api/v1/proxy/traffic?scope=node&protocol_format=split",
      "/api/v1/proxy/traffic/buckets?scope=node&protocol_format=split&resolution=minute",
    ]);
    fetcher.mockClear();
    fetcher.mockResolvedValue(jsonResponse(remote(null, "pending")));
    const pending = await readTrafficView(client, NODE, node, {}, signal());
    expect(pending.totals).toBeNull();
    expect(pending.history).toBeNull();
    expect(pending.totalsSource).toMatchObject({
      state: "pending",
      cached: true,
      age_millis: null,
    });
    expect(fetcher.mock.calls.map(([input]) => input)).toEqual([
      `/api/v1/targets/${NODE}/traffic?scope=node&protocol_format=split`,
      `/api/v1/targets/${NODE}/traffic/buckets?scope=node&protocol_format=split`,
    ]);
    fetcher
      .mockClear()
      .mockResolvedValue(
        jsonResponse({ error: { code: "remote_traffic_unsupported" } }, 503),
      );
    await expect(
      readTrafficView(client, NODE, node, {}, signal()),
    ).rejects.toMatchObject({ code: "remote_traffic_unsupported" });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(String(fetcher.mock.calls[0][0])).toContain(
      `/targets/${NODE}/traffic`,
    );
    fetcher.mockClear();
    fetcher.mockResolvedValue(
      jsonResponse({ error: { code: "traffic_unavailable" } }, 503),
    );
    await expect(
      readTrafficView(client, null, node, {}, signal()),
    ).rejects.toMatchObject({ code: "traffic_unavailable" });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("rejects mixed meter epochs rather than mixing restart/incarnation snapshots", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(splitTotals()))
      .mockResolvedValueOnce(
        jsonResponse({ ...splitHistory(), meter_epoch: SUBJECT }),
      );
    const result = await readTrafficView(
      new ManagementClient(fetcher, () => true),
      null,
      node,
      { resolution: "minute" },
      signal(),
    );
    expect(result.totals?.meter_epoch).toBe(EPOCH);
    expect(result.history).toBeNull();
    expect(result.historyError).toMatchObject({ code: "traffic_changed" });
  });

  it("retains explicitly historical remote cache for offline, revoked, paused and continuity states", async () => {
    for (const state of [
      "stale",
      "unavailable",
      "unsupported",
      "not_authorized",
      "paused",
      "continuity_error",
    ]) {
      const fetcher = vi
        .fn<typeof fetch>()
        .mockImplementation(async (input) =>
          jsonResponse(
            remote(
              String(input).includes("/buckets")
                ? splitHistory()
                : splitTotals(),
              state,
            ),
          ),
        );
      const result = await readTrafficView(
        new ManagementClient(fetcher, () => true),
        NODE,
        node,
        { resolution: "minute" },
        signal(),
      );
      expect(result.totalsSource?.state).toBe(state);
      expect(result.totalsSource?.age_millis).toBeNull();
      expect(result.totals?.items[0].durable_upload_bytes).toBe(
        "9007199254740993",
      );
      expect(result.totals?.items[0].live_upload_bytes).toBeNull();
      expect(result.historySource?.state).toBe(state);
      expect(
        fetcher.mock.calls.every(([input]) =>
          String(input).startsWith(`/api/v1/targets/${NODE}/traffic`),
        ),
      ).toBe(true);
    }
  });

  it("does not infer remote loss or a stopped process from an open durable run marker", () => {
    const durable = {
      ...totals(),
      last_run_clean: false,
      loss_possible: false,
    };
    const result = remoteTraffic(remote(durable), NODE, node, (value) =>
      trafficTotals(value, node),
    );
    expect(result.data?.last_run_clean).toBe(false);
    expect(result.data?.active_run_id).toBeNull();
    expect(result.data?.loss_possible).toBe(false);
    expect(
      result.data?.items.every((row) => row.live_upload_bytes === null),
    ).toBe(true);
  });

  it("binds remote provenance and durable-only data to the selected node and entity", async () => {
    for (const invalid of [
      {
        ...remote(totals()),
        source: { ...remote(null).source, origin_node_id: SUBJECT },
      },
      { ...remote(totals()), data: { ...totals(), origin_node_id: SUBJECT } },
      {
        ...remote(totals()),
        source: { ...remote(null).source, cached: false },
      },
      remote(totals(true)),
      {
        ...remote(totals()),
        source: { ...remote(null).source, secret: "unexpected" },
      },
    ])
      expect(() =>
        remoteTraffic(invalid, NODE, node, (value) =>
          trafficTotals(value, node),
        ),
      ).toThrow(ApiError);
    const credential: TrafficScope = { kind: "credential", id: SUBJECT };
    const wire = remote(
      { ...splitTotals(), scope: credential },
      "ready",
      false,
    );
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(wire));
    const result = await readTrafficView(
      new ManagementClient(fetcher, () => true),
      NODE,
      credential,
      {},
      signal(),
    );
    expect(result.totalsSource?.cached).toBe(false);
    expect(result.history).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("keeps a verified cumulative snapshot when a separate history read fails", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(remote(splitTotals())))
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: "remote_traffic_unavailable" } }, 503),
      );
    const result = await readTrafficView(
      new ManagementClient(fetcher, () => true),
      NODE,
      node,
      {},
      signal(),
    );
    expect(result.totals?.items[0].durable_upload_bytes).toBe(
      "9007199254740993",
    );
    expect(result.history).toBeNull();
    expect(result.historyError).toMatchObject({
      code: "remote_traffic_unavailable",
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("does not hide browser session expiry behind a partial history result", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(sessionFixture()))
      .mockResolvedValueOnce(jsonResponse(splitTotals()))
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: "authentication_required" } }, 403),
      );
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const session = controller.snapshot().session!;
    await expect(
      controller.resource(session, (client, _csrf, signal) =>
        readTrafficView(client, null, node, {}, signal),
      ),
    ).rejects.toMatchObject({ code: "authentication_required" });
    expect(controller.snapshot().phase).toBe("anonymous");
    expect(controller.snapshot().session).toBeNull();
  });

  it("cancels a late old-session read before starting history or delivering a result", async () => {
    let deliver!: (response: Response) => void;
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (input) => {
      if (String(input).endsWith("/auth/session"))
        return jsonResponse(sessionFixture());
      return new Promise<Response>((resolve) => {
        deliver = resolve;
      });
    });
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const session = controller.snapshot().session!;
    const pending = controller.resource(session, (client, _csrf, signal) =>
      readTrafficView(client, null, node, { resolution: "minute" }, signal),
    );
    const rejected = expect(pending).rejects.toMatchObject({
      name: "AbortError",
    });
    controller.cancel();
    deliver(jsonResponse(totals()));
    await rejected;
    expect(
      fetcher.mock.calls.some(([input]) => String(input).includes("/buckets")),
    ).toBe(false);
  });

  it("keeps entity/node selection canonical and navigation on the fixed traffic route", () => {
    expect(
      trafficLocation(
        trafficHref({ kind: "user", id: SUBJECT }, NODE).split("?")[1],
      ),
    ).toMatchObject({ peer: NODE, scope: { kind: "user", id: SUBJECT } });
    for (const search of [
      "?target=https://outside.invalid",
      "?target=bad",
      "?returnTo=https://outside.invalid",
      "?scope=node&id=" + SUBJECT,
      "?target=" + NODE + "&target=" + NODE,
    ])
      expect(() => trafficLocation(search)).toThrow(ApiError);
  });
});
