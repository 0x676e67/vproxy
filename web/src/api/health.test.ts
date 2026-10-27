import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import {
  healthOutcomes,
  healthQuery,
  healthSnapshot,
  type HealthCheck,
} from "./health";
import { endpointStatus } from "./proxy";

const ID = "A".repeat(22);
const SECOND = "AQEBAQEBAQEBAQEBAQEBAQ";
const signal = () => new AbortController().signal;
const check = (): HealthCheck => ({
  kind: "bind",
  target: null,
  outcome: "unknown",
  sequence: null,
  observed_at_unix_ms: null,
  age_millis: null,
  latency_millis: null,
});
const snapshot = () => ({
  boot_id: ID,
  sequence: "0",
  catalog_revision: null,
  catalog_loaded: false,
  catalog_error: null,
  catalog_observed_at_unix_ms: null,
  catalog_age_millis: null,
  in_flight: 0,
  entries: [],
  next_cursor: null,
});
const loaded = () => ({
  ...snapshot(),
  sequence: "3",
  catalog_revision: "2",
  catalog_loaded: true,
  catalog_observed_at_unix_ms: 1_800_000_000_000,
  catalog_age_millis: 10,
  entries: [
    {
      address_id: ID,
      address_revision: "2",
      ip: "192.0.2.1",
      checks: [check()],
    },
  ],
});

describe("scoped local health observations", () => {
  it("uses a separate 16-address response budget and a GET-only, fixed local endpoint", async () => {
    expect(healthQuery({ after: ID, limit: 10 })).toBe(`?after=${ID}&limit=10`);
    expect(endpointStatus("/proxy/health?limit=16", "GET")).toBe(200);
    expect(() => endpointStatus("/proxy/health?limit=17", "GET")).toThrow(
      ApiError,
    );
    expect(() => endpointStatus("/proxy/health", "POST")).toThrow(ApiError);
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(snapshot()));
    const client = new ManagementClient(fetcher, () => true);
    await expect(client.health({ limit: 17 }, signal())).rejects.toThrow(
      ApiError,
    );
    expect(fetcher).not.toHaveBeenCalled();
    await client.health({ limit: 10 }, signal());
    expect(fetcher.mock.calls[0]?.[0]).toBe("/api/v1/proxy/health?limit=10");
    expect(fetcher.mock.calls[0]?.[1]).toMatchObject({
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
    });
  });
  it("preserves a new boot’s unloaded/unknown state instead of synthesizing healthy inventory", () => {
    expect(healthSnapshot(snapshot()).catalog_loaded).toBe(false);
    expect(healthSnapshot(loaded()).entries[0].checks[0].outcome).toBe(
      "unknown",
    );
    expect(() =>
      healthSnapshot({ ...snapshot(), entries: loaded().entries }),
    ).toThrow(ApiError);
    expect(() =>
      healthSnapshot({ ...loaded(), catalog_loaded: false }),
    ).toThrow(ApiError);
    expect(() =>
      healthSnapshot({ ...loaded(), catalog_error: "untrusted-server-text" }),
    ).toThrow(ApiError);
  });
  it("retains timestamps on expired Unknown and does not treat a repeated sequence as unchanged freshness", async () => {
    const fresh = loaded();
    fresh.entries[0].checks[0] = {
      kind: "bind",
      target: null,
      outcome: "success",
      sequence: "3",
      observed_at_unix_ms: 1_800_000_000_001,
      age_millis: 5,
      latency_millis: 0,
    };
    const expired = structuredClone(fresh);
    expired.entries[0].checks[0].outcome = "unknown";
    expired.entries[0].checks[0].age_millis = 180_000;
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(fresh))
      .mockResolvedValueOnce(jsonResponse(expired));
    const client = new ManagementClient(fetcher, () => true);
    const first = await client.health({ limit: 10 }, signal());
    const second = await client.health({ limit: 10 }, signal());
    expect(first.sequence).toBe(second.sequence);
    expect(first.entries[0].checks[0].outcome).toBe("success");
    expect(second.entries[0].checks[0]).toMatchObject({
      outcome: "unknown",
      age_millis: 180_000,
      observed_at_unix_ms: 1_800_000_000_001,
    });
  });
  it("validates fixed outcomes, numeric targets, full u64 sequences and metadata without widening trust", () => {
    const value = loaded();
    value.sequence = "18446744073709551615";
    for (const outcome of healthOutcomes) {
      value.entries[0].checks[0] = {
        ...check(),
        outcome,
        sequence: "18446744073709551615",
        age_millis: 1,
        latency_millis: 1,
      };
      expect(healthSnapshot(value).entries[0].checks[0].outcome).toBe(outcome);
    }
    expect(() =>
      healthSnapshot({ ...value, sequence: "18446744073709551616" }),
    ).toThrow(ApiError);
    expect(() => healthSnapshot({ ...value, sequence: "03" })).toThrow(
      ApiError,
    );
    expect(() => healthSnapshot({ ...value, in_flight: 5 })).toThrow(ApiError);
    expect(() =>
      healthSnapshot({
        ...value,
        entries: [
          {
            ...value.entries[0],
            checks: [
              { ...check(), kind: "tcp", target: "https://example.com" },
            ],
          },
        ],
      }),
    ).toThrow(ApiError);
    expect(() =>
      healthSnapshot({
        ...value,
        entries: [
          {
            ...value.entries[0],
            checks: [
              check(),
              { ...check(), kind: "tcp", target: "[::1%1]:8080" },
            ],
          },
        ],
      }),
    ).toThrow(ApiError);
    expect(() =>
      healthSnapshot({
        ...value,
        entries: [
          { ...value.entries[0], checks: [{ ...check(), outcome: "healthy" }] },
        ],
      }),
    ).toThrow(ApiError);
    expect(() =>
      healthSnapshot({
        ...value,
        entries: [{ ...value.entries[0], checks: [check(), check()] }],
      }),
    ).toThrow(ApiError);
    expect(() => healthSnapshot({ ...value, next_cursor: SECOND })).toThrow(
      ApiError,
    );
    expect(() =>
      healthSnapshot({ ...value, secret: "not-a-health-field" }),
    ).toThrow(ApiError);
  });
});
