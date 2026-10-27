import { describe, expect, it, vi } from "vitest";
import { acmeDate, acmeStatus } from "./acme";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import { endpointStatus } from "./proxy";

const status = () => ({
  mode: "acme",
  environment: "staging",
  challenge: "tls-alpn-01",
  certificate: {
    not_before_unix_s: "100",
    not_after_unix_s: "200",
    available: true,
  },
  activity: "waiting",
  next_attempt_at_unix_s: "160",
  last_failure: null,
  observed_at_unix_s: "150",
});

describe("local browser certificate status", () => {
  it("keeps manual mode exact and accepts failures alongside an active or working identity", () => {
    expect(acmeStatus({ mode: "manual" })).toEqual({ mode: "manual" });
    for (const last_failure of [null, "attempt_unavailable", "review_required"])
      for (const activity of ["waiting", "working", "stopped"]) {
        const value = {
          ...status(),
          activity,
          last_failure,
          next_attempt_at_unix_s: activity === "waiting" ? "0" : null,
        };
        expect(acmeStatus(value)).toEqual(value);
      }
    expect(
      acmeStatus({
        ...status(),
        environment: "production",
        challenge: "http-01",
        certificate: null,
      }),
    ).toMatchObject({ certificate: null });
    for (const observed_at_unix_s of ["100", "200"])
      expect(acmeStatus({ ...status(), observed_at_unix_s })).toMatchObject({
        certificate: { available: true },
      });
    for (const observed_at_unix_s of ["99", "201"])
      expect(
        acmeStatus({
          ...status(),
          observed_at_unix_s,
          certificate: { ...status().certificate, available: false },
        }),
      ).toMatchObject({ certificate: { available: false } });
  });

  it("rejects unexpected fields, values, missing fields and contradictory snapshots", () => {
    const missing: Record<string, unknown> = status();
    delete missing.last_failure;
    for (const value of [
      null,
      [],
      {},
      missing,
      { mode: "manual", certificate: null },
      { ...status(), mode: "automatic" },
      { ...status(), contact: "private@example.invalid" },
      { ...status(), environment: "custom" },
      { ...status(), challenge: "tls-alpn01" },
      { ...status(), activity: "ready" },
      { ...status(), last_failure: "raw_ca_response" },
      { ...status(), next_attempt_at_unix_s: null },
      { ...status(), activity: "working" },
      { ...status(), activity: "stopped" },
      { ...status(), certificate: {} },
      {
        ...status(),
        certificate: { ...status().certificate, path: "private" },
      },
      {
        ...status(),
        certificate: { ...status().certificate, not_before_unix_s: "200" },
      },
      {
        ...status(),
        certificate: { ...status().certificate, not_after_unix_s: "99" },
      },
      {
        ...status(),
        certificate: { ...status().certificate, available: false },
      },
      { ...status(), observed_at_unix_s: "201" },
    ])
      expect(() => acmeStatus(value)).toThrow(ApiError);
  });

  it("bounds all exact timestamps and keeps out-of-range display separate from valid wire data", () => {
    for (const value of [
      "",
      "01",
      "-1",
      "+1",
      "1.0",
      "1e2",
      " 1",
      "18446744073709551616",
      150,
      null,
    ]) {
      expect(() =>
        acmeStatus({ ...status(), observed_at_unix_s: value }),
      ).toThrow(ApiError);
      expect(() =>
        acmeStatus({ ...status(), next_attempt_at_unix_s: value }),
      ).toThrow(ApiError);
      expect(() =>
        acmeStatus({
          ...status(),
          certificate: { ...status().certificate, not_before_unix_s: value },
        }),
      ).toThrow(ApiError);
      expect(() =>
        acmeStatus({
          ...status(),
          certificate: { ...status().certificate, not_after_unix_s: value },
        }),
      ).toThrow(ApiError);
    }
    const huge = {
      ...status(),
      certificate: null,
      observed_at_unix_s: "18446744073709551615",
      next_attempt_at_unix_s: "18446744073709551615",
    };
    expect(acmeStatus(huge)).toEqual(huge);
    expect(acmeDate("18446744073709551615")).toBeNull();
    expect(acmeDate("8640000000001")).toBeNull();
    expect(acmeDate("8640000000000")?.getTime()).toBe(8640000000000000);
    expect(acmeDate("0")?.getTime()).toBe(0);
  });

  it("uses one fixed same-origin read and preserves an older server's 404 without retries", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(status()))
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: "not_found" } }, 404),
      );
    const client = new ManagementClient(fetcher, () => true);
    const signal = new AbortController().signal;
    expect(await client.acmeStatus(signal)).toEqual(status());
    await expect(client.acmeStatus(signal)).rejects.toMatchObject({
      kind: "server",
      status: 404,
      code: "not_found",
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
    for (const [path, options] of fetcher.mock.calls) {
      expect(path).toBe("/api/v1/tls/acme");
      expect(options).toMatchObject({
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
      });
      expect(options?.body).toBeUndefined();
      expect(new Headers(options?.headers).has("X-CSRF-Token")).toBe(false);
      expect(new Headers(options?.headers).has("Authorization")).toBe(false);
    }
    expect(endpointStatus("/tls/acme", "GET")).toBe(200);
    for (const [path, method] of [
      ["/tls/acme?", "GET"],
      ["/tls/acme?domain=other", "GET"],
      ["/tls/acme", "POST"],
      ["/tls/acme", "PUT"],
      ["/targets/AAAAAAAAAAAAAAAAAAAAAA/tls/acme", "GET"],
    ] as const)
      expect(() => endpointStatus(path, method)).toThrow(ApiError);
  });
});
