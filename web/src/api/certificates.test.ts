import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import {
  certificateCondition,
  certificateDate,
  certificateSeconds,
  certificateStatus,
} from "./certificates";

const id = "A".repeat(22);
const leaf = {
  sha256: "a".repeat(64),
  not_before_unix_s: "-10",
  not_after_unix_s: "1000000",
};
export const fixture = () => ({
  node_id: id,
  observed_at_unix_s: "0",
  entries: [
    {
      role: "management",
      source: "manual",
      id: null,
      protocol: null,
      state: "loaded",
      certificate: { ...leaf },
      valid_now: true,
    },
    {
      role: "node",
      source: "manual",
      id: null,
      protocol: null,
      state: "disabled",
      certificate: null,
      valid_now: null,
    },
  ],
});

describe("actual local loaded TLS status", () => {
  it("accepts managed renewable proxy TLS without granting ACME to node or plaintext roles", () => {
    const base = fixture();
    const proxy = {
      ...base.entries[0],
      role: "proxy",
      source: "acme",
      id: "B".repeat(21) + "A",
      protocol: "https",
    };
    for (const protocol of ["https", "masque", "auto"])
      expect(
        certificateStatus({
          ...base,
          entries: [...base.entries, { ...proxy, protocol }],
        }).entries[2].source,
      ).toBe("acme");
    expect(() =>
      certificateStatus({
        ...base,
        entries: [base.entries[0], { ...base.entries[1], source: "acme" }],
      }),
    ).toThrow(ApiError);
    expect(() =>
      certificateStatus({
        ...base,
        entries: [
          ...base.entries,
          {
            ...proxy,
            protocol: "http",
            state: "disabled",
            certificate: null,
            valid_now: null,
          },
        ],
      }),
    ).toThrow(ApiError);
  });
  it("retains exact signed seconds, inclusive endpoints and separate display limits", () => {
    for (const value of [
      "-9223372036854775808",
      "9223372036854775807",
      "0",
      "-1",
    ])
      expect(certificateSeconds(value)).toBe(true);
    for (const value of [
      "-0",
      "01",
      "+1",
      "1.0",
      "9223372036854775808",
      "-9223372036854775809",
      1,
      null,
    ])
      expect(certificateSeconds(value)).toBe(false);
    for (const now of ["-10", "1000000"])
      expect(
        certificateStatus({ ...fixture(), observed_at_unix_s: now }).entries[0]
          .valid_now,
      ).toBe(true);
    expect(certificateDate("9223372036854775807")).toBeNull();
    expect(certificateDate("-1")?.getTime()).toBe(-1000);
    const entry = certificateStatus(fixture()).entries[0];
    expect(certificateCondition(entry, null)).toBe("time_unknown");
    for (const [now, condition] of [
      ["-11", "not_yet_valid"],
      ["0", "within_validity"],
      ["395200", "expiring"],
      ["1000001", "expired"],
    ])
      expect(certificateCondition(entry, now)).toBe(condition);
  });
  it("rejects excess fields, identity confusion, time contradictions and plaintext TLS claims", () => {
    const base = fixture(),
      management = base.entries[0];
    for (const value of [
      null,
      {},
      { ...base, private_path: "x" },
      { ...base, node_id: "invalid" },
      { ...base, entries: [] },
      { ...base, entries: [base.entries[1], management] },
      ...[
        {
          ...management,
          state: "disabled",
          certificate: null,
          valid_now: null,
        },
        { ...management, certificate: { ...leaf, sha256: "A".repeat(64) } },
        { ...management, certificate: { ...leaf, not_after_unix_s: "-11" } },
        { ...management, valid_now: false },
        { ...management, source: "acme", state: "pending" },
      ].map((entry) => ({ ...base, entries: [entry, base.entries[1]] })),
      {
        ...base,
        entries: [
          ...base.entries,
          {
            ...management,
            role: "proxy",
            id: "B".repeat(21) + "A",
            protocol: "http",
          },
        ],
      },
      {
        ...base,
        entries: [
          ...base.entries,
          {
            ...base.entries[1],
            role: "proxy",
            id: "B".repeat(21) + "A",
            protocol: "https",
          },
        ],
      },
    ])
      expect(() => certificateStatus(value)).toThrow(ApiError);
    expect(
      certificateStatus({
        ...base,
        observed_at_unix_s: null,
        entries: [{ ...management, valid_now: null }, base.entries[1]],
      }).observed_at_unix_s,
    ).toBeNull();
  });
  it("uses one exact same-origin local GET, binding the returned node and preserving abort", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => jsonResponse(fixture()));
    const client = new ManagementClient(fetcher, () => true);
    const signal = new AbortController().signal;
    expect(await client.certificateStatus(id, signal)).toEqual(fixture());
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0]).toEqual([
      "/api/v1/tls/status",
      expect.objectContaining({
        method: "GET",
        signal: expect.any(AbortSignal),
        credentials: "same-origin",
        redirect: "error",
      }),
    ]);
    await expect(
      client.certificateStatus("B".repeat(21) + "A", signal),
    ).rejects.toMatchObject({ kind: "format" });
    await expect(
      client.certificateStatus("not-an-id", signal),
    ).rejects.toMatchObject({ kind: "format" });
    expect(fetcher).toHaveBeenCalledTimes(2);
    fetcher.mockImplementationOnce(() => new Promise<Response>(() => {}));
    const cancellation = new AbortController();
    const pending = client.certificateStatus(id, cancellation.signal);
    const rejected = expect(pending).rejects.toMatchObject({
      name: "AbortError",
    });
    cancellation.abort();
    await rejected;
    expect(fetcher.mock.calls[2][1]?.signal?.aborted).toBe(true);
  });
});
