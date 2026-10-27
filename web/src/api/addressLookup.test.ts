import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import { endpointStatus } from "./proxy";
import { addressView } from "./routing";

const ADDRESS = "A".repeat(22);
const PEER = "AQEBAQEBAQEBAQEBAQEBAQ";
const response = () => ({
  revision: "9",
  address: {
    id: ADDRESS,
    name: "Directory address",
    ip: "192.0.2.10",
    prefix_id: null,
    state: "retired",
    revision: "2",
  },
});

describe("exact address directory reads", () => {
  it("checks the exact resource and global revision without treating retired as missing", () => {
    const value = response();
    expect(addressView(value, ADDRESS)).toEqual(value);
    for (const invalid of [
      { ...value, address: { ...value.address, id: PEER } },
      { ...value, revision: "1" },
      { ...value, revision: "09" },
      { ...value, address: { ...value.address, state: "deleted" } },
      {
        ...value,
        address: { ...value.address, ip: "https://outside.invalid" },
      },
      { ...value, address: { ...value.address, prefix_id: "invalid" } },
      { ...value, address: { ...value.address, secret: "unexpected" } },
      { ...value, extra: true },
    ])
      expect(() => addressView(invalid, ADDRESS)).toThrow(ApiError);
  });

  it("admits only canonical fixed GETs without a query, mutation or arbitrary destination", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementation(async () => jsonResponse(response()));
    const client = new ManagementClient(fetcher, () => true);
    const request = new AbortController();
    expect(await client.routingAddress(ADDRESS, request.signal)).toEqual(
      response(),
    );
    expect(
      await client.targetRoutingAddress(PEER, ADDRESS, request.signal),
    ).toEqual(response());
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      `/api/v1/proxy/addresses/${ADDRESS}`,
      `/api/v1/targets/${PEER}/proxy/addresses/${ADDRESS}`,
    ]);
    for (const [, init] of fetcher.mock.calls) {
      expect(init).toMatchObject({
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
      });
      expect(init?.body).toBeUndefined();
      expect(init?.headers).not.toHaveProperty("X-CSRF-Token");
    }
    for (const path of [
      `/proxy/addresses/${ADDRESS}`,
      `/targets/${PEER}/proxy/addresses/${ADDRESS}`,
    ]) {
      expect(endpointStatus(path, "GET")).toBe(200);
      for (const invalid of [
        `${path}?`,
        `${path}?after=${PEER}`,
        `${path}?address=${ADDRESS}`,
        `${path}/other`,
      ])
        expect(() => endpointStatus(invalid, "GET")).toThrow(ApiError);
      for (const method of ["POST", "PUT"] as const)
        expect(() => endpointStatus(path, method)).toThrow(ApiError);
    }
    await expect(
      client.routingAddress("invalid", request.signal),
    ).rejects.toBeInstanceOf(ApiError);
    await expect(
      client.targetRoutingAddress(
        "https://outside.invalid",
        ADDRESS,
        request.signal,
      ),
    ).rejects.toBeInstanceOf(ApiError);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("preserves remote not-found versus unsupported, never falls back, and cancels an ignored abort", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const client = new ManagementClient(fetcher, () => true);
    for (const [status, code] of [
      [404, "resource_not_found"],
      [502, "address_lookup_unsupported"],
    ] as const) {
      fetcher.mockResolvedValue(jsonResponse({ error: { code } }, status));
      await expect(
        client.targetRoutingAddress(
          PEER,
          ADDRESS,
          new AbortController().signal,
        ),
      ).rejects.toMatchObject({ kind: "server", status, code });
    }
    expect(
      fetcher.mock.calls.every(([path]) =>
        String(path).includes(`/targets/${PEER}/`),
      ),
    ).toBe(true);
    fetcher.mockImplementation(() => new Promise(() => {}));
    const request = new AbortController();
    const pending = client.targetRoutingAddress(PEER, ADDRESS, request.signal);
    request.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    expect(fetcher.mock.calls.at(-1)?.[1]?.signal?.aborted).toBe(true);
  });
});
