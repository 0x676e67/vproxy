import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import { endpointStatus } from "./proxy";

const NODE = "A".repeat(22);
const signal = () => new AbortController().signal;
const catalog = () => ({
  node_id: NODE,
  proxy_running: true,
  listeners: [
    {
      protocol: "socks5",
      bind: "0.0.0.0:1080",
      public_address: "proxy.example:1080",
    },
  ],
});

describe("startup-owned proxy endpoint reads", () => {
  it("uses only fixed local/selected-node GET routes without sending a secret or mutation", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementation(async () => jsonResponse(catalog()));
    const client = new ManagementClient(fetcher, () => true);
    expect(await client.proxyEndpoints(signal())).toEqual(catalog());
    expect(await client.targetEndpoints(NODE, signal())).toEqual(catalog());
    for (const [index, path] of [
      [1, "/api/v1/proxy/endpoints"],
      [2, `/api/v1/targets/${NODE}/proxy/endpoints`],
    ] as const) {
      expect(fetcher).toHaveBeenNthCalledWith(
        index,
        path,
        expect.objectContaining({ method: "GET" }),
      );
      const options = fetcher.mock.calls[index - 1][1];
      expect(options?.body).toBeUndefined();
      expect(options?.headers).not.toHaveProperty("X-CSRF-Token");
    }
    for (const path of [
      "/proxy/endpoints",
      `/targets/${NODE}/proxy/endpoints`,
    ]) {
      expect(endpointStatus(path, "GET")).toBe(200);
      expect(() => endpointStatus(path, "POST")).toThrow(ApiError);
      expect(() => endpointStatus(`${path}?after=${NODE}`, "GET")).toThrow(
        ApiError,
      );
    }
  });

  it("rejects remote identity mismatch and never substitutes local data or retries unsupported children", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({ ...catalog(), node_id: "AQEBAQEBAQEBAQEBAQEBAQ" }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: "remote_endpoints_unsupported" } }, 502),
      );
    const client = new ManagementClient(fetcher, () => true);
    await expect(client.targetEndpoints(NODE, signal())).rejects.toMatchObject({
      kind: "format",
    });
    await expect(client.targetEndpoints(NODE, signal())).rejects.toMatchObject({
      kind: "server",
      code: "remote_endpoints_unsupported",
      status: 502,
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(
      fetcher.mock.calls.every(
        ([url]) => url === `/api/v1/targets/${NODE}/proxy/endpoints`,
      ),
    ).toBe(true);
    await expect(
      client.targetEndpoints("https://outside.invalid", signal()),
    ).rejects.toThrow(ApiError);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
