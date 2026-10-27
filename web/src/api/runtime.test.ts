import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse, sessionFixture } from "./client.fixtures";
import { LOCAL, PEER, JOB } from "./maintenance.fixtures";
import { endpointStatus } from "./proxy";
import { drainNonce, drainRequest, runtimeStatus } from "./runtime";
import { drainFixture, runtimeFixture, RUNTIME } from "./runtime.fixtures";

describe("runtime observations and one-shot drain", () => {
  it("requires exact shapes, canonical counts and coherent runtime/request/node/epoch/revision bindings", () => {
    const value = runtimeFixture(false, "drained");
    expect(runtimeStatus(value, LOCAL).runtime?.active_operations).toBe("3");
    expect(
      runtimeStatus(
        {
          ...value,
          runtime: {
            ...value.runtime,
            active_operations: "18446744073709551615",
          },
        },
        LOCAL,
      ).runtime?.phase,
    ).toBe("drained");
    expect(
      runtimeStatus({ ...value, runtime: null }, LOCAL).runtime,
    ).toBeNull();
    for (const patch of [
      { runtime: undefined },
      { runtime: {} },
      { saved_accepting: true },
      { node_id: PEER },
      { saved_revision: "8" },
      { password: "not-retained" },
      { ownership: { ...value.ownership, epoch: "1" } },
      ...["00", "-1", "18446744073709551616", 0, undefined].map(
        (active_operations) => ({
          runtime: { ...value.runtime, active_operations },
        }),
      ),
      ...[
        { request: null },
        { request: { ...drainFixture(), runtime_id: JOB } },
        { phase: "serving" },
        { phase: "complete" },
        { extra: true },
      ].map((patch) => ({ runtime: { ...value.runtime, ...patch } })),
    ])
      expect(() => runtimeStatus({ ...value, ...patch }, LOCAL)).toThrow(
        ApiError,
      );
    expect(() =>
      runtimeStatus(runtimeFixture(), LOCAL, drainFixture()),
    ).toThrow(ApiError);
    expect(() =>
      runtimeStatus(value, LOCAL, { ...drainFixture(), request_id: PEER }),
    ).toThrow(ApiError);
    expect(() =>
      drainRequest({ ...drainFixture(), csrf: "not-retained" }),
    ).toThrow(ApiError);
  });
  it("sends exactly one POST with every assertion and reads only the original pair, including remote target CAS", async () => {
    for (const remote of [false, true]) {
      let response = runtimeFixture(remote, "draining");
      const fetcher = vi.fn(
        async (_path: RequestInfo | URL, init?: RequestInit) =>
          jsonResponse(response, init?.method === "POST" ? 202 : 200),
      );
      const client = new ManagementClient(fetcher, () => true),
        signal = new AbortController().signal;
      const peer = remote ? PEER : null,
        node = remote ? PEER : LOCAL,
        original = drainFixture(remote);
      const prefix = `/api/v1${remote ? `/targets/${PEER}` : ""}/proxy/runtime`;
      await client.proxyRuntime(node, peer, signal);
      await client.drainRuntime(
        peer,
        original,
        remote ? "4" : null,
        sessionFixture().csrf_token,
        signal,
      );
      expect(fetcher).toHaveBeenLastCalledWith(
        `${prefix}/drain`,
        expect.objectContaining({
          method: "POST",
          redirect: "error",
          body: JSON.stringify(
            remote
              ? { expected_target_revision: "4", request: original }
              : original,
          ),
        }),
      );
      response = runtimeFixture(remote, "drained");
      await client.runtimeDrain(peer, original, signal);
      expect(fetcher).toHaveBeenLastCalledWith(
        `${prefix}/drains/${RUNTIME}/${JOB}`,
        expect.objectContaining({ method: "GET" }),
      );
      expect(
        fetcher.mock.calls.filter(([, init]) => init?.method === "POST"),
      ).toHaveLength(1);
      response = {
        ...response,
        runtime: { ...response.runtime!, runtime_id: LOCAL },
      };
      await expect(
        client.runtimeDrain(peer, original, signal),
      ).rejects.toBeInstanceOf(ApiError);
      const count = fetcher.mock.calls.length;
      await expect(
        client.drainRuntime(
          peer,
          original,
          remote ? null : "4",
          "csrf",
          signal,
        ),
      ).rejects.toBeInstanceOf(ApiError);
      expect(fetcher).toHaveBeenCalledTimes(count);
    }
  });
  it("keeps 404, wrong success status and a replacement request unknown without fallback or POST retry", async () => {
    for (const reply of [
      jsonResponse({ error: { code: "resource_not_found" } }, 404),
      jsonResponse(runtimeFixture(false, "draining"), 200),
      jsonResponse(
        {
          ...runtimeFixture(false, "draining"),
          runtime: {
            ...runtimeFixture(false, "draining").runtime,
            request: { ...drainFixture(), request_id: PEER },
          },
        },
        202,
      ),
    ]) {
      const fetcher = vi.fn(async () => reply),
        client = new ManagementClient(fetcher, () => true);
      await expect(
        client.drainRuntime(
          null,
          drainFixture(),
          null,
          "csrf",
          new AbortController().signal,
        ),
      ).rejects.toBeInstanceOf(ApiError);
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
    const fetcher = vi.fn(async () =>
      jsonResponse({ error: { code: "resource_not_found" } }, 404),
    );
    await expect(
      new ManagementClient(fetcher, () => true).runtimeDrain(
        null,
        drainFixture(),
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ status: 404 });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(endpointStatus("/proxy/runtime/drain", "POST")).toBe(202);
    expect(() => endpointStatus("/proxy/runtime/drain", "GET")).toThrow(
      ApiError,
    );
    expect(() =>
      endpointStatus(
        `/proxy/runtime/drains/${RUNTIME}/${JOB}?latest=true`,
        "GET",
      ),
    ).toThrow(ApiError);
  });
  it("uses exactly 16 cryptographic bytes without a weak fallback", () => {
    const getRandomValues = vi.fn((value: Uint8Array) => value.fill(0));
    vi.stubGlobal("crypto", { getRandomValues });
    try {
      expect(drainNonce()).toBe("A".repeat(22));
      expect(getRandomValues.mock.calls[0][0]).toHaveLength(16);
      vi.stubGlobal("crypto", undefined);
      expect(() => drainNonce()).toThrow(ApiError);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
