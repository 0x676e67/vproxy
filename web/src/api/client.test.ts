import { describe, expect, it, vi } from "vitest";
import {
  ApiError,
  authenticationRequired,
  ManagementClient,
  nodeView,
  sessionView,
} from "./client";
import { jsonResponse, sessionFixture } from "./client.fixtures";

describe("same-origin management client", () => {
  it("refuses HTTP before transmitting a password or any API request", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const client = new ManagementClient(fetcher, () => false);
    await expect(
      client.login(
        "operator",
        "not-a-real-password",
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ kind: "https" });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("uses fixed relative endpoints and browser-managed cookies, never a token store", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(sessionFixture()));
    const client = new ManagementClient(fetcher, () => true);
    const signal = new AbortController().signal;
    await client.login("operator", "not-a-real-password", signal);
    expect(fetcher).toHaveBeenCalledWith("/api/v1/auth/login", {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: expect.any(AbortSignal),
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: "operator",
        password: "not-a-real-password",
      }),
    });
  });

  it("validates every session field and keeps untrusted payloads out of errors", async () => {
    for (const value of [
      null,
      {},
      { ...sessionFixture(), csrf_token: "short" },
      { ...sessionFixture(), expires_at: Infinity },
    ]) {
      expect(() => sessionView(value)).toThrow(ApiError);
    }
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      new Response("<html>sensitive detail</html>", {
        headers: { "Content-Type": "text/html" },
      }),
    );
    await expect(
      new ManagementClient(fetcher, () => true).session(
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({
      kind: "format",
      message: "Management request failed",
    });
  });

  it("requires identity facts instead of accepting incomplete or invented node data", () => {
    const fact = {
      node_id: "A".repeat(22),
      name: "Renamable node",
      version: "2.5.5",
      os: "linux",
      arch: "x86_64",
      capabilities: ["local_administration"],
    };
    expect(nodeView(fact)).toEqual(fact);
    for (const value of [
      { ...fact, name: "" },
      { ...fact, capabilities: [3] },
      { ...fact, node_id: "display-name" },
      { ...fact, os: undefined },
    ]) {
      expect(() => nodeView(value)).toThrow(ApiError);
    }
  });

  it("distinguishes an expired session from wrong credentials and malformed errors", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: "authentication_required" } }, 403),
      )
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: "invalid_credentials" } }, 403),
      )
      .mockResolvedValueOnce(jsonResponse({ error: "internal secret" }, 500));
    const client = new ManagementClient(fetcher, () => true);
    const signal = new AbortController().signal;
    const expired = await client
      .session(signal)
      .catch((error: unknown) => error);
    const wrong = await client.session(signal).catch((error: unknown) => error);
    expect(authenticationRequired(expired)).toBe(true);
    expect(authenticationRequired(wrong)).toBe(false);
    await expect(client.session(signal)).rejects.toMatchObject({
      kind: "format",
    });
  });

  it("sends in-memory CSRF for logout and accepts only a confirmed 204", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(jsonResponse({}));
    const client = new ManagementClient(fetcher, () => true);
    const signal = new AbortController().signal;
    await client.logout("C".repeat(43), signal);
    expect(fetcher).toHaveBeenCalledWith(
      "/api/v1/auth/logout",
      expect.objectContaining({
        body: "{}",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-CSRF-Token": "C".repeat(43),
        },
      }),
    );
    await expect(client.logout("C".repeat(43), signal)).rejects.toMatchObject({
      kind: "format",
    });
  });

  it("rejects an abort-ignoring response instead of treating it as successful authentication", async () => {
    const abort = new AbortController();
    const cancel = vi.fn();
    const stream = new ReadableStream<Uint8Array>({ cancel });
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => {
      abort.abort();
      return new Response(stream, {
        headers: { "Content-Type": "application/json" },
      });
    });
    await expect(
      new ManagementClient(fetcher, () => true).session(abort.signal),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("turns transport failures into a generic retryable error without leaking details", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockRejectedValue(new Error("private transport detail"));
    await expect(
      new ManagementClient(fetcher, () => true).session(
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({
      kind: "network",
      message: "Management request failed",
    });
  });

  it("cancels an oversized response before decoding or accumulating it", async () => {
    const cancel = vi.fn();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(32_769));
      },
      cancel,
    });
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(stream, {
        headers: { "Content-Type": "application/json" },
      }),
    );
    await expect(
      new ManagementClient(fetcher, () => true).session(
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ kind: "format" });
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("bounds a stalled body with the same total request deadline", async () => {
    vi.useFakeTimers();
    try {
      const cancel = vi.fn();
      const stream = new ReadableStream<Uint8Array>({ cancel });
      const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
        new Response(stream, {
          headers: { "Content-Type": "application/json" },
        }),
      );
      const request = new ManagementClient(fetcher, () => true).session(
        new AbortController().signal,
      );
      const rejected = expect(request).rejects.toMatchObject({
        kind: "network",
      });
      await vi.advanceTimersByTimeAsync(15_000);
      await rejected;
      expect(cancel).toHaveBeenCalledOnce();
      expect(fetcher.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("bounds missing response headers even if a test transport ignores abort", async () => {
    vi.useFakeTimers();
    try {
      const fetcher = vi
        .fn<typeof fetch>()
        .mockReturnValue(new Promise<Response>(() => {}));
      const request = new ManagementClient(fetcher, () => true).session(
        new AbortController().signal,
      );
      const rejected = expect(request).rejects.toMatchObject({
        kind: "network",
      });
      await vi.advanceTimersByTimeAsync(15_000);
      await rejected;
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});
