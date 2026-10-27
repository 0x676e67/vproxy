import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "../api/client";
import { jsonResponse, sessionFixture } from "../api/client.fixtures";
import { SessionController } from "./session";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}

describe("session-owned policy reads and writes", () => {
  it("aborts remaining protected reads when one branch of a composite request fails", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(sessionFixture()));
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    let sibling: AbortSignal | undefined;
    await expect(
      controller.resource(
        controller.snapshot().session!,
        async (_client, _csrf, signal) => {
          sibling = signal;
          return Promise.all([
            Promise.reject(new ApiError("server", "policy_busy", 503)),
            new Promise((resolve) =>
              signal.addEventListener("abort", () => resolve("cancelled"), {
                once: true,
              }),
            ),
          ]);
        },
      ),
    ).rejects.toMatchObject({ code: "policy_busy" });
    expect(sibling?.aborted).toBe(true);
  });
  it("passes only the current in-memory CSRF and rejects late secrets after a new login", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(sessionFixture("first")))
      .mockResolvedValueOnce(jsonResponse(sessionFixture("second")));
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const first = controller.snapshot().session!;
    const pending = deferred<{ secret: string }>();
    let requestSignal: AbortSignal | undefined;
    const issued = controller
      .resource(first, async (_client, csrf, signal) => {
        expect(csrf).toBe(first.csrf_token);
        requestSignal = signal;
        return pending.promise;
      })
      .catch((error) => error);
    await controller.login("second", "fixture password");
    pending.resolve({ secret: "must-not-reach-the-old-modal" });
    expect(await issued).toMatchObject({ name: "AbortError" });
    expect(requestSignal?.aborted).toBe(true);
    expect(controller.snapshot().session?.administrator.username).toBe(
      "second",
    );
    expect(JSON.stringify(controller.snapshot())).not.toContain(
      "must-not-reach-the-old-modal",
    );
  });
  it("cancels all independent reads when logout starts, even if logout fails", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(sessionFixture()))
      .mockRejectedValueOnce(new Error("response lost"));
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const session = controller.snapshot().session!;
    const pending = deferred<string>();
    const first = controller
      .resource(session, () => pending.promise)
      .catch((error) => error);
    const second = controller
      .resource(session, () => pending.promise)
      .catch((error) => error);
    const generation = controller.generation();
    await controller.logout();
    pending.resolve("stale");
    expect((await first).name).toBe("AbortError");
    expect((await second).name).toBe("AbortError");
    expect(controller.generation()).toBeGreaterThan(generation);
    expect(controller.snapshot().phase).toBe("authenticated");
  });
  it.each([401, 403])("honors cleanup and signs out on authentication_required (%s) without retrying a mutation", async (status) => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(sessionFixture()));
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const session = controller.snapshot().session!;
    const cleanup = new AbortController();
    const pending = deferred<string>();
    const cancelled = controller
      .resource(session, () => pending.promise, cleanup.signal)
      .catch((error) => error);
    cleanup.abort();
    pending.resolve("discarded");
    expect((await cancelled).name).toBe("AbortError");
    const mutation = vi
      .fn()
      .mockRejectedValue(
        new ApiError("server", "authentication_required", status),
      );
    await expect(controller.resource(session, mutation)).rejects.toMatchObject({
      code: "authentication_required",
    });
    expect(mutation).toHaveBeenCalledTimes(1);
    expect(controller.snapshot().phase).toBe("anonymous");
  });
});
