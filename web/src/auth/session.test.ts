import { describe, expect, it, vi } from "vitest";
import { ManagementClient } from "../api/client";
import { jsonResponse, sessionFixture } from "../api/client.fixtures";
import { SessionController, sessionRecheckDelay } from "./session";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}

describe("in-memory session ownership", () => {
  it("schedules expiry revalidation without trusting a skewed clock or looping immediately", () => {
    expect(sessionRecheckDelay(120, 0)).toBe(120_000);
    expect(sessionRecheckDelay(0, 1_800_000_000_000)).toBe(60_000);
    expect(sessionRecheckDelay(Number.MAX_SAFE_INTEGER, 0)).toBe(
      8 * 60 * 60 * 1000,
    );
  });
  it("does not authenticate a rejected login", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(
        jsonResponse({ error: { code: "invalid_credentials" } }, 403),
      );
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    expect(
      await controller.login("operator", "incorrect fixture password"),
    ).toBe(false);
    expect(controller.snapshot()).toMatchObject({
      phase: "anonymous",
      session: null,
      error: { code: "invalid_credentials" },
    });
  });
  it("keeps a connection failure distinct from an anonymous session", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockRejectedValue(new Error("offline"));
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    expect(controller.snapshot()).toMatchObject({
      phase: "error",
      session: null,
      error: { kind: "network" },
    });
  });

  it("survives StrictMode cleanup/restart and ignores the old check response", async () => {
    const old = deferred<Response>();
    const fetcher = vi
      .fn<typeof fetch>()
      .mockReturnValueOnce(old.promise)
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: "authentication_required" } }, 403),
      );
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    const first = controller.check();
    controller.cancel();
    await controller.check();
    old.resolve(jsonResponse(sessionFixture("old-user")));
    await first;
    expect(fetcher.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
    expect(controller.snapshot()).toMatchObject({
      phase: "anonymous",
      session: null,
      error: null,
    });
  });

  it("does not let an older login replace a newer authenticated user", async () => {
    const old = deferred<Response>();
    const fetcher = vi
      .fn<typeof fetch>()
      .mockReturnValueOnce(old.promise)
      .mockResolvedValueOnce(jsonResponse(sessionFixture("new-user")));
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    const first = controller.login("old-user", "old fixture password");
    expect(await controller.login("new-user", "new fixture password")).toBe(
      true,
    );
    old.resolve(jsonResponse(sessionFixture("old-user")));
    expect(await first).toBe(false);
    expect(controller.snapshot().session?.administrator.username).toBe(
      "new-user",
    );
  });

  it("never fabricates successful logout after a network or CSRF failure", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(sessionFixture()))
      .mockRejectedValueOnce(new Error("response lost"))
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: "invalid_csrf" } }, 403),
      )
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const original = controller.snapshot().session;
    await controller.logout();
    expect(controller.snapshot()).toMatchObject({
      phase: "authenticated",
      session: original,
      error: { kind: "network" },
    });
    await controller.logout();
    expect(controller.snapshot()).toMatchObject({
      phase: "authenticated",
      session: original,
      error: { code: "invalid_csrf" },
    });
    await controller.logout();
    expect(controller.snapshot()).toMatchObject({
      phase: "anonymous",
      session: null,
      error: null,
    });
  });

  it("does not let an old node response expire a newly rotated session", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(sessionFixture("first")))
      .mockResolvedValueOnce(jsonResponse(sessionFixture("second")));
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const previous = controller.snapshot().session!;
    await controller.login("second", "fixture password");
    controller.authenticationLost(previous);
    expect(controller.snapshot().session?.administrator.username).toBe(
      "second",
    );
    controller.authenticationLost(controller.snapshot().session!);
    expect(controller.snapshot()).toMatchObject({
      phase: "anonymous",
      session: null,
    });
  });
});
