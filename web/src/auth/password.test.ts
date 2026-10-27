import { describe, expect, it, vi } from "vitest";
import { ManagementClient } from "../api/client";
import { jsonResponse, sessionFixture } from "../api/client.fixtures";
import { SessionController } from "./session";

const current = "current fixture passphrase",
  next = "new fixture passphrase";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}

describe("password-change session ownership", () => {
  it("clears session memory only after confirmed success and cancels old protected work", async () => {
    const pending = deferred<Response>();
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(sessionFixture()))
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const session = controller.snapshot().session!;
    const oldRead = controller
      .resource(session, (client, _, signal) => client.node(signal))
      .catch((error: unknown) => error);
    await controller.changePassword(session, current, next);
    expect(controller.snapshot()).toMatchObject({
      phase: "anonymous",
      session: null,
      busy: false,
      passwordChangeNotice: "changed",
    });
    expect(fetcher.mock.calls[1]?.[1]?.signal?.aborted).toBe(true);
    expect(await oldRead).toMatchObject({ name: "AbortError" });
    pending.resolve(jsonResponse({}));
  });

  it("keeps a rejected current password distinct from an invalidated session", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(sessionFixture()))
      .mockResolvedValueOnce(
        jsonResponse({ error: { code: "invalid_credentials" } }, 403),
      );
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const session = controller.snapshot().session!;
    await expect(
      controller.changePassword(session, current, next),
    ).rejects.toMatchObject({ code: "invalid_credentials" });
    expect(controller.snapshot()).toMatchObject({
      phase: "authenticated",
      session,
      busy: false,
      error: null,
    });
  });

  it("drops local authority after an uncertain result without retrying or claiming success", async () => {
    for (const [response, notice] of [
      [new Error("response lost"), "unconfirmed"],
      [
        jsonResponse(
          { error: { code: "password_change_outcome_unknown" } },
          503,
        ),
        "blocked",
      ],
      [
        jsonResponse({ error: { code: "password_change_failed" } }, 500),
        "failed",
      ],
    ] as const) {
      const fetcher = vi
        .fn<typeof fetch>()
        .mockResolvedValueOnce(jsonResponse(sessionFixture()));
      if (response instanceof Error) fetcher.mockRejectedValueOnce(response);
      else fetcher.mockResolvedValueOnce(response);
      const controller = new SessionController(
        new ManagementClient(fetcher, () => true),
      );
      await controller.check();
      await controller.changePassword(
        controller.snapshot().session!,
        current,
        next,
      );
      expect(controller.snapshot()).toMatchObject({
        phase: "anonymous",
        session: null,
        busy: false,
        passwordChangeNotice: notice,
      });
      expect(fetcher).toHaveBeenCalledTimes(2);
      expect(JSON.stringify(controller.snapshot())).not.toContain(current);
      expect(JSON.stringify(controller.snapshot())).not.toContain(next);
    }
  });

  it("rejects duplicate submission and ignores late success from a superseded session", async () => {
    const pending = deferred<Response>();
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(sessionFixture("first")))
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce(jsonResponse(sessionFixture("second")));
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const session = controller.snapshot().session!;
    const change = controller.changePassword(session, current, next);
    await expect(
      controller.changePassword(session, current, next),
    ).rejects.toMatchObject({ name: "AbortError" });
    await controller.check();
    pending.resolve(new Response(null, { status: 204 }));
    await change;
    expect(controller.snapshot().session?.administrator.username).toBe(
      "second",
    );
    expect(controller.snapshot().passwordChangeNotice).toBeUndefined();
    expect(
      fetcher.mock.calls.filter(([path]) => path === "/api/v1/auth/password"),
    ).toHaveLength(1);
  });
});
