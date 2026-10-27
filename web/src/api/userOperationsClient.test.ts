import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse, sessionFixture } from "./client.fixtures";
import { SessionController } from "../auth/session";
import type { UserOperation, UserOperationInput } from "./userOperations";

const ID = "A".repeat(22);
const USER = "AQEBAQEBAQEBAQEBAQEBAQ";
const NODE = "AgICAgICAgICAgICAgICAg";
const input: UserOperationInput = {
  expected_revision: "7",
  expected_epoch: "3",
  change: {
    action: "create_user",
    name: "Test user",
    protocols: ["http"],
    concurrent_limit: 32,
  },
};
const reserved: UserOperation = {
  id: ID,
  node_id: NODE,
  expected_revision: "7",
  expected_epoch: "3",
  sequence: "10",
  action: "create_user",
  user_id: null,
  state: "reserved",
  saved_revision: null,
  rejection: null,
};
const saved: UserOperation = {
  ...reserved,
  state: "saved",
  saved_revision: "8",
  user_id: USER,
};
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}

describe("session-owned local user operation client", () => {
  it("reserves without executing, sends the same input only on explicit execution and queries non-secret records", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(sessionFixture()))
      .mockResolvedValueOnce(jsonResponse(reserved, 201))
      .mockResolvedValueOnce(jsonResponse(saved))
      .mockResolvedValueOnce(jsonResponse(saved))
      .mockResolvedValueOnce(
        jsonResponse({ items: [saved], next_cursor: null }),
      );
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const session = controller.snapshot().session!;
    expect(
      await controller.resource(session, (client, csrf, signal) =>
        client.reserveUserOperation(input, csrf, signal),
      ),
    ).toEqual(reserved);
    expect(fetcher).toHaveBeenCalledTimes(2);
    const [reservePath, reserveRequest] = fetcher.mock.calls[1];
    expect(reservePath).toBe("/api/v1/proxy/user-operations");
    expect(reserveRequest).toMatchObject({
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": session.csrf_token,
      },
      body: JSON.stringify(input),
    });
    expect(
      await controller.resource(session, (client, csrf, signal) =>
        client.executeUserOperation(ID, input, csrf, signal),
      ),
    ).toEqual(saved);
    expect(fetcher.mock.calls[2][0]).toBe(
      `/api/v1/proxy/user-operations/${ID}/execute`,
    );
    expect(fetcher.mock.calls[2][1]?.body).toBe(reserveRequest?.body);
    expect(
      await controller.resource(session, (client, _csrf, signal) =>
        client.userOperation(ID, signal),
      ),
    ).toEqual(saved);
    expect(
      await controller.resource(session, (client, _csrf, signal) =>
        client.userOperations({ before: "11", limit: 1 }, signal),
      ),
    ).toEqual({ items: [saved], next_cursor: null });
    expect(fetcher.mock.calls[4][0]).toBe(
      "/api/v1/proxy/user-operations?before=11&limit=1",
    );
    for (const index of [3, 4])
      expect(fetcher.mock.calls[index][1]).toMatchObject({
        method: "GET",
        headers: { Accept: "application/json" },
      });
    expect(fetcher.mock.calls[3][1]?.body).toBeUndefined();
    expect(fetcher.mock.calls[3][1]?.headers).not.toHaveProperty(
      "X-CSRF-Token",
    );
    expect(fetcher).toHaveBeenCalledTimes(5);
  });

  it("refuses HTTP and malformed inputs before any request", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const signal = new AbortController().signal;
    await expect(
      new ManagementClient(fetcher, () => false).reserveUserOperation(
        input,
        "csrf",
        signal,
      ),
    ).rejects.toMatchObject({ kind: "https" });
    const client = new ManagementClient(fetcher, () => true);
    await expect(
      client.reserveUserOperation(
        { ...input, secret: "not-accepted" } as UserOperationInput,
        "csrf",
        signal,
      ),
    ).rejects.toBeInstanceOf(ApiError);
    await expect(
      client.executeUserOperation("not-an-id", input, "csrf", signal),
    ).rejects.toBeInstanceOf(ApiError);
    await expect(
      client.userOperation("https://elsewhere.invalid", signal),
    ).rejects.toBeInstanceOf(ApiError);
    await expect(
      client.userOperations({ before: "01" }, signal),
    ).rejects.toBeInstanceOf(ApiError);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("requires exact successful statuses and matching operation identity rather than treating a 2xx as proof", async () => {
    const signal = new AbortController().signal;
    for (const [status, body] of [
      [200, reserved],
      [201, saved],
      [201, { ...reserved, expected_epoch: "4" }],
    ] as const) {
      const fetcher = vi
        .fn<typeof fetch>()
        .mockResolvedValue(jsonResponse(body, status));
      await expect(
        new ManagementClient(fetcher, () => true).reserveUserOperation(
          input,
          "csrf",
          signal,
        ),
      ).rejects.toMatchObject({ kind: "format" });
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
    for (const [status, body] of [
      [201, saved],
      [202, saved],
      [200, reserved],
      [200, { ...saved, id: USER }],
      [200, { ...saved, secret: "not-accepted" }],
    ] as const) {
      const fetcher = vi
        .fn<typeof fetch>()
        .mockResolvedValue(jsonResponse(body, status));
      await expect(
        new ManagementClient(fetcher, () => true).executeUserOperation(
          ID,
          input,
          "csrf",
          signal,
        ),
      ).rejects.toMatchObject({ kind: "format" });
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
    const wrongId = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse({ ...saved, id: USER }));
    await expect(
      new ManagementClient(wrongId, () => true).userOperation(ID, signal),
    ).rejects.toMatchObject({ kind: "format" });
  });

  it("preserves unknown transport/storage failures without retrying execution or falling back to legacy user writes", async () => {
    const signal = new AbortController().signal;
    for (const status of [403, 404, 409, 503]) {
      const fetcher = vi
        .fn<typeof fetch>()
        .mockResolvedValue(
          jsonResponse({ error: { code: "policy_conflict" } }, status),
        );
      await expect(
        new ManagementClient(fetcher, () => true).executeUserOperation(
          ID,
          input,
          "csrf",
          signal,
        ),
      ).rejects.toMatchObject({
        kind: "server",
        code: "policy_conflict",
        status,
      });
      expect(fetcher).toHaveBeenCalledTimes(1);
    }
    const lost = vi
      .fn<typeof fetch>()
      .mockRejectedValue(new TypeError("Lost response"));
    await expect(
      new ManagementClient(lost, () => true).executeUserOperation(
        ID,
        input,
        "csrf",
        signal,
      ),
    ).rejects.toMatchObject({ kind: "network" });
    expect(lost).toHaveBeenCalledTimes(1);
  });

  it("uses the real session cancellation fence to discard an abort-ignoring execute response", async () => {
    const late = deferred<Response>();
    const started = deferred<AbortSignal>();
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementation(async (url, request) => {
        if (url === "/api/v1/auth/session")
          return jsonResponse(sessionFixture());
        if (url === "/api/v1/auth/logout")
          return new Response(null, { status: 204 });
        expect(url).toBe(`/api/v1/proxy/user-operations/${ID}/execute`);
        started.resolve(request!.signal!);
        return late.promise;
      });
    const controller = new SessionController(
      new ManagementClient(fetcher, () => true),
    );
    await controller.check();
    const session = controller.snapshot().session!;
    const issued = controller
      .resource(session, (client, csrf, signal) =>
        client.executeUserOperation(ID, input, csrf, signal),
      )
      .catch((error: unknown) => error);
    const signal = await started.promise;
    await controller.logout();
    expect(signal.aborted).toBe(true);
    late.resolve(jsonResponse(saved));
    expect(await issued).toMatchObject({ name: "AbortError" });
    expect(controller.snapshot().phase).toBe("anonymous");
    expect(fetcher).toHaveBeenCalledTimes(3);
  });
});
