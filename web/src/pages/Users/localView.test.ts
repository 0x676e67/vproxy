import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../../api/client";
import { readLocalUserView } from "./localView";

const policy = (revision = "1") => ({
  saved_revision: revision,
  applied_revision: null,
  durable_applied_revision: null,
  proxy_running: false,
  user_count: 0,
  credential_count: 0,
});
const page = (revision = "1") => ({
  revision,
  items: [],
  next_cursor: null,
});
const owner = () => ({
  controller_node_id: null,
  epoch: "1",
  last_terminal_command: "0",
});
function client() {
  return {
    policy: vi.fn(async (_signal: AbortSignal) => policy()),
    users: vi.fn(async (_options: object, _signal: AbortSignal) => page()),
    userSearch: vi.fn(async (_options: object, _signal: AbortSignal) => page()),
    owner: vi.fn(async (_signal: AbortSignal) => owner()),
  };
}
const busy = () => new ApiError("server", "policy_busy", 503);
beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("bounded local user metadata reads", () => {
  it("discards a failed sample and reads all metadata again at the new revision", async () => {
    const api = client();
    api.policy.mockRejectedValueOnce(busy()).mockResolvedValueOnce(policy("2"));
    api.users.mockResolvedValueOnce(page("1")).mockResolvedValueOnce(page("2"));
    const result = readLocalUserView(
      api,
      { include_deleted: false },
      null,
      new AbortController().signal,
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(api.policy).toHaveBeenCalledTimes(1);
    expect(api.users.mock.calls[0][1].aborted).toBe(true);
    await vi.advanceTimersByTimeAsync(249);
    expect(api.policy).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect((await result).page.revision).toBe("2");
    expect(api.policy).toHaveBeenCalledTimes(2);
    expect(api.users).toHaveBeenCalledTimes(2);
    expect(api.owner).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("rechecks ownership busy with the exact search and pagination, without restarting a cursor", async () => {
    const api = client();
    api.owner.mockRejectedValueOnce(busy()).mockResolvedValueOnce(owner());
    const options = {
      include_deleted: true,
      after: "original-cursor",
      limit: 1,
    };
    const search = { mode: "id" as const, q: "original-user" };
    const result = readLocalUserView(
      api,
      options,
      search,
      new AbortController().signal,
    );
    await vi.advanceTimersByTimeAsync(250);
    expect((await result).owner).toEqual(owner());
    expect(api.users).not.toHaveBeenCalled();
    expect(api.policy).toHaveBeenCalledTimes(2);
    expect(api.userSearch.mock.calls.map(([input]) => input)).toEqual([
      { ...options, ...search },
      { ...options, ...search },
    ]);
  });

  it("stops after three busy attempts with no remaining timer", async () => {
    const api = client();
    api.policy.mockRejectedValue(busy());
    const result = readLocalUserView(
      api,
      { include_deleted: false },
      null,
      new AbortController().signal,
    ).catch((error) => error);
    await vi.advanceTimersByTimeAsync(750);
    expect(await result).toMatchObject({ code: "policy_busy" });
    expect(api.policy).toHaveBeenCalledTimes(3);
    expect(api.owner).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([
    new ApiError("network"),
    new ApiError("format"),
    new ApiError("server", "authentication_required", 401),
    new ApiError("server", "policy_denied", 403),
    new ApiError("server", "user_search_changed", 409),
    new ApiError("server", "policy_unavailable", 503),
    new ApiError("server", "policy_busy", 502),
  ])("does not retry other errors (%s)", async (error) => {
    const api = client();
    api.policy.mockRejectedValue(error);
    await expect(
      readLocalUserView(
        api,
        { include_deleted: false },
        null,
        new AbortController().signal,
      ),
    ).rejects.toBe(error);
    expect(api.policy).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([null, { mode: "name" as const, q: "same name" }])(
    "preserves a revision conflict instead of silently changing the observation (%s)",
    async (search) => {
      const api = client();
      api.policy.mockResolvedValue(policy("2"));
      await expect(
        readLocalUserView(
          api,
          { include_deleted: false },
          search,
          new AbortController().signal,
        ),
      ).rejects.toMatchObject({
        code: search ? "user_search_changed" : "policy_conflict",
        status: 409,
      });
      expect(api.policy).toHaveBeenCalledTimes(1);
      expect(api.owner).not.toHaveBeenCalled();
    },
  );

  it("cancels the retry delay before a replaced view can issue more reads", async () => {
    const api = client();
    api.policy.mockRejectedValue(busy());
    const request = new AbortController();
    const result = readLocalUserView(
      api,
      { include_deleted: false },
      null,
      request.signal,
    ).catch((error) => error);
    await vi.advanceTimersByTimeAsync(0);
    request.abort();
    expect(await result).toMatchObject({ name: "AbortError" });
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(1000);
    expect(api.policy).toHaveBeenCalledTimes(1);
  });

  it("rejects a late sample even when its transport ignores cancellation", async () => {
    const api = client();
    let finish!: (value: ReturnType<typeof page>) => void;
    api.users.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    const request = new AbortController();
    const result = readLocalUserView(
      api,
      { include_deleted: false },
      null,
      request.signal,
    ).catch((error) => error);
    request.abort();
    finish(page());
    expect(await result).toMatchObject({ name: "AbortError" });
    expect(api.owner).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
});
