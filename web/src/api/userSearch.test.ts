import { describe, expect, it, vi } from "vitest";
import { ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import { ApiError } from "./error";
import {
  endpointStatus,
  listQuery,
  page,
  proxyUser,
  userSearchCursor,
  userSearchPage,
  userSearchQuery,
  type UserSearchOptions,
} from "./proxy";

const USER = "A".repeat(22);
const PEER = "Q".repeat(22);
const CURSOR = `us1_${"A".repeat(98)}`;
const user = (id = USER) => ({
  id,
  name: "用户 + / %_",
  active: true,
  deleted: false,
  protocols: ["http"],
  concurrent_limit: 8,
  revision: "9",
});
const input: UserSearchOptions = { mode: "name", q: "用户 + / %_", limit: 1 };
const result = () => ({ revision: "9", items: [user()], next_cursor: CURSOR });
const signal = () => new AbortController().signal;

describe("bounded user search boundary", () => {
  it("uses explicit modes and lossless literal query encoding without widening legacy pagination", () => {
    const query = userSearchQuery({
      ...input,
      after: CURSOR,
      include_deleted: true,
    });
    const values = new URLSearchParams(query);
    expect(values.get("q")).toBe(input.q);
    expect(values.get("after")).toBe(CURSOR);
    expect(endpointStatus(`/proxy/users/search${query}`, "GET")).toBe(200);
    expect(endpointStatus(`/targets/${PEER}/users/search${query}`, "GET")).toBe(
      200,
    );
    expect(userSearchQuery({ mode: "name", q: USER })).toContain("mode=name");
    expect(userSearchQuery({ mode: "id", q: USER })).toContain("mode=id");
    expect(() => listQuery({ after: CURSOR }, false)).toThrow(ApiError);
    expect(() => page(result(), proxyUser)).toThrow(ApiError);
    expect(() => endpointStatus("/proxy/users?q=name", "GET")).toThrow(
      ApiError,
    );
  });

  it("rejects invalid UTF-8 escapes, duplicate/unknown fields and malformed input before fetch", async () => {
    for (const query of [
      "mode=name&q=%FF",
      "mode=name&q=%",
      "mode=name&q=x&q=y",
      "mode=name&q=x&mode=id",
      "mode=name&q=x&extra=y",
      "mode=name",
      "q=x",
      "mode=id&q=name",
      "mode=name&q=%00",
      "mode=name&q=+x",
      "mode=name&q=x&after=" + USER,
      "mode=name&q=x&limit=51",
      "mode=name&q=x&include_deleted=1",
    ])
      expect(() =>
        endpointStatus(`/proxy/users/search?${query}`, "GET"),
      ).toThrow(ApiError);
    expect(() =>
      endpointStatus("/proxy/users/search?mode=name&q=x", "POST"),
    ).toThrow(ApiError);
    expect(() => endpointStatus("/proxy/users/search", "GET")).toThrow(
      ApiError,
    );
    const fetcher = vi.fn();
    const client = new ManagementClient(fetcher, () => true);
    for (const options of [
      { mode: "name", q: "界".repeat(43) },
      { mode: "name", q: "\ud800" },
      { mode: "name", q: " " },
      { mode: "id", q: "partial" },
      { mode: "id", q: USER, after: CURSOR },
      { ...input, after: CURSOR.slice(0, -1) + "B" },
    ])
      await expect(
        client.userSearch(options as UserSearchOptions, signal()),
      ).rejects.toThrow(ApiError);
    expect(fetcher).not.toHaveBeenCalled();
    expect(() =>
      endpointStatus(
        `/proxy/users/search?mode=name&q=${"%41".repeat(400)}`,
        "GET",
      ),
    ).toThrow(ApiError);
  });

  it("checks bounded opaque cursors, row order, snapshot revisions and deleted/ID projections", () => {
    expect(userSearchCursor(CURSOR)).toBe(true);
    expect(userSearchPage(result(), input)).toEqual(result());
    expect(() => userSearchPage(result(), { ...input, after: CURSOR })).toThrow(
      ApiError,
    );
    for (const value of [
      { ...result(), next_cursor: USER },
      { ...result(), next_cursor: CURSOR + "A" },
      { ...result(), items: [] },
      { ...result(), items: [user(), user()] },
      { ...result(), items: [{ ...user(), revision: "10" }] },
      { ...result(), items: [{ ...user(), deleted: true }] },
      { ...result(), items: [{ ...user(), verifier: "not-public" }] },
    ])
      expect(() => userSearchPage(value, input)).toThrow(ApiError);
    expect(() =>
      userSearchPage(
        { ...result(), next_cursor: null },
        { mode: "id", q: PEER },
      ),
    ).toThrow(ApiError);
    expect(
      userSearchPage(
        { ...result(), next_cursor: null },
        { mode: "id", q: USER },
      ).items[0].id,
    ).toBe(USER);
    expect(
      userSearchPage(
        { ...result(), items: [{ ...user(), deleted: true }] },
        { ...input, include_deleted: true },
      ).items[0].deleted,
    ).toBe(true);
  });

  it("uses only the selected local/remote read route and never falls back after an error", async () => {
    const fetcher = vi.fn<typeof fetch>(async () =>
      jsonResponse({ ...result(), next_cursor: null }),
    );
    const client = new ManagementClient(fetcher, () => true);
    await client.userSearch(input, signal());
    await client.targetUserSearch(PEER, input, signal());
    expect(fetcher.mock.calls.map((call) => String(call[0]))).toEqual([
      `/api/v1/proxy/users/search${userSearchQuery(input)}`,
      `/api/v1/targets/${PEER}/users/search${userSearchQuery(input)}`,
    ]);
    for (const [status, code] of [
      [502, "user_search_unsupported"],
      [403, "peer_not_authorized"],
      [409, "user_search_changed"],
    ] as const) {
      fetcher.mockImplementationOnce(async () =>
        jsonResponse({ error: { code } }, status),
      );
      await expect(
        client.targetUserSearch(PEER, input, signal()),
      ).rejects.toMatchObject({ status, code });
    }
    expect(fetcher).toHaveBeenCalledTimes(5);
  });
});
