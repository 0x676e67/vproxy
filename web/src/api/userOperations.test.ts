import { describe, expect, it } from "vitest";
import { ApiError } from "./error";
import { endpointStatus } from "./proxy";
import {
  userOperation,
  userOperationInput,
  userOperationPage,
  userOperationQuery,
  type UserChange,
  type UserOperation,
  type UserOperationInput,
  type UserOperationOptions,
} from "./userOperations";

const ID = "A".repeat(22);
const OTHER = "AQEBAQEBAQEBAQEBAQEBAQ";
const NODE = "AgICAgICAgICAgICAgICAg";
const USER = "AwMDAwMDAwMDAwMDAwMDAw";
const MAXIMUM = "9223372036854775807";
const input = (
  change: UserChange = {
    action: "create_user",
    name: "Test user",
    protocols: ["http"],
    concurrent_limit: 32,
  },
): UserOperationInput => ({
  expected_revision: "7",
  expected_epoch: "3",
  change,
});
const operation = (patch: Partial<UserOperation> = {}): UserOperation => ({
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
  ...patch,
});

describe("non-secret local user operation codec", () => {
  it("accepts only the four user changes and copies their mutable input fields", () => {
    const changes: UserChange[] = [
      input().change,
      { ...input().change, action: "update_user", id: USER } as UserChange,
      { action: "set_user_active", id: USER, active: false },
      { action: "delete_user", id: USER },
    ];
    for (const change of changes)
      expect(userOperationInput(input(change))).toEqual(input(change));
    const original = input();
    const checked = userOperationInput(original);
    expect(checked).not.toBe(original);
    expect(checked.change).not.toBe(original.change);
    if (
      original.change.action === "create_user" &&
      checked.change.action === "create_user"
    )
      expect(checked.change.protocols).not.toBe(original.change.protocols);
    for (const invalid of [
      null,
      { ...original, expected_revision: "0" },
      { ...original, expected_epoch: "03" },
      { ...original, expected_epoch: "9223372036854775808" },
      { ...original, secret: "not-accepted" },
      { ...original, change: null },
      { ...original, change: { ...original.change, name: " padded " } },
      { ...original, change: { ...original.change, protocols: ["udp"] } },
      { ...original, change: { ...original.change, concurrent_limit: 0 } },
      { ...original, change: { action: "delete_user", id: "not-an-id" } },
      {
        ...original,
        change: { action: "set_user_active", id: USER, active: "false" },
      },
      { ...original, change: { action: "create_credential", user_id: USER } },
    ])
      expect(() => userOperationInput(invalid as UserOperationInput)).toThrow(
        ApiError,
      );
  });

  it("distinguishes reserved, saved and fixed rejection metadata without inventing runtime success", () => {
    expect(userOperation(operation())).toEqual(operation());
    const saved = operation({
      state: "saved",
      saved_revision: "8",
      user_id: USER,
    });
    expect(userOperation(saved)).toEqual(saved);
    for (const rejection of [
      "invalid_policy",
      "policy_conflict",
      "resource_not_found",
      "policy_capacity",
      "resource_managed",
      "owner_conflict",
    ] as const)
      expect(
        userOperation(operation({ state: "rejected", rejection })).rejection,
      ).toBe(rejection);
    const maximum = operation({
      expected_revision: MAXIMUM,
      sequence: MAXIMUM,
    });
    expect(userOperation(maximum)).toEqual(maximum);
    for (const action of [
      "update_user",
      "set_user_active",
      "delete_user",
    ] as const)
      expect(userOperation(operation({ action, user_id: USER })).user_id).toBe(
        USER,
      );
  });

  it("rejects contradictory states, unbounded numbers and unexpected secret or payload fields", () => {
    const saved = operation({
      state: "saved",
      saved_revision: "8",
      user_id: USER,
    });
    for (const invalid of [
      null,
      { ...operation(), id: `${"A".repeat(21)}B` },
      { ...operation(), node_id: "display-name" },
      { ...operation(), sequence: "01" },
      { ...operation(), sequence: "9223372036854775808" },
      { ...operation(), action: "create_credential" },
      { ...operation(), state: "applied" },
      { ...operation(), user_id: USER },
      { ...operation(), action: "delete_user", user_id: null },
      { ...operation(), saved_revision: "8" },
      { ...operation(), rejection: "owner_conflict" },
      { ...operation(), state: "rejected", rejection: null },
      { ...operation(), state: "rejected", rejection: "internal_error" },
      { ...saved, user_id: null },
      { ...saved, saved_revision: "7" },
      { ...saved, saved_revision: "9" },
      { ...saved, rejection: "policy_conflict" },
      {
        ...saved,
        expected_revision: MAXIMUM,
        saved_revision: "9223372036854775808",
      },
      { ...saved, secret: "unexpected-secret" },
      { ...saved, change: input().change },
    ])
      expect(() => userOperation(invalid)).toThrow(ApiError);
  });

  it("binds a known operation ID, action, subject and CAS envelope without matching the latest record", () => {
    expect(userOperation(operation(), { id: ID, input: input() }).id).toBe(ID);
    const update = input({ action: "delete_user", id: USER });
    const deleted = operation({
      action: "delete_user",
      user_id: USER,
      state: "saved",
      saved_revision: "8",
    });
    expect(userOperation(deleted, { id: ID, input: update })).toEqual(deleted);
    for (const [record, expected] of [
      [operation(), { id: OTHER }],
      [operation({ expected_epoch: "4" }), { input: input() }],
      [operation({ expected_revision: "8" }), { input: input() }],
      [operation({ action: "update_user", user_id: USER }), { input: input() }],
      [deleted, { input: input({ action: "delete_user", id: OTHER }) }],
    ] as const)
      expect(() => userOperation(record, expected)).toThrow(ApiError);
  });

  it("checks descending bounded pages and their exact continuation sequence", () => {
    const first = operation();
    const last = operation({ id: OTHER, sequence: "9" });
    const page = { items: [first, last], next_cursor: "9" };
    expect(userOperationPage(page, { before: "11", limit: 2 })).toEqual(page);
    expect(userOperationPage({ items: [], next_cursor: null }, {})).toEqual({
      items: [],
      next_cursor: null,
    });
    for (const invalid of [
      { ...page, next_cursor: "10" },
      { ...page, next_cursor: "09" },
      { ...page, next_cursor: "11" },
      { ...page, items: [last, first] },
      { ...page, items: [first, { ...last, sequence: "10" }] },
      { ...page, items: [first, { ...last, id: ID }] },
      { ...page, items: [first, { ...last, node_id: ID }] },
      { items: [first], next_cursor: "10" },
      { items: [], next_cursor: "9" },
      { ...page, revision: "8" },
    ])
      expect(() =>
        userOperationPage(invalid, { before: "11", limit: 2 }),
      ).toThrow(ApiError);
    expect(() => userOperationPage(page, { before: "10", limit: 2 })).toThrow(
      ApiError,
    );
    expect(() => userOperationPage(page, { limit: 1 })).toThrow(ApiError);
    expect(userOperationQuery({ before: MAXIMUM, limit: 50 })).toBe(
      `?before=${MAXIMUM}&limit=50`,
    );
    expect(userOperationQuery({})).toBe("");
    for (const invalid of [
      null,
      { before: "0" },
      { before: "01" },
      { before: "9223372036854775808" },
      { limit: 0 },
      { limit: 51 },
      { after: ID },
      { administrator_id: ID },
    ])
      expect(() => userOperationQuery(invalid as UserOperationOptions)).toThrow(
        ApiError,
      );
  });

  it("keeps methods, statuses and list query fields fixed at the transport boundary", () => {
    expect(endpointStatus("/proxy/user-operations", "POST")).toBe(201);
    expect(
      endpointStatus("/proxy/user-operations?before=10&limit=25", "GET"),
    ).toBe(200);
    expect(endpointStatus(`/proxy/user-operations/${ID}`, "GET")).toBe(200);
    expect(endpointStatus(`/proxy/user-operations/${ID}/execute`, "POST")).toBe(
      200,
    );
    for (const [endpoint, method] of [
      ["/proxy/user-operations", "PUT"],
      ["/proxy/user-operations?limit=1", "POST"],
      ["/proxy/user-operations?before=01", "GET"],
      ["/proxy/user-operations?limit=51", "GET"],
      ["/proxy/user-operations?limit=1&limit=2", "GET"],
      ["/proxy/user-operations?after=10", "GET"],
      ["/proxy/user-operations?administrator_id=other", "GET"],
      [`/proxy/user-operations/${ID}?limit=1`, "GET"],
      [`/proxy/user-operations/${ID}`, "POST"],
      [`/proxy/user-operations/${ID}/execute`, "GET"],
      [`/proxy/user-operations/${"A".repeat(21)}B`, "GET"],
      [`/targets/${NODE}/user-operations`, "GET"],
    ] as const)
      expect(() => endpointStatus(endpoint, method)).toThrow(ApiError);
  });
});
