import { describe, expect, it } from "vitest";
import type { ProxyUser } from "../../api/proxy";
import type { ScopeChange } from "../../api/scope";
import type { Submission } from "../../api/targets";
import { createdUserDelivery } from "./delivery";

const user: ProxyUser = {
  id: "Q".repeat(22),
  name: "A name shared by other users",
  active: true,
  deleted: false,
  protocols: ["http"],
  concurrent_limit: 32,
  revision: "27",
};
const result = (): ScopeChange => ({
  revision: "27",
  user,
  credential: null,
  secret: null,
  submission: null,
});
const submission = (): Submission => ({
  job: {
    node_id: "A".repeat(22),
    job_id: "A".repeat(22),
    controller_epoch: "1",
    command_id: "2",
    expected_policy_revision: "26",
    state: "saved",
    policy_revision: "27",
    outcome_code: null,
    attempts: 1,
    next_attempt: "0",
  },
  response: {
    receipt: {
      controller_epoch: "1",
      command_id: "2",
      status: "saved",
      policy_revision: "27",
      rejection: null,
      user_id: user.id,
      credential_id: null,
    },
    replayed: false,
    user,
    credential: null,
    secret: null,
    secret_available: false,
  },
});

describe("completed user creation delivery", () => {
  it("retains the exact returned identity and global revision without depending on a page or display name", () => {
    const created = createdUserDelivery(result());
    expect(created).toEqual({ user, revision: "27" });
    expect(created?.user).toBe(user);
    const remote = { ...result(), submission: submission() };
    expect(createdUserDelivery(remote)).toEqual(created);
    // Delivery holds no credential/secret or executable follow-up command.
    expect(Object.keys(created!)).toEqual(["user", "revision"]);
  });

  it("does not continue from a pending ticket, rejected or replayed command, or missing result identity", () => {
    const ticket = submission();
    expect(
      createdUserDelivery({
        ...result(),
        submission: { ...ticket, response: null },
      }),
    ).toBeNull();
    const response = ticket.response!;
    for (const value of [
      { ...result(), user: null },
      { ...result(), revision: null },
      {
        ...result(),
        submission: {
          ...ticket,
          response: { ...response, replayed: true },
        },
      },
      {
        ...result(),
        submission: {
          ...ticket,
          response: {
            ...response,
            receipt: { ...response.receipt, status: "rejected" as const },
          },
        },
      },
    ])
      expect(createdUserDelivery(value)).toBeNull();
  });
});
