import { describe, expect, it } from "vitest";
import { ApiError, authenticationRequired } from "./error";

describe("authenticationRequired", () => {
  it.each([401, 403])("recognizes a session rejection with status %s", (status) => {
    expect(
      authenticationRequired(new ApiError("server", "authentication_required", status)),
    ).toBe(true);
  });

  it("does not log out on an invalid machine key or a different server failure", () => {
    expect(authenticationRequired(new ApiError("server", "invalid_token", 401))).toBe(false);
    expect(authenticationRequired(new ApiError("server", "policy_denied", 403))).toBe(false);
    expect(
      authenticationRequired(new ApiError("server", "authentication_required", 503)),
    ).toBe(false);
    expect(authenticationRequired(new Error("authentication_required"))).toBe(false);
  });
});
