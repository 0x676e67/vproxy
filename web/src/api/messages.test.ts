import { describe, expect, it } from "vitest";
import { ApiError } from "./client";
import { errorMessage } from "./messages";

describe("safe translated API errors", () => {
  it("does not present a missing operation record as a failed policy mutation", () => {
    expect(
      errorMessage(new ApiError("server", "operation_not_queryable", 404)),
    ).toBe("users.operationUnavailable");
    expect(
      errorMessage(new ApiError("server", "operation_capacity", 503)),
    ).toBe("users.operationCapacity");
    expect(errorMessage(new ApiError("server", "operation_denied", 403))).toBe(
      "users.denied",
    );
  });
  it("maps only explicit error codes, not inherited object property names", () => {
    expect(
      errorMessage(new ApiError("server", "invalid_credentials", 403)),
    ).toBe("auth.invalidCredentials");
    for (const code of ["__proto__", "constructor", "unknown_code"]) {
      expect(errorMessage(new ApiError("server", code, 500))).toBe(
        "api.server",
      );
    }
  });
});
