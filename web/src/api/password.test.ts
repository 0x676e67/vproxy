import { describe, expect, it, vi } from "vitest";
import { ApiError, ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import {
  passwordChangeDisposition,
  validCurrentPassword,
  validNewPassword,
} from "./password";

describe("self-service password boundary", () => {
  it("matches UTF-8/codepoint/control limits without trimming or accepting lone surrogates", () => {
    expect(validNewPassword("  twelve chars  ")).toBe(true);
    expect(validNewPassword("😀".repeat(12))).toBe(true);
    expect(validNewPassword("😀".repeat(256))).toBe(true);
    for (const value of [
      "short",
      "😀".repeat(257),
      "valid passphrase\n",
      "valid passphrase\u0085",
      "long password\ud800",
      undefined,
    ])
      expect(validNewPassword(value)).toBe(false);
    expect(validCurrentPassword("old")).toBe(true);
    expect(validCurrentPassword("")).toBe(false);
  });

  it("sends exactly one same-origin CSRF POST with no target or password in its URL", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(null, { status: 204 }));
    const client = new ManagementClient(fetcher, () => true);
    await client.changePassword(
      "current fixture password",
      "new fixture password",
      "C".repeat(43),
      new AbortController().signal,
    );
    expect(fetcher).toHaveBeenCalledOnce();
    const [path, request] = fetcher.mock.calls[0]!;
    expect(path).toBe("/api/v1/auth/password");
    expect(request).toMatchObject({
      method: "POST",
      credentials: "same-origin",
      redirect: "error",
      cache: "no-store",
      headers: { "X-CSRF-Token": "C".repeat(43) },
    });
    expect(JSON.parse(request!.body as string)).toEqual({
      current_password: "current fixture password",
      new_password: "new fixture password",
    });
  });

  it("requires 204 and never retries network, malformed-success or unknown outcomes", async () => {
    for (const response of [
      jsonResponse({}),
      jsonResponse({ error: { code: "password_change_outcome_unknown" } }, 503),
      new Error("private transport detail"),
    ]) {
      const fetcher = vi.fn<typeof fetch>();
      if (response instanceof Error) fetcher.mockRejectedValue(response);
      else fetcher.mockResolvedValue(response);
      const failure = await new ManagementClient(fetcher, () => true)
        .changePassword(
          "current fixture password",
          "new fixture password",
          "C".repeat(43),
          new AbortController().signal,
        )
        .catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(ApiError);
      expect((failure as Error).message).toBe("Management request failed");
      expect(fetcher).toHaveBeenCalledOnce();
    }
    const fetcher = vi.fn<typeof fetch>();
    await expect(
      new ManagementClient(fetcher, () => false).changePassword(
        "current fixture password",
        "new fixture password",
        "C".repeat(43),
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ kind: "https" });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("retains authority only for explicit pre-fence status/code pairs", () => {
    expect(
      passwordChangeDisposition(
        new ApiError("server", "invalid_credentials", 403),
      ),
    ).toBe("retain");
    expect(
      passwordChangeDisposition(
        new ApiError("server", "password_change_busy", 503),
      ),
    ).toBe("retain");
    expect(
      passwordChangeDisposition(
        new ApiError("server", "password_change_outcome_unknown", 503),
      ),
    ).toBe("blocked");
    expect(
      passwordChangeDisposition(
        new ApiError("server", "password_change_conflict", 409),
      ),
    ).toBe("failed");
    for (const error of [
      new ApiError("network"),
      new ApiError("format"),
      new ApiError("server", "unknown"),
      new ApiError("server", "invalid_credentials", 500),
    ])
      expect(passwordChangeDisposition(error)).toBe("unconfirmed");
  });
});
