// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../../api/error";
import english from "../../locales/en-US";
import chinese from "../../locales/zh-CN";
import ManagementGate from ".";

const fixture = vi.hoisted(() => ({
  locale: "en-US",
  kind: "https" as "https" | "network",
  check: vi.fn(),
}));

// Exercise the real gate and captions; session transport and HTTP refusal have
// separate client tests. No account, secret or actual API is used here.
vi.mock("../../auth/context", () => ({
  useManagement: () => ({
    controller: { check: fixture.check },
    state: {
      phase: "error",
      busy: false,
      session: null,
      error: new ApiError(fixture.kind),
    },
  }),
}));
vi.mock("../../hooks/useMessages", async () => {
  const en = (await import("../../locales/en-US")).default;
  const zh = (await import("../../locales/zh-CN")).default;
  return {
    useMessages: () => ({
      intl: { locale: fixture.locale },
      t: (key: keyof typeof en) => (fixture.locale === "zh-CN" ? zh : en)[key],
    }),
  };
});

beforeEach(() => {
  fixture.locale = "en-US";
  fixture.kind = "https";
  fixture.check.mockReset().mockResolvedValue(undefined);
});
afterEach(cleanup);

describe("management connection guidance", () => {
  for (const [locale, captions] of [
    ["en-US", english],
    ["zh-CN", chinese],
  ] as const) {
    it(`explains the required HTTPS address without an ineffective retry in ${locale}`, () => {
      fixture.locale = locale;
      render(
        <ManagementGate>
          <div>Protected management content</div>
        </ManagementGate>,
      );
      expect(screen.getByText(captions["auth.httpsTitle"])).toBeTruthy();
      expect(screen.getByText(captions["auth.httpsRequired"])).toBeTruthy();
      expect(
        screen.queryByRole("button", { name: captions["api.retry"] }),
      ).toBeNull();
      expect(screen.queryByRole("textbox")).toBeNull();
      expect(screen.queryByText("Protected management content")).toBeNull();
      expect(fixture.check).not.toHaveBeenCalled();
    });
  }

  it("retains an explicit retry for a transient network failure", () => {
    fixture.kind = "network";
    render(<ManagementGate>{null}</ManagementGate>);
    expect(screen.getByText(english["auth.unavailable"])).toBeTruthy();
    expect(screen.getByText(english["api.network"])).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: english["api.retry"] }));
    expect(fixture.check).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(english["auth.httpsTitle"])).toBeNull();
  });
});
