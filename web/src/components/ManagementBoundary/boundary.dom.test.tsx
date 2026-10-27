// @vitest-environment jsdom
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { lazy, Suspense, useEffect, type ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import ManagementBoundary from ".";
import { innerProvider } from "../../app";

const provider = vi.hoisted(() => ({ mounted: 0, unmounted: 0 }));
vi.mock("../../auth/context", () => ({
  ManagementProvider: ({ children }: { children: ReactNode }) => {
    useEffect(() => {
      provider.mounted++;
      return () => {
        provider.unmounted++;
      };
    }, []);
    return children;
  },
  useManagement: vi.fn(),
}));
vi.mock("../ManagementShell", () => ({
  default: ({ children }: { children: ReactNode }) => children,
}));
vi.mock("../../hooks/useMessages", () => ({
  useMessages: () => ({ t: (key: string) => key }),
}));
vi.mock("@umijs/max", () => ({
  Link: () => null,
  useLocation: vi.fn(),
  useNavigate: vi.fn(),
}));

beforeEach(() => {
  provider.mounted = provider.unmounted = 0;
  vi.stubGlobal("__VPROXY_DEMO__", false);
  // React reports the deliberately injected render error. Never inject a real
  // secret or allow its diagnostic text to enter the test's captured output.
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("management render failure boundary", () => {
  it("keeps the session owner, cleans up the page and never automatically remounts failed work", () => {
    const stopped = vi.fn();
    let started = 0;
    function Page({ failed }: { failed: boolean }) {
      useEffect(() => {
        started++;
        return stopped;
      }, []);
      if (failed) throw new Error("untrusted-render-diagnostic");
      return <div>healthy workspace</div>;
    }
    const view = render(innerProvider(<Page failed={false} />));
    expect(screen.getByText("healthy workspace")).toBeTruthy();
    expect(provider.mounted).toBe(1);
    view.rerender(innerProvider(<Page failed />));
    expect(screen.getByRole("alert").textContent).toContain(
      "app.pageReloadNotice",
    );
    expect(screen.queryByText("healthy workspace")).toBeNull();
    expect(document.body.textContent).not.toContain(
      "untrusted-render-diagnostic",
    );
    expect(stopped).toHaveBeenCalledOnce();
    expect(provider.mounted).toBe(1);
    expect(provider.unmounted).toBe(0);
    view.rerender(innerProvider(<Page failed={false} />));
    expect(started).toBe(1);
    expect(screen.queryByText("healthy workspace")).toBeNull();
    expect(provider.unmounted).toBe(0);
    const reload = vi.fn();
    const realWindow = window;
    try {
      vi.stubGlobal("window", { location: { reload } });
      fireEvent.click(screen.getByRole("button", { name: "app.reloadPage" }));
    } finally {
      vi.stubGlobal("window", realWindow);
    }
    expect(reload).toHaveBeenCalledOnce();
    expect(started).toBe(1);
  });

  it("also catches rejected lazy imports after Suspense without rendering their diagnostic", async () => {
    const Failed = lazy(() =>
      Promise.reject(new Error("untrusted-chunk-diagnostic")),
    );
    render(
      <ManagementBoundary>
        <Suspense fallback={<p>loading page</p>}>
          <Failed />
        </Suspense>
      </ManagementBoundary>,
    );
    await waitFor(() => expect(screen.getByRole("alert")).toBeTruthy());
    expect(document.body.textContent).not.toContain(
      "untrusted-chunk-diagnostic",
    );
    expect(screen.queryByText("loading page")).toBeNull();
    expect(screen.getByRole("button", { name: "app.reloadPage" })).toBeTruthy();
  });
});
