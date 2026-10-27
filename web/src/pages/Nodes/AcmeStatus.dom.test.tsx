// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://manager.example/"}
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { ConfigProvider } from "antd";
import { StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import { ManagementProvider, useManagement } from "../../auth/context";
import ManagementGate from "../../components/ManagementGate";
import messages from "../../locales/en-US";
import AcmeStatus from "./AcmeStatus";

vi.mock("../../hooks/useMessages", async () => {
  const captions = (await import("../../locales/en-US")).default;
  return {
    useMessages: () => ({
      intl: { locale: "en-US" },
      t: (id: keyof typeof captions) => captions[id],
    }),
  };
});

const status = () => ({
  mode: "acme",
  environment: "staging",
  challenge: "tls-alpn-01",
  certificate: {
    not_before_unix_s: "100",
    not_after_unix_s: "200",
    available: true,
  },
  activity: "waiting",
  next_attempt_at_unix_s: "175",
  last_failure: "review_required",
  observed_at_unix_s: "150",
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
let readStatus: () => Promise<Response>;
let checkSession: () => Promise<void>;
let requests: { path: string; method: string; signal: AbortSignal | null }[];
beforeEach(() => {
  requests = [];
  readStatus = async () => jsonResponse(status());
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  vi.stubGlobal("matchMedia", (media: string) => ({
    matches: false,
    media,
    onchange: null,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent: () => false,
  }));
  const computed = window.getComputedStyle.bind(window);
  vi.spyOn(window, "getComputedStyle").mockImplementation((element) =>
    computed(element),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input),
        method = init?.method ?? "GET";
      requests.push({ path, method, signal: init?.signal ?? null });
      if (path === "/api/v1/auth/session")
        return jsonResponse({
          ...sessionFixture(),
          expires_at: Math.floor(Date.now() / 1000) + 3600,
        });
      if (path === "/api/v1/auth/logout" && method === "POST")
        return new Response(null, { status: 204 });
      if (path === "/api/v1/tls/acme" && method === "GET") return readStatus();
      throw new Error("Unexpected fixture API request");
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function Host() {
  const { controller, state } = useManagement();
  checkSession = () => controller.check();
  return (
    <>
      <output data-testid="session-phase">{state.phase}</output>
      <button onClick={() => void controller.logout()}>test.logout</button>
      <button onClick={() => void controller.check()}>test.session</button>
      <ManagementGate>
        <p>Local node remains visible</p>
        <AcmeStatus disabled={false} />
      </ManagementGate>
    </>
  );
}
async function mount() {
  const view = render(
    <StrictMode>
      <ConfigProvider theme={{ token: { motion: false } }}>
        <ManagementProvider>
          <Host />
        </ManagementProvider>
      </ConfigProvider>
    </StrictMode>,
  );
  await screen.findByRole("button", { name: messages["acme.title"] });
  return view;
}
const reads = () =>
  requests.filter((request) => request.path === "/api/v1/tls/acme");
const toggle = () =>
  fireEvent.click(screen.getByRole("button", { name: messages["acme.title"] }));

describe("local management HTTPS panel", () => {
  it("reads only on expansion and explicit refresh, keeping an old failure beside a usable certificate", async () => {
    await mount();
    expect(reads()).toHaveLength(0);
    toggle();
    await screen.findByText(messages["acme.stagingWarning"]);
    expect(screen.getByText(messages["acme.available"])).toBeTruthy();
    expect(
      screen.getByText(messages["acme.failure.review_required"]),
    ).toBeTruthy();
    expect(reads()).toHaveLength(1);
    readStatus = async () =>
      jsonResponse({
        ...status(),
        environment: "production",
        challenge: "http-01",
        activity: "working",
        next_attempt_at_unix_s: null,
      });
    fireEvent.click(
      screen.getByRole("button", { name: messages["acme.refresh"] }),
    );
    await screen.findByText(messages["acme.activity.working"]);
    expect(screen.queryByText(messages["acme.stagingWarning"])).toBeNull();
    expect(screen.getByText(messages["acme.available"])).toBeTruthy();
    expect(screen.getByText(messages["acme.lastFailure"])).toBeTruthy();
    expect(reads()).toHaveLength(2);
    expect(requests.every((request) => request.method === "GET")).toBe(true);
    toggle();
    expect(reads()).toHaveLength(2);
  });

  it("keeps an older server's 404 local and can explicitly refresh to manual mode", async () => {
    readStatus = async () =>
      jsonResponse(
        { error: { code: "not_found", message: "private-status-marker" } },
        404,
      );
    await mount();
    toggle();
    await screen.findByText(messages["acme.unsupported"]);
    expect(screen.getByText("Local node remains visible")).toBeTruthy();
    expect(screen.queryByText("private-status-marker")).toBeNull();
    expect(reads()).toHaveLength(1);
    readStatus = async () => jsonResponse({ mode: "manual" });
    fireEvent.click(
      screen.getByRole("button", { name: messages["acme.refresh"] }),
    );
    await screen.findByText(messages["acme.manual"]);
    expect(screen.queryByText(messages["acme.unsupported"])).toBeNull();
    expect(reads()).toHaveLength(2);
  });

  it("requires a new expansion after a session check completes in one render batch", async () => {
    await mount();
    toggle();
    await screen.findByText(messages["acme.stagingWarning"]);
    expect(reads()).toHaveLength(1);
    await act(async () => {
      await checkSession();
    });
    expect(screen.getByTestId("session-phase").textContent).toBe(
      "authenticated",
    );
    expect(
      screen
        .getByRole("button", { name: messages["acme.title"] })
        .getAttribute("aria-expanded"),
    ).toBe("false");
    expect(reads()).toHaveLength(1);
    expect(screen.queryByText(messages["acme.stagingWarning"])).toBeNull();
    readStatus = async () => jsonResponse({ mode: "manual" });
    toggle();
    await screen.findByText(messages["acme.manual"]);
    expect(reads()).toHaveLength(2);
  });

  it("aborts a closed panel and ignores its late response after reopening", async () => {
    const late = deferred<Response>();
    readStatus = () => late.promise;
    await mount();
    toggle();
    await waitFor(() => expect(reads()).toHaveLength(1));
    const signal = reads()[0].signal;
    toggle();
    await waitFor(() => expect(signal?.aborted).toBe(true));
    readStatus = async () => jsonResponse({ mode: "manual" });
    toggle();
    await screen.findByText(messages["acme.manual"]);
    await act(async () => {
      late.resolve(jsonResponse(status()));
    });
    expect(screen.queryByText(messages["acme.stagingWarning"])).toBeNull();
    expect(screen.getByText(messages["acme.manual"])).toBeTruthy();
    expect(reads()).toHaveLength(2);
  });

  it("cancels on logout and cannot show an abort-ignoring response in a later session generation", async () => {
    const late = deferred<Response>();
    readStatus = () => late.promise;
    await mount();
    toggle();
    await waitFor(() => expect(reads()).toHaveLength(1));
    const signal = reads()[0].signal;
    fireEvent.click(screen.getByRole("button", { name: "test.logout" }));
    await waitFor(() =>
      expect(screen.getByTestId("session-phase").textContent).toBe("anonymous"),
    );
    expect(signal?.aborted).toBe(true);
    readStatus = async () => jsonResponse({ mode: "manual" });
    fireEvent.click(screen.getByRole("button", { name: "test.session" }));
    await screen.findByRole("button", { name: messages["acme.title"] });
    toggle();
    await screen.findByText(messages["acme.manual"]);
    await act(async () => {
      late.resolve(jsonResponse(status()));
    });
    expect(screen.queryByText(messages["acme.stagingWarning"])).toBeNull();
    expect(screen.queryByText(messages["acme.available"])).toBeNull();
    expect(screen.getByText(messages["acme.manual"])).toBeTruthy();
    expect(reads()).toHaveLength(2);
    expect(
      requests
        .filter((request) => request.method !== "GET")
        .map((request) => request.path),
    ).toEqual(["/api/v1/auth/logout"]);
  });
});
