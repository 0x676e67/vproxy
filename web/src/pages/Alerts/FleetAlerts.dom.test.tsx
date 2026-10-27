// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://manager.example/"}
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { ConfigProvider } from "antd";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ALERT_NODE,
  ALERT_PEER,
  ALERT_RESOURCE,
  ALERT_BOOT,
  nodeAlertPageFixture,
  alertFixture,
} from "../../api/alerts.fixtures";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import type { Target } from "../../api/targets";
import { ManagementProvider, useManagement } from "../../auth/context";
import ManagementGate from "../../components/ManagementGate";
import messages from "../../locales/en-US";
import FleetAlerts from "./FleetAlerts";
import { FLEET_POLL_MS } from "./fleet";
vi.mock("@umijs/max", async () => ({
  Link: (await import("react-router-dom")).Link,
}));
vi.mock("../../hooks/useMessages", async () => {
  const captions = (await import("../../locales/en-US")).default;
  return {
    useMessages: () => ({
      intl: {
        locale: "en-US",
        formatNumber: (value: number) => value.toLocaleString("en-US"),
      },
      t: (
        id: keyof typeof captions,
        values?: Record<string, string | number>,
      ) =>
        Object.entries(values ?? {}).reduce(
          (text, [key, value]) => text.replaceAll(`{${key}}`, String(value)),
          captions[id],
        ),
    }),
  };
});
const ids = [ALERT_RESOURCE, ALERT_BOOT, ALERT_PEER];
const target = (node_id: string, index: number): Target => ({
  node_id,
  name: `Child ${index}`,
  origin: "https://child.example:9443",
  server_ip: null,
  active: true,
  retired: false,
  revision: "1",
  observed_epoch: null,
  observed_command: null,
  observed_policy_revision: null,
  rollback_detected: false,
});
const page = (node_id: string) =>
  nodeAlertPageFixture({
    node_id,
    items: [alertFixture({ origin_node_id: node_id })],
  });
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
let visibility: DocumentVisibilityState,
  authenticated: boolean,
  targets: Target[],
  registryReads: number;
let registry: () => Response;
let requests: { url: URL; signal: AbortSignal | null }[];
let remote: (url: URL) => Promise<Response>;
let localReply: () => Response;
beforeEach(() => {
  visibility = "visible";
  authenticated = true;
  targets = ids.map(target);
  registryReads = 0;
  requests = [];
  registry = () =>
    jsonResponse({
      items: targets,
      next_cursor: null,
      controller_available: true,
    });
  remote = async (url) => jsonResponse(page(url.pathname.split("/")[4]));
  localReply = () => jsonResponse(page(ALERT_NODE));
  vi.spyOn(document, "visibilityState", "get").mockImplementation(
    () => visibility,
  );
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
      const url = new URL(String(input), "https://manager.example/");
      if (url.pathname === "/api/v1/auth/session")
        return authenticated
          ? jsonResponse({
              ...sessionFixture(),
              expires_at: Math.floor(Date.now() / 1000) + 3600,
            })
          : jsonResponse({ error: { code: "authentication_required" } }, 403);
      if (url.pathname === "/api/v1/node")
        return jsonResponse({
          node_id: ALERT_NODE,
          name: "Local",
          version: "test",
          os: "linux",
          arch: "x86_64",
          capabilities: [],
        });
      if (url.pathname === "/api/v1/targets") {
        registryReads++;
        return registry();
      }
      if (url.pathname === "/api/v1/operations-alerts") return localReply();
      if (/^\/api\/v1\/targets\/[^/]+\/operations-alerts$/.test(url.pathname)) {
        requests.push({ url, signal: init?.signal ?? null });
        return remote(url);
      }
      throw new Error("Unexpected fixture request");
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
function Host() {
  const { controller } = useManagement();
  return (
    <ManagementGate>
      <button onClick={() => void controller.check()}>test.session</button>
      <FleetAlerts />
    </ManagementGate>
  );
}
function mount() {
  return render(
    <MemoryRouter>
      <ConfigProvider
        theme={{ token: { motion: false } }}
        wave={{ disabled: true }}
      >
        <ManagementProvider>
          <Host />
        </ManagementProvider>
      </ConfigProvider>
    </MemoryRouter>,
  );
}
const click = (key: keyof typeof messages) =>
  fireEvent.click(screen.getByRole("button", { name: messages[key] }));
describe("bounded explicit fleet reads", () => {
  it("expires all near-stale cards with one display deadline and no polling round", async () => {
    vi.useFakeTimers();
    let monotonic = 10_000;
    vi.spyOn(performance, "now").mockImplementation(() => monotonic);
    localReply = () =>
      jsonResponse({ ...page(ALERT_NODE), age_millis: "29000" });
    remote = async (url) =>
      jsonResponse({
        ...page(url.pathname.split("/")[4]),
        age_millis: "29000",
      });
    await act(async () => {
      mount();
      await vi.advanceTimersByTimeAsync(0);
    });
    await act(async () => {
      click("fleet.start");
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(screen.getAllByText(messages["fleet.state.read"])).toHaveLength(4);
    expect(requests).toHaveLength(3);
    expect(registryReads).toBe(2);
    vi.setSystemTime(Date.now() - 60_000);
    monotonic += 2000;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000);
    });
    expect(screen.queryByText(messages["fleet.state.read"])).toBeNull();
    expect(screen.getAllByText(messages["fleet.state.stale"])).toHaveLength(4);
    expect(
      screen.getByText(
        messages["fleet.known"].replace("{known}", "0").replace("{total}", "4"),
      ),
    ).toBeTruthy();
    const card = screen.getByText("Child 0").closest(".ant-card")!;
    expect(
      within(card as HTMLElement).getAllByText(messages["fleet.unknown"]),
    ).toHaveLength(2);
    expect(requests).toHaveLength(3);
    expect(registryReads).toBe(2);
  });
  it("starts explicitly, limits remote concurrency to two, skips paused targets and confirms the registry before publishing full counts", async () => {
    const pending = ids.map(() => deferred<Response>());
    let active = 0,
      peak = 0;
    targets.push({ ...target("BAQEBAQEBAQEBAQEBAQEBA", 3), active: false });
    remote = async (url) => {
      const index = ids.indexOf(url.pathname.split("/")[4]);
      active++;
      peak = Math.max(peak, active);
      try {
        return await pending[index].promise;
      } finally {
        active--;
      }
    };
    mount();
    await screen.findByRole("button", { name: messages["fleet.start"] });
    expect(registryReads).toBe(0);
    expect(requests).toHaveLength(0);
    click("fleet.start");
    await waitFor(() => expect(requests).toHaveLength(2));
    expect(peak).toBe(2);
    await act(async () => pending[0].resolve(jsonResponse(page(ids[0]))));
    await waitFor(() => expect(requests).toHaveLength(3));
    expect(peak).toBe(2);
    await act(async () => {
      pending[1].resolve(jsonResponse(page(ids[1])));
      pending[2].resolve(jsonResponse(page(ids[2])));
    });
    await screen.findByText(messages["fleet.state.paused"]);
    await waitFor(() =>
      expect(screen.getAllByText(messages["fleet.state.read"])).toHaveLength(4),
    );
    expect(registryReads).toBe(2);
    expect(
      requests.every(
        ({ url }) =>
          url.searchParams.get("limit") === "1" &&
          !url.searchParams.has("after"),
      ),
    ).toBe(true);
    const card = screen.getByText("Child 0").closest(".ant-card")!;
    expect(
      within(card as HTMLElement)
        .getByRole("link")
        .getAttribute("href"),
    ).toBe(`/alerts?target=${ids[0]}`);
    expect(
      requests.some(({ url }) => url.pathname.endsWith("egress-alerts")),
    ).toBe(false);
  });
  it("stops when hidden, needs explicit restart and rejects abort-ignoring late replies", async () => {
    const pending = deferred<Response>();
    remote = () => pending.promise;
    mount();
    await screen.findByRole("button", { name: messages["fleet.start"] });
    click("fleet.start");
    await waitFor(() => expect(requests).toHaveLength(2));
    await act(async () => {
      visibility = "hidden";
      document.dispatchEvent(new Event("visibilitychange"));
    });
    expect(requests.every((row) => row.signal?.aborted)).toBe(true);
    await act(async () => {
      visibility = "visible";
      document.dispatchEvent(new Event("visibilitychange"));
      pending.resolve(jsonResponse(page(ids[0])));
    });
    await waitFor(() =>
      expect(
        screen
          .getByRole("button", { name: messages["fleet.start"] })
          .hasAttribute("disabled"),
      ).toBe(false),
    );
    expect(screen.queryByText(messages["fleet.state.read"])).toBeNull();
    expect(requests).toHaveLength(2);
    expect(registryReads).toBe(1);
  });
  it("marks a completed round unknown when target revision drifts instead of publishing successful old results or rescanning indefinitely", async () => {
    registry = () =>
      jsonResponse({
        items: targets.map((row) => ({
          ...row,
          revision: registryReads > 1 ? "2" : "1",
        })),
        next_cursor: null,
        controller_available: true,
      });
    mount();
    await screen.findByRole("button", { name: messages["fleet.start"] });
    click("fleet.start");
    await screen.findByText(messages["fleet.registryChanged"]);
    expect(registryReads).toBe(2);
    expect(requests).toHaveLength(3);
    expect(screen.queryByText(messages["fleet.state.read"])).toBeNull();
    expect(
      screen
        .getByRole("button", { name: messages["fleet.start"] })
        .hasAttribute("disabled"),
    ).toBe(false);
  });
  it("cancels a round on session generation change and does not read another node with the replacement session", async () => {
    const pending = deferred<Response>();
    remote = () => pending.promise;
    mount();
    await screen.findByRole("button", { name: messages["fleet.start"] });
    click("fleet.start");
    await waitFor(() => expect(requests).toHaveLength(2));
    fireEvent.click(screen.getByRole("button", { name: "test.session" }));
    await waitFor(() =>
      expect(requests.every((row) => row.signal?.aborted)).toBe(true),
    );
    await act(async () => pending.resolve(jsonResponse(page(ids[0]))));
    await screen.findByRole("button", { name: messages["fleet.start"] });
    expect(screen.queryByText(messages["fleet.state.read"])).toBeNull();
    expect(requests).toHaveLength(2);
  });
  it("propagates expired local authentication before any remote node read", async () => {
    localReply = () =>
      jsonResponse({ error: { code: "authentication_required" } }, 403);
    mount();
    await screen.findByRole("button", { name: messages["fleet.start"] });
    click("fleet.start");
    await screen.findByRole("button", { name: messages["auth.signIn"] });
    expect(requests).toHaveLength(0);
    expect(screen.queryByText(messages["fleet.state.read"])).toBeNull();
  });
  it("waits thirty seconds after the completed round rather than starting a periodic queue", async () => {
    vi.useFakeTimers();
    const pending = ids.map(() => deferred<Response>());
    let delayed = true;
    remote = async (url) =>
      delayed
        ? pending[ids.indexOf(url.pathname.split("/")[4])].promise
        : jsonResponse(page(url.pathname.split("/")[4]));
    await act(async () => {
      mount();
      await vi.advanceTimersByTimeAsync(0);
    });
    await act(async () => {
      click("fleet.start");
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(requests).toHaveLength(2);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(requests).toHaveLength(2);
    delayed = false;
    await act(async () => {
      pending[0].resolve(jsonResponse(page(ids[0])));
      pending[1].resolve(jsonResponse(page(ids[1])));
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(requests).toHaveLength(3);
    expect(registryReads).toBe(2);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(FLEET_POLL_MS - 1);
    });
    expect(requests).toHaveLength(3);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1);
    });
    expect(requests).toHaveLength(6);
    expect(registryReads).toBe(4);
    await act(async () => click("fleet.stop"));
  });
});
