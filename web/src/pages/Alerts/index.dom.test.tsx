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
import { Link, MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ALERT_BOOT,
  ALERT_NODE,
  ALERT_PEER,
  ALERT_RESOURCE,
  alertFixture,
  alertPageFixture,
  nodeAlertPageFixture,
} from "../../api/alerts.fixtures";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import { ManagementProvider, useManagement } from "../../auth/context";
import messages from "../../locales/en-US";
import ResourcesPage from "../Resources";
import AlertsPage from "./index";
import { ALERT_POLL_MS } from "./useAlerts";

// Keep the page, Ant Design, session lifecycle and API parsing real.
vi.mock("@umijs/max", async () => {
  const router = await import("react-router-dom");
  return {
    Link: router.Link,
    useLocation: router.useLocation,
    useNavigate: router.useNavigate,
  };
});
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
        Object.entries(values ?? {}).reduce<string>(
          (caption, [key, value]) =>
            caption.replaceAll(`{${key}}`, String(value)),
          captions[id],
        ),
    }),
  };
});

let authenticated: boolean;
let visibility: DocumentVisibilityState;
let requests: { query: string; method: string; signal: AbortSignal | null }[];
let onRead: (url: URL) => Promise<Response>;
let nodeReads: number;
let remoteRequests: { url: URL; signal: AbortSignal | null }[];
let onRemoteRead: (url: URL) => Promise<Response>;
let addressRequests: { url: URL; signal: AbortSignal | null }[];
let onAddressRead: (url: URL) => Promise<Response>;
const addressPage = (ip: string) => ({
  revision: "9",
  address: {
    id: ALERT_RESOURCE,
    name: "Current directory entry",
    ip,
    prefix_id: null,
    state: "retired",
    revision: "2",
  },
});
const OTHER_PEER = "BAQEBAQEBAQEBAQEBAQEBA";
const registeredTarget = (node_id: string) => ({
  node_id,
  name: node_id === ALERT_PEER ? "Remote fixture" : "Other fixture",
  origin: "https://child.example:9443",
  server_ip: null,
  active: true,
  retired: false,
  revision: "1",
  observed_epoch: "1",
  observed_command: "0",
  observed_policy_revision: "1",
  rollback_detected: false,
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
function SessionControl({ resources }: { resources: boolean }) {
  const { controller, state } = useManagement();
  return (
    <>
      <output data-testid="session-phase">{state.phase}</output>
      <button onClick={() => void controller.check()}>test.session</button>
      <Link to={`/alerts?target=${ALERT_PEER}`}>test.first</Link>
      <Link to={`/alerts?target=${OTHER_PEER}`}>test.other</Link>
      <Link to="/alerts">test.local</Link>
      {resources ? (
        <Routes>
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/resources" element={<ResourcesPage />} />
        </Routes>
      ) : (
        <AlertsPage />
      )}
    </>
  );
}
function mount(location = "/alerts", resources = false) {
  return render(
    <MemoryRouter initialEntries={[location]}>
      <ConfigProvider wave={{ disabled: true }}>
        <ManagementProvider>
          <SessionControl resources={resources} />
        </ManagementProvider>
      </ConfigProvider>
    </MemoryRouter>,
  );
}
async function refresh() {
  const button = screen.getByRole("button", {
    name: messages["alerts.refresh"],
  });
  await waitFor(() => {
    expect(button.getAttribute("aria-busy")).toBe("false");
    expect((button as HTMLButtonElement).disabled).toBe(false);
  });
  fireEvent.click(button);
}
async function hide() {
  await act(async () => {
    visibility = "hidden";
    document.dispatchEvent(new Event("visibilitychange"));
  });
}
async function show() {
  await act(async () => {
    visibility = "visible";
    document.dispatchEvent(new Event("visibilitychange"));
  });
}
beforeEach(() => {
  authenticated = true;
  visibility = "visible";
  requests = [];
  nodeReads = 0;
  remoteRequests = [];
  addressRequests = [];
  onRead = async () => jsonResponse(alertPageFixture());
  onRemoteRead = async (url) => {
    const node_id = url.pathname.split("/")[4];
    return jsonResponse(
      nodeAlertPageFixture({
        node_id,
        items: [alertFixture({ origin_node_id: node_id })],
      }),
    );
  };
  onAddressRead = async (url) =>
    jsonResponse(
      addressPage(
        url.pathname.includes(ALERT_PEER) ? "192.0.2.20" : "2001:db8::30",
      ),
    );
  vi.stubGlobal("__VPROXY_DEMO__", false);
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
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: false,
    media: query,
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
      const url = new URL(String(input), "https://manager.example");
      if (url.pathname === "/api/v1/auth/session")
        return authenticated
          ? jsonResponse({
              ...sessionFixture(),
              expires_at: Math.floor(Date.now() / 1000) + 3600,
            })
          : jsonResponse({ error: { code: "authentication_required" } }, 403);
      if (url.pathname === "/api/v1/targets")
        return jsonResponse({
          items: [registeredTarget(ALERT_PEER), registeredTarget(OTHER_PEER)],
          next_cursor: null,
          controller_available: true,
        });
      if (url.pathname === "/api/v1/node") {
        nodeReads++;
        return jsonResponse({
          node_id: ALERT_NODE,
          name: "Observer",
          version: "test",
          os: "linux",
          arch: "x86_64",
          capabilities: [],
        });
      }
      if (
        [ALERT_PEER, OTHER_PEER].some(
          (peer) => url.pathname === `/api/v1/targets/${peer}`,
        )
      )
        return jsonResponse(registeredTarget(url.pathname.split("/")[4]));
      if (/^\/api\/v1\/targets\/[^/]+\/operations-alerts$/.test(url.pathname)) {
        remoteRequests.push({ url, signal: init?.signal ?? null });
        return onRemoteRead(url);
      }
      if (
        /^\/api\/v1\/targets\/[^/]+\/proxy\/addresses\/[^/]+$/.test(
          url.pathname,
        )
      ) {
        addressRequests.push({ url, signal: init?.signal ?? null });
        return onAddressRead(url);
      }
      if (url.pathname !== "/api/v1/alerts")
        throw new Error("Unexpected fixture endpoint");
      requests.push({
        query: url.search,
        method: init?.method ?? "GET",
        signal: init?.signal ?? null,
      });
      return onRead(url);
    }),
  );
});

describe("explicit selected-node operations alert reads", () => {
  it("expires a manual snapshot using monotonic receipt age without a new request or another UI action", async () => {
    vi.useFakeTimers();
    let monotonic = 10_000;
    vi.spyOn(performance, "now").mockImplementation(() => monotonic);
    onRemoteRead = async () =>
      jsonResponse(nodeAlertPageFixture({ age_millis: "29000" }));
    await act(async () => {
      mount(`/alerts?target=${ALERT_PEER}`);
      await vi.advanceTimersByTimeAsync(0);
    });
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: messages["alerts.refresh"] }),
      );
      await vi.advanceTimersByTimeAsync(0);
    });
    const active = () =>
      screen
        .getByText(messages["alerts.activeCount"])
        .closest(".ant-descriptions-item")!
        .querySelector(".ant-descriptions-item-content")!.textContent;
    expect(active()).toBe("1");
    expect(screen.queryByText(messages["alerts.previousRecord"])).toBeNull();
    expect(remoteRequests).toHaveLength(1);
    // Changing wall time does not give the received snapshot a fresh lifetime.
    vi.setSystemTime(Date.now() - 60_000);
    monotonic += 2000;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000);
    });
    expect(screen.getByText(messages["alerts.previousRecord"])).toBeTruthy();
    expect(screen.getByText(messages["alerts.remoteUnknown"])).toBeTruthy();
    expect(active()).toBe("—");
    expect(remoteRequests).toHaveLength(1);
    expect(requests).toHaveLength(0);
  });
  it("keeps policy, traffic and node actions attached to the selected node without reading its downstream directory", async () => {
    onRemoteRead = async () =>
      jsonResponse(
        nodeAlertPageFixture({
          active_count: 3,
          items: (
            [
              ["policy", "policy_not_applied"],
              ["traffic_checkpoint", "traffic_checkpoint_failed"],
              ["node_tls", "node_tls_identity_expired"],
            ] as const
          ).map(([kind, code], index) =>
            alertFixture({
              id: String(index + 1),
              kind,
              code,
              origin_node_id: ALERT_PEER,
              resource_id: null,
              check: null,
              target: null,
            }),
          ),
        }),
      );
    mount(`/alerts?target=${ALERT_PEER}`);
    await screen.findByText(messages["alerts.remoteUnread"]);
    await refresh();
    await screen.findByText(messages["alerts.code.policy_not_applied"]);
    expect(
      screen
        .getByRole("link", { name: messages["alerts.openPolicy"] })
        .getAttribute("href"),
    ).toBe(`/users?target=${ALERT_PEER}`);
    expect(
      screen
        .getByRole("link", { name: messages["alerts.openTraffic"] })
        .getAttribute("href"),
    ).toBe(`/traffic?scope=node&target=${ALERT_PEER}`);
    const tls = screen
      .getByText(messages["alerts.code.node_tls_identity_expired"])
      .closest("tr")!;
    expect(within(tls).getByRole("link").getAttribute("href")).toBe("/nodes");
    expect(
      within(tls).getByText(messages["fleet.nodeLocationHint"]),
    ).toBeTruthy();
    expect(remoteRequests).toHaveLength(1);
    expect(requests).toHaveLength(0);
  });
  it("keeps remote snapshots manual and binds identical resource IDs to their selected node", async () => {
    onRemoteRead = async (url) => {
      const node_id = url.pathname.split("/")[4];
      return jsonResponse(
        nodeAlertPageFixture({
          node_id,
          active_count: 2,
          items: [
            alertFixture({ origin_node_id: node_id }),
            alertFixture({
              id: "2",
              origin_node_id: node_id,
              kind: "health_catalog",
              resource_id: null,
              check: null,
              target: null,
              code: "health_catalog_unavailable",
            }),
          ],
        }),
      );
    };
    vi.useFakeTimers();
    await act(async () => {
      mount(`/alerts?target=${ALERT_PEER}`);
    });
    expect(screen.getByText(messages["alerts.remoteUnread"])).toBeTruthy();
    expect(remoteRequests).toHaveLength(0);
    expect(requests).toHaveLength(0);
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: messages["alerts.refresh"] }),
      );
    });
    expect(remoteRequests).toHaveLength(1);
    expect(screen.getByText(messages["alerts.remoteSnapshot"])).toBeTruthy();
    expect(
      screen
        .getByRole("link", { name: messages["resources.lookupOpen"] })
        .getAttribute("href"),
    ).toBe(`/resources?target=${ALERT_PEER}&address=${ALERT_RESOURCE}`);
    expect(
      screen
        .getByRole("link", { name: messages["alerts.openNodeResources"] })
        .getAttribute("href"),
    ).toBe(`/resources?target=${ALERT_PEER}`);
    await hide();
    await show();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ALERT_POLL_MS * 3);
    });
    expect(remoteRequests).toHaveLength(1);
    await act(async () => {
      fireEvent.click(screen.getByRole("link", { name: "test.other" }));
    });
    expect(remoteRequests).toHaveLength(1);
    expect(screen.queryByText(messages["alerts.remoteSnapshot"])).toBeNull();
    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: messages["alerts.refresh"] }),
      );
    });
    expect(remoteRequests).toHaveLength(2);
    expect(
      screen
        .getByRole("link", { name: messages["resources.lookupOpen"] })
        .getAttribute("href"),
    ).toBe(`/resources?target=${OTHER_PEER}&address=${ALERT_RESOURCE}`);
    const picker = screen.getByRole("combobox", {
      name: messages["control.scope"],
    });
    await act(async () => {
      picker.focus();
      fireEvent.keyDown(picker, { key: " ", keyCode: 32, which: 32 });
    });
    expect(picker.getAttribute("aria-expanded")).toBe("true");
    await act(async () => {
      fireEvent.keyDown(picker, { key: "ArrowUp", keyCode: 38, which: 38 });
    });
    await act(async () => {
      fireEvent.keyDown(picker, { key: "Enter", keyCode: 13, which: 13 });
      fireEvent.keyUp(picker, { key: "Enter", keyCode: 13, which: 13 });
    });
    expect(picker.getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByText(messages["alerts.remoteUnread"])).toBeTruthy();
    expect(screen.queryByText(messages["alerts.remoteSnapshot"])).toBeNull();
    expect(remoteRequests).toHaveLength(2);
    expect(requests).toHaveLength(0);
  });

  it("opens a current read-only address on the alert node and isolates another node's same ID", async () => {
    mount(`/alerts?target=${ALERT_PEER}`, true);
    await screen.findByText(messages["alerts.remoteUnread"]);
    await refresh();
    fireEvent.click(
      await screen.findByRole("link", {
        name: messages["resources.lookupOpen"],
      }),
    );
    await screen.findByText("192.0.2.20");
    expect(screen.getByText(messages["resources.lookupReadOnly"])).toBeTruthy();
    expect(screen.getByText(messages["resources.healthHint"])).toBeTruthy();
    const previousRead = deferred<Response>();
    const currentRead = onAddressRead;
    onAddressRead = (url) =>
      url.pathname.includes(ALERT_PEER)
        ? previousRead.promise
        : currentRead(url);
    try {
      const readAgain = screen
        .getByText(messages["users.refresh"])
        .closest("button")!;
      expect(readAgain).toBeInstanceOf(HTMLButtonElement);
      await waitFor(() => {
        expect(readAgain.disabled).toBe(false);
        expect(readAgain.classList.contains("ant-btn-loading")).toBe(false);
      });
      fireEvent.click(readAgain);
      await waitFor(() => expect(addressRequests).toHaveLength(2));
      const oldSignal = addressRequests[1].signal;
      fireEvent.click(screen.getByRole("link", { name: "test.other" }));
      await screen.findByText(messages["alerts.remoteUnread"]);
      expect(oldSignal?.aborted).toBe(true);
      expect(remoteRequests).toHaveLength(1);
      await refresh();
      fireEvent.click(
        await screen.findByRole("link", {
          name: messages["resources.lookupOpen"],
        }),
      );
      await screen.findByText("2001:db8::30");
      await act(async () =>
        previousRead.resolve(jsonResponse(addressPage("192.0.2.99"))),
      );
      expect(screen.queryByText("192.0.2.99")).toBeNull();
      expect(addressRequests.map(({ url }) => url.pathname)).toEqual([
        `/api/v1/targets/${ALERT_PEER}/proxy/addresses/${ALERT_RESOURCE}`,
        `/api/v1/targets/${ALERT_PEER}/proxy/addresses/${ALERT_RESOURCE}`,
        `/api/v1/targets/${OTHER_PEER}/proxy/addresses/${ALERT_RESOURCE}`,
      ]);
      const reads = vi.mocked(fetch).mock.calls;
      expect(reads.every(([, init]) => init?.method === "GET")).toBe(true);
      expect(
        reads.some(([input]) =>
          /\/api\/v1\/proxy\/|\/(?:policy|owner|command|health)$/.test(
            String(input),
          ),
        ),
      ).toBe(false);
      for (const key of [
        "resources.register",
        "resources.drain",
        "resources.resume",
        "resources.retire",
      ] as const)
        expect(
          screen.queryByRole("button", { name: messages[key] }),
        ).toBeNull();
      fireEvent.click(screen.getByRole("link", { name: "test.first" }));
      await screen.findByText(messages["alerts.remoteUnread"]);
      expect(screen.queryByText(messages["alerts.remoteSnapshot"])).toBeNull();
      expect(remoteRequests).toHaveLength(2);
      expect(requests).toHaveLength(0);
    } finally {
      await act(async () =>
        previousRead.resolve(jsonResponse(addressPage("192.0.2.99"))),
      );
    }
  });

  it("keeps failed history visibly stale and does not turn unsupported or absent monitoring into recovery", async () => {
    onRemoteRead = async () =>
      jsonResponse(
        nodeAlertPageFixture({
          active_count: 0,
          recent_count: 1,
          items: [
            alertFixture({
              origin_node_id: ALERT_PEER,
              status: "recovered",
              ended_at_unix_ms: "1780000002000",
            }),
          ],
        }),
      );
    mount(`/alerts?target=${ALERT_PEER}`);
    await screen.findByText(messages["alerts.remoteUnread"]);
    fireEvent.click(
      screen.getByRole("tab", { name: messages["alerts.recent"] }),
    );
    await refresh();
    await screen.findByText(messages["alerts.remoteRecovered"]);
    expect(screen.queryByText(messages["alerts.status.recovered"])).toBeNull();
    onRemoteRead = async () =>
      jsonResponse({ error: { code: "node_unavailable" } }, 502);
    await refresh();
    await screen.findByText(messages["alerts.remoteFailed"]);
    expect(screen.getByText(messages["alerts.retained"])).toBeTruthy();
    expect(screen.getByText(messages["alerts.previousRecord"])).toBeTruthy();
    expect(screen.getByText(messages["alerts.stale"])).toBeTruthy();
    expect(screen.queryByText(messages["alerts.remoteRecovered"])).toBeNull();
    onRemoteRead = async () =>
      jsonResponse({ error: { code: "operations_alerts_unsupported" } }, 502);
    await refresh();
    await screen.findByText(messages["fleet.unsupported"]);
    expect(screen.getByTestId("session-phase").textContent).toBe(
      "authenticated",
    );
    onRemoteRead = async () =>
      jsonResponse(
        nodeAlertPageFixture({
          coverage: {
            local_egress: false,
            local_traffic: false,
            local_proxy_expected: false,
            local_management_https: false,
            local_node_tls: false,
            local_proxy_tls: false,
          },
          observed_at_unix_ms: null,
          age_millis: null,
          active_count: 0,
          items: [],
        }),
      );
    await refresh();
    await screen.findByText(messages["alerts.remoteUnknown"]);
    expect(screen.queryByText(messages["alerts.emptyRecent"])).toBeNull();
    expect(requests).toHaveLength(0);
  });

  it("requires an explicit first-page reload after a remote snapshot cursor changes", async () => {
    onRemoteRead = async (url) =>
      url.searchParams.has("after")
        ? jsonResponse({ error: { code: "alerts_changed" } }, 409)
        : jsonResponse(
            nodeAlertPageFixture({
              active_count: 11,
              items: Array.from({ length: 10 }, (_, index) =>
                alertFixture({
                  id: String(index + 1),
                  origin_node_id: ALERT_PEER,
                }),
              ),
              next_cursor: `${ALERT_BOOT}:1:node-active:10`,
            }),
          );
    mount(`/alerts?target=${ALERT_PEER}`);
    await screen.findByText(messages["alerts.remoteUnread"]);
    await refresh();
    await screen.findAllByText(
      messages["alerts.code.egress_connection_refused"],
    );
    fireEvent.click(
      screen.getByRole("button", { name: messages["users.next"] }),
    );
    await screen.findByText(messages["alerts.changed"]);
    expect(screen.getAllByText(messages["alerts.previousRecord"])).toHaveLength(
      10,
    );
    const previous = remoteRequests.length;
    await refresh();
    await waitFor(() =>
      expect(screen.queryByText(messages["alerts.changed"])).toBeNull(),
    );
    expect(remoteRequests).toHaveLength(previous + 1);
    expect(remoteRequests.at(-1)?.url.searchParams.has("after")).toBe(false);
  });

  it("discards late responses after scope and session changes without reading the replacement node", async () => {
    const first = deferred<Response>();
    onRemoteRead = () => first.promise;
    mount(`/alerts?target=${ALERT_PEER}`);
    await screen.findByText(messages["alerts.remoteUnread"]);
    await refresh();
    await waitFor(() => expect(remoteRequests).toHaveLength(1));
    const firstSignal = remoteRequests[0].signal;
    fireEvent.click(screen.getByRole("link", { name: "test.other" }));
    await screen.findByText(messages["alerts.remoteUnread"]);
    expect(firstSignal?.aborted).toBe(true);
    expect(remoteRequests).toHaveLength(1);
    await act(async () => first.resolve(jsonResponse(nodeAlertPageFixture())));
    expect(screen.queryByText(messages["alerts.remoteSnapshot"])).toBeNull();
    const second = deferred<Response>();
    onRemoteRead = () => second.promise;
    await refresh();
    await waitFor(() => expect(remoteRequests).toHaveLength(2));
    const secondSignal = remoteRequests[1].signal;
    authenticated = false;
    fireEvent.click(screen.getByRole("button", { name: "test.session" }));
    await waitFor(() =>
      expect(screen.getByTestId("session-phase").textContent).toBe("anonymous"),
    );
    expect(secondSignal?.aborted).toBe(true);
    await act(async () => second.resolve(jsonResponse(nodeAlertPageFixture())));
    expect(screen.queryByText(messages["alerts.remoteSnapshot"])).toBeNull();
    expect(requests).toHaveLength(0);
  });
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("alert observation and lifecycle display", () => {
  it("shows opt-in background observations locally and routes each preserved source without contacting it", async () => {
    const page = alertPageFixture({
      active_count: 2,
      coverage: { ...alertPageFixture().coverage, remote_observation: true },
      items: [
        alertFixture({ origin_node_id: ALERT_PEER }),
        alertFixture({
          id: "2",
          kind: "remote_observation",
          origin_node_id: OTHER_PEER,
          resource_id: null,
          check: null,
          target: null,
          code: "remote_observation_unavailable",
          evidence_fresh: false,
        }),
      ],
    });
    onRead = async () => jsonResponse(page);
    mount();
    await screen.findByText(
      messages["alerts.code.remote_observation_unavailable"],
    );
    expect(screen.getByText(messages["alerts.backgroundHint"])).toBeTruthy();
    expect(
      screen.getAllByText(messages["alerts.foreignObservation"]),
    ).toHaveLength(2);
    expect(
      screen
        .getByRole("link", { name: messages["resources.lookupOpen"] })
        .getAttribute("href"),
    ).toBe(`/resources?target=${ALERT_PEER}&address=${ALERT_RESOURCE}`);
    const failedRow = screen
      .getByText(messages["alerts.code.remote_observation_unavailable"])
      .closest("tr")!;
    expect(
      within(failedRow)
        .getByRole("link", { name: messages["alerts.openNode"] })
        .getAttribute("href"),
    ).toBe("/nodes");
    expect(within(failedRow).getAllByText(OTHER_PEER)).toHaveLength(2);
    expect(remoteRequests).toHaveLength(0);
    expect(nodeReads).toBe(1);
    await refresh();
    await waitFor(() => expect(requests).toHaveLength(2));
    expect(nodeReads).toBe(1);
    expect(remoteRequests).toHaveLength(0);
  });
  it("explains disabled background collection instead of treating an unread empty source as healthy", async () => {
    onRead = async () =>
      jsonResponse(
        alertPageFixture({
          active_count: 0,
          items: [],
          observed_at_unix_ms: null,
          age_millis: null,
        }),
      );
    mount();
    await screen.findByText(messages["alerts.backgroundDisabledHint"]);
    expect(screen.queryByText(messages["alerts.backgroundHint"])).toBeNull();
    expect(screen.queryByText(messages["alerts.status.recovered"])).toBeNull();
    const activeCount = screen
      .getByText(messages["alerts.activeCount"])
      .closest(".ant-descriptions-item")!
      .querySelector(".ant-descriptions-item-content")!.textContent;
    expect(activeCount).toBe("—");
    expect(screen.queryByText(messages["alerts.emptyActive"])).toBeNull();
    expect(remoteRequests).toHaveLength(0);
  });
  it("links fixed forwarding faults to Nodes while keeping policy and unknown reasons separate", async () => {
    const codes = [
      "proxy_not_running",
      "proxy_drain_failed",
      "proxy_drain_interrupted",
      "policy_not_applied",
      "policy_publication_unavailable",
      "future_fixed_code",
    ] as const;
    onRead = async () =>
      jsonResponse(
        alertPageFixture({
          active_count: codes.length,
          items: codes.map((code, index) =>
            alertFixture({
              id: String(index + 1),
              kind: "policy",
              resource_id: null,
              check: null,
              target: null,
              code,
            }),
          ),
        }),
      );
    mount();
    await screen.findByText(messages["alerts.code.proxy_drain_failed"]);
    for (const [index, code] of codes.entries()) {
      const reason =
        code === "future_fixed_code"
          ? messages["alerts.code.unknown"]
          : messages[`alerts.code.${code}`];
      const row = screen.getByText(reason).closest("tr");
      expect(row).not.toBeNull();
      expect(within(row!).getByRole("link").getAttribute("href")).toBe(
        index < 3 ? "/nodes" : "/users",
      );
    }
    expect(screen.queryByText("future_fixed_code")).toBeNull();
    expect(requests.every((request) => request.method === "GET")).toBe(true);
    expect(remoteRequests).toHaveLength(0);
  });
  it("shows node and proxy TLS metadata reasons without implying remote connectivity or linking to traffic", async () => {
    const suffixes = [
      "unavailable",
      "expiring",
      "expired",
      "not_yet_valid",
      "metadata_unavailable",
    ] as const;
    const items = (["node_tls", "proxy_tls"] as const).flatMap((kind, group) =>
      suffixes.map((suffix, index) =>
        alertFixture({
          id: String(group * suffixes.length + index + 1),
          kind,
          resource_id: kind === "proxy_tls" ? ALERT_RESOURCE : null,
          check: null,
          target: null,
          code: `${kind}_identity_${suffix}`,
        }),
      ),
    );
    const page = alertPageFixture({
      active_count: items.length,
      coverage: {
        ...alertPageFixture().coverage,
        local_management_https: true,
        local_node_tls: true,
        local_proxy_tls: true,
      },
      items,
    });
    onRead = async () => jsonResponse(page);
    mount();
    await screen.findByText(
      messages["alerts.code.node_tls_identity_metadata_unavailable"],
    );
    for (const item of items)
      expect(
        screen.getByText(
          messages[`alerts.code.${item.code}` as keyof typeof messages],
        ),
      ).toBeTruthy();
    expect(
      screen.getByText(
        messages["alerts.code.proxy_tls_identity_metadata_unavailable"],
      ),
    ).toBeTruthy();
    for (const label of [
      "alerts.localManagementHttps",
      "alerts.localNodeTls",
      "alerts.localProxyTls",
      "alerts.managementHttpsHint",
    ] as const)
      expect(screen.getByText(messages[label])).toBeTruthy();
    const links = screen.getAllByRole("link", {
      name: messages["alerts.openNode"],
    });
    expect(links).toHaveLength(items.length);
    expect(links.every((link) => link.getAttribute("href") === "/nodes")).toBe(
      true,
    );
    expect(
      screen.queryByRole("link", { name: messages["alerts.openTraffic"] }),
    ).toBeNull();
    expect(remoteRequests).toHaveLength(0);
    expect(requests.every((request) => request.method === "GET")).toBe(true);
    page.items[2].evidence_fresh = false;
    await refresh();
    await screen.findByText(
      messages["alerts.previousObservation"].replace(
        "{reason}",
        messages["alerts.code.node_tls_identity_expired"],
      ),
    );
    expect(
      screen.queryByText(messages["alerts.code.node_tls_identity_expired"]),
    ).toBeNull();
  });

  it("shows fixed HTTPS reasons and links only to the local Nodes page", async () => {
    const codes = [
      "https_identity_unavailable",
      "https_identity_expiring",
      "https_identity_expired",
      "https_identity_not_yet_valid",
      "https_identity_metadata_unavailable",
      "acme_attempt_unavailable",
      "acme_review_required",
      "acme_worker_stopped",
    ] as const;
    const page = alertPageFixture({
      active_count: codes.length,
      coverage: {
        ...alertPageFixture().coverage,
        local_proxy_expected: false,
        local_management_https: true,
      },
      items: codes.map((code, index) =>
        alertFixture({
          id: String(index + 1),
          kind: "management_https",
          resource_id: null,
          check: null,
          target: null,
          code,
        }),
      ),
    });
    onRead = async (url) =>
      jsonResponse(
        url.searchParams.get("state") === "recent"
          ? {
              ...page,
              active_count: 0,
              recent_count: 1,
              items: [
                {
                  ...page.items[0],
                  status: "recovered",
                  evidence_fresh: true,
                  ended_at_unix_ms: "1780000002000",
                },
              ],
            }
          : page,
      );
    mount();
    await screen.findByText(messages["alerts.code.https_identity_unavailable"]);
    for (const code of codes)
      expect(screen.getByText(messages[`alerts.code.${code}`])).toBeTruthy();
    const links = screen.getAllByRole("link", {
      name: messages["alerts.openNode"],
    });
    expect(links).toHaveLength(codes.length);
    expect(links.every((link) => link.getAttribute("href") === "/nodes")).toBe(
      true,
    );
    expect(
      screen.queryByRole("link", { name: messages["alerts.openTraffic"] }),
    ).toBeNull();
    expect(
      screen.getByText(messages["alerts.localManagementHttps"]),
    ).toBeTruthy();
    expect(
      screen.getByText(messages["alerts.managementHttpsHint"]),
    ).toBeTruthy();
    expect(requests.every((request) => request.method === "GET")).toBe(true);
    page.items[0].evidence_fresh = false;
    await refresh();
    await screen.findByText(
      messages["alerts.previousObservation"].replace(
        "{reason}",
        messages["alerts.code.https_identity_unavailable"],
      ),
    );
    expect(
      screen.queryByText(messages["alerts.code.https_identity_unavailable"]),
    ).toBeNull();
    expect(screen.getByText(messages["alerts.stale"])).toBeTruthy();
    expect(screen.getAllByText(messages["alerts.status.active"])).toHaveLength(
      codes.length,
    );
    fireEvent.click(
      screen.getByRole("tab", { name: messages["alerts.recent"] }),
    );
    await screen.findByText(
      messages["alerts.previousObservation"].replace(
        "{reason}",
        messages["alerts.code.https_identity_unavailable"],
      ),
    );
    expect(screen.getByText(messages["alerts.status.recovered"])).toBeTruthy();
    expect(
      screen.queryByText(messages["alerts.code.https_identity_unavailable"]),
    ).toBeNull();
  });

  it("keeps stale failures active and separates recovered and unmonitored history", async () => {
    onRead = async (url) =>
      url.searchParams.get("state") === "recent"
        ? jsonResponse(
            alertPageFixture({
              active_count: 0,
              recent_count: 2,
              dropped: "18446744073709551615",
              items: [
                alertFixture({
                  status: "recovered",
                  ended_at_unix_ms: "1780000002000",
                }),
                alertFixture({
                  id: "2",
                  status: "unmonitored",
                  evidence_fresh: false,
                  code: "future_fixed_code",
                  ended_at_unix_ms: "1780000003000",
                }),
              ],
            }),
          )
        : jsonResponse(
            alertPageFixture({
              items: [alertFixture({ evidence_fresh: false })],
            }),
          );
    mount();
    await screen.findByText(messages["alerts.code.egress_connection_refused"]);
    expect(screen.getByText(messages["alerts.stale"])).toBeTruthy();
    expect(screen.getByText(messages["alerts.status.active"])).toBeTruthy();
    expect(screen.queryByText(messages["alerts.status.recovered"])).toBeNull();
    expect(
      screen
        .getByRole("link", { name: messages["resources.lookupOpen"] })
        .getAttribute("href"),
    ).toBe(`/resources?address=${ALERT_RESOURCE}`);
    fireEvent.click(
      screen.getByRole("tab", { name: messages["alerts.recent"] }),
    );
    await screen.findByText(messages["alerts.status.recovered"]);
    expect(
      screen.getByText(messages["alerts.status.unmonitored"]),
    ).toBeTruthy();
    expect(screen.getByText(messages["alerts.code.unknown"])).toBeTruthy();
    expect(screen.queryByText("future_fixed_code")).toBeNull();
    expect(screen.getByText(/18,446,744,073,709,551,615/)).toBeTruthy();
    expect(requests.every((request) => request.method === "GET")).toBe(true);
  });

  it("retains a failed read without claiming a current zero problem count", async () => {
    mount();
    await screen.findByText(messages["alerts.code.egress_connection_refused"]);
    onRead = async () =>
      jsonResponse({ error: { code: "alerts_unavailable" } }, 503);
    await refresh();
    await screen.findByText(messages["alerts.unavailable"]);
    expect(screen.getByText(messages["alerts.retained"])).toBeTruthy();
    expect(
      screen.getByText(messages["alerts.code.egress_connection_refused"]),
    ).toBeTruthy();
    expect(screen.queryByText(messages["alerts.emptyActive"])).toBeNull();
    onRead = async () =>
      jsonResponse(
        alertPageFixture({
          boot_id: "AwMDAwMDAwMDAwMDAwMDAw",
          active_count: 0,
          items: [],
        }),
      );
    await refresh();
    await screen.findByText(messages["alerts.emptyActive"]);
    await screen.findByText(messages["alerts.restarted"]);
    expect(screen.queryByText(messages["alerts.retained"])).toBeNull();
  });

  it("keeps the prior page after a cursor conflict and rereads from the beginning", async () => {
    onRead = async (url) =>
      url.searchParams.has("after")
        ? jsonResponse({ error: { code: "alerts_changed" } }, 409)
        : jsonResponse(
            alertPageFixture({
              active_count: 11,
              items: Array.from({ length: 10 }, (_, index) =>
                alertFixture({ id: String(index + 1) }),
              ),
              next_cursor: "opaque-cursor",
            }),
          );
    mount();
    await screen.findAllByText(
      messages["alerts.code.egress_connection_refused"],
    );
    fireEvent.click(
      screen.getByRole("button", { name: messages["users.next"] }),
    );
    await screen.findByText(messages["alerts.changed"]);
    expect(
      screen.getAllByText(messages["alerts.code.egress_connection_refused"]),
    ).toHaveLength(10);
    expect(requests.at(-1)?.query).toContain("after=opaque-cursor");
    const beforeReload = requests.length;
    await refresh();
    await waitFor(() =>
      expect(screen.queryByText(messages["alerts.changed"])).toBeNull(),
    );
    expect(requests).toHaveLength(beforeReload + 1);
    expect(requests.at(-1)?.query).not.toContain("after=");
  });

  it("polls one read at a time and cancels when hidden, unmounted or the session changes", async () => {
    vi.useFakeTimers();
    let mounted!: ReturnType<typeof mount>;
    await act(async () => {
      mounted = mount();
    });
    expect(
      screen.getByText(messages["alerts.code.egress_connection_refused"]),
    ).toBeTruthy();
    const late = deferred<Response>();
    onRead = () => late.promise;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ALERT_POLL_MS);
    });
    expect(requests).toHaveLength(2);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ALERT_POLL_MS);
    });
    expect(requests).toHaveLength(2);
    const hiddenSignal = requests[1].signal;
    await hide();
    expect(hiddenSignal?.aborted).toBe(true);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ALERT_POLL_MS * 3);
    });
    expect(requests).toHaveLength(2);
    onRead = async () => jsonResponse(alertPageFixture());
    await show();
    expect(requests).toHaveLength(3);
    await act(async () =>
      late.resolve(
        jsonResponse(alertPageFixture({ active_count: 0, items: [] })),
      ),
    );
    expect(screen.queryByText(messages["alerts.emptyActive"])).toBeNull();
    const sessionLate = deferred<Response>();
    onRead = () => sessionLate.promise;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ALERT_POLL_MS);
    });
    expect(requests).toHaveLength(4);
    const sessionSignal = requests[3].signal;
    authenticated = false;
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "test.session" }));
    });
    expect(sessionSignal?.aborted).toBe(true);
    expect(screen.getByTestId("session-phase").textContent).toBe("anonymous");
    await act(async () =>
      sessionLate.resolve(jsonResponse(alertPageFixture())),
    );
    expect(
      screen.queryByText(messages["alerts.code.egress_connection_refused"]),
    ).toBeNull();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ALERT_POLL_MS * 2);
    });
    expect(requests).toHaveLength(4);
    mounted.unmount();
  });

  it("cancels an in-flight read when leaving the page", async () => {
    const late = deferred<Response>();
    onRead = () => late.promise;
    const mounted = mount();
    await waitFor(() => expect(requests).toHaveLength(1));
    const signal = requests[0].signal;
    mounted.unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () => late.resolve(jsonResponse(alertPageFixture())));
    expect(requests).toHaveLength(1);
  });

  it("waits for a hidden page to become visible before its first read", async () => {
    visibility = "hidden";
    mount();
    await screen.findByText(messages["alerts.paused"]);
    expect(requests).toHaveLength(0);
    await show();
    await screen.findByText(messages["alerts.code.egress_connection_refused"]);
    expect(requests).toHaveLength(1);
  });
});
