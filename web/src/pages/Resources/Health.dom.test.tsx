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
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import type { HealthCheck, HealthSnapshot } from "../../api/health";
import { ManagementProvider, useManagement } from "../../auth/context";
import ManagementGate from "../../components/ManagementGate";
import messages from "../../locales/en-US";
import { useScopeNavigation } from "../../routing/ScopeNavigation";
import { scopeHref, scopeLocation } from "../../routing/scope";
import Health from "./Health";
import ResourcesPage from "./index";

// Only Umi's Router re-exports and caption formatting are fixture boundaries.
// Health, Resources, Ant Design, session cancellation and API validation stay real.
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
      intl: { locale: "en-US" },
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

const LOCAL = "A".repeat(22);
const PEER = "AQEBAQEBAQEBAQEBAQEBAQ";
const OTHER = "AgICAgICAgICAgICAgICAg";
const ADDRESS = "AwMDAwMDAwMDAwMDAwMDAw";
const BOOT = "BAQEBAQEBAQEBAQEBAQEBA";
const NEW_BOOT = "BQUFBQUFBQUFBQUFBQUFBQ";
const TCP_TARGET = "198.51.100.10:443";
const EXPIRED_TARGET = "198.51.100.11:443";
const localIp = "192.0.2.10";
const peerIp = "192.0.2.20";
const otherIp = "192.0.2.30";

function observed(
  kind: HealthCheck["kind"],
  target: string | null,
): HealthCheck {
  return {
    kind,
    target,
    outcome: "success",
    sequence: "7",
    observed_at_unix_ms: Date.now() - 10,
    age_millis: 10,
    latency_millis: 0,
  };
}
function loaded(ip: string): HealthSnapshot {
  return {
    boot_id: BOOT,
    sequence: "7",
    // A health catalog can precede an unrelated global policy revision.
    catalog_revision: "2",
    catalog_loaded: true,
    catalog_error: null,
    catalog_observed_at_unix_ms: Date.now() - 10,
    catalog_age_millis: 10,
    in_flight: 0,
    entries: [
      {
        address_id: ADDRESS,
        address_revision: "2",
        ip,
        checks: [
          observed("bind", null),
          observed("tcp", TCP_TARGET),
          {
            ...observed("tcp", EXPIRED_TARGET),
            outcome: "unknown",
            sequence: "6",
            observed_at_unix_ms: Date.now() - 180_000,
            age_millis: 180_000,
          },
        ],
      },
    ],
    next_cursor: null,
  };
}
const unloaded = (): HealthSnapshot => ({
  boot_id: NEW_BOOT,
  sequence: "0",
  catalog_revision: null,
  catalog_loaded: false,
  catalog_error: null,
  catalog_observed_at_unix_ms: null,
  catalog_age_millis: null,
  in_flight: 0,
  entries: [],
  next_cursor: null,
});
const policy = () => ({
  saved_revision: "9",
  applied_revision: null,
  durable_applied_revision: null,
  proxy_running: false,
  user_count: 0,
  credential_count: 0,
});
const target = (id: string) => ({
  node_id: id,
  name: id === PEER ? "Child one" : "Child two",
  origin: id === PEER ? "https://one.example:9443" : "https://two.example:9443",
  server_ip: null,
  active: true,
  retired: false,
  revision: "1",
  observed_epoch: null,
  observed_command: null,
  observed_policy_revision: null,
  rollback_detected: false,
});
let authenticated: boolean;
let requests: {
  path: string;
  query: string;
  method: string;
  signal: AbortSignal | null;
}[];
let onRead: (path: string) => Promise<Response> | undefined;
let active: number;
let maximumActive: number;

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
async function response(path: string): Promise<Response> {
  const intercepted = onRead(path);
  if (intercepted) return intercepted;
  if (path === "/api/v1/auth/session")
    return authenticated
      ? jsonResponse({
          ...sessionFixture(),
          expires_at: Math.floor(Date.now() / 1000) + 3600,
        })
      : jsonResponse({ error: { code: "authentication_required" } }, 403);
  if (path === "/api/v1/node")
    return jsonResponse({
      node_id: LOCAL,
      name: "Local fixture",
      version: "test",
      os: "linux",
      arch: "x86_64",
      capabilities: ["local_administration"],
    });
  if (path === "/api/v1/proxy/policy") return jsonResponse(policy());
  if (path === "/api/v1/proxy/owner")
    return jsonResponse({
      controller_node_id: null,
      epoch: "1",
      last_terminal_command: "0",
    });
  if (path === "/api/v1/proxy/health") return jsonResponse(loaded(localIp));
  if (path === "/api/v1/proxy/prefixes")
    return jsonResponse({ revision: "9", items: [], next_cursor: null });
  if (path === "/api/v1/targets")
    return jsonResponse({
      items: [target(PEER), target(OTHER)],
      next_cursor: null,
      controller_available: true,
    });
  for (const id of [PEER, OTHER]) {
    if (path === `/api/v1/targets/${id}`) return jsonResponse(target(id));
    if (path === `/api/v1/targets/${id}/command`) return jsonResponse(null);
    if (path === `/api/v1/targets/${id}/policy`)
      return jsonResponse({
        ...policy(),
        controller_node_id: LOCAL,
        controller_epoch: "2",
        last_terminal_command: "0",
      });
    if (path === `/api/v1/targets/${id}/proxy/health`)
      return jsonResponse(loaded(id === PEER ? peerIp : otherIp));
    if (path === `/api/v1/targets/${id}/proxy/prefixes`)
      return jsonResponse({ revision: "9", items: [], next_cursor: null });
  }
  throw new Error("Unexpected fixture read");
}

beforeEach(() => {
  authenticated = true;
  requests = [];
  active = 0;
  maximumActive = 0;
  onRead = () => undefined;
  vi.stubGlobal("__VPROXY_DEMO__", false);
  // Platform shims only: no synthetic geometry is used as layout evidence.
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
      const method = init?.method ?? "GET";
      requests.push({
        path: url.pathname,
        query: url.search,
        method,
        signal: init?.signal ?? null,
      });
      if (method !== "GET") throw new Error("Unexpected fixture mutation");
      active++;
      maximumActive = Math.max(maximumActive, active);
      try {
        return await response(url.pathname);
      } finally {
        active--;
      }
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// Stable callbacks preserve the production component's effect dependencies.
const observeTarget = () => {};
const observeBusy = () => {};
function Harness({ wholePage }: { wholePage: boolean }) {
  const location = useLocation();
  const selectScope = useScopeNavigation();
  const peer = scopeLocation(location);
  const { controller, state } = useManagement();
  return (
    <>
      <output data-testid="location">
        {location.pathname + location.search}
      </output>
      <output data-testid="session-phase">{state.phase}</output>
      <button onClick={() => void controller.check()}>test.session</button>
      <button onClick={() => selectScope(scopeHref("/resources", OTHER))}>
        test.other
      </button>
      {wholePage ? (
        <ResourcesPage />
      ) : (
        <ManagementGate>
          <Health
            key={peer ?? "local"}
            peer={peer}
            onTarget={observeTarget}
            onBusy={observeBusy}
          />
        </ManagementGate>
      )}
    </>
  );
}
function mount(peer: string | null = null, wholePage = false) {
  return render(
    <ConfigProvider theme={{ token: { motion: false } }}>
      <MemoryRouter
        initialEntries={[peer ? `/resources?target=${peer}` : "/resources"]}
      >
        <ManagementProvider>
          <Harness wholePage={wholePage} />
        </ManagementProvider>
      </MemoryRouter>
    </ConfigProvider>,
  );
}
const mutations = () => requests.filter(({ method }) => method !== "GET");
const healthReads = (peer: string | null = null) =>
  requests.filter(
    ({ path }) =>
      path ===
      (peer ? `/api/v1/targets/${peer}/proxy/health` : "/api/v1/proxy/health"),
  );
function readLatest() {
  const button = screen
    .getByText(messages["resources.readLatestSnapshot"])
    .closest("button");
  expect(button).not.toBeNull();
  expect((button as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(button!);
}
function rowFor(caption: string) {
  const row = screen.getByText(caption).closest("tr");
  expect(row).not.toBeNull();
  return row!;
}
function guidance(row: HTMLElement) {
  const button = within(row)
    .getByText(messages["resources.guidanceTitle"])
    .closest<HTMLElement>('[role="button"]');
  expect(button).not.toBeNull();
  button!.focus();
  fireEvent.keyDown(button!, { key: "Enter", code: "Enter", keyCode: 13 });
  expect(button!.getAttribute("aria-expanded")).toBe("true");
  return button!;
}
async function openHealthTab(peer: string) {
  await waitFor(() =>
    expect(
      requests.some(
        ({ path }) => path === `/api/v1/targets/${peer}/proxy/prefixes`,
      ),
    ).toBe(true),
  );
  const tab = screen.getByRole("tab", {
    name: messages["resources.observations"],
  });
  await waitFor(() =>
    expect(tab.getAttribute("aria-disabled")).not.toBe("true"),
  );
  fireEvent.click(tab);
}

describe("read-only scoped health guidance", () => {
  it("distinguishes bind, one TCP target and expired Unknown without probing when guidance opens", async () => {
    mount();
    await screen.findByText(EXPIRED_TARGET);
    const healthRow = rowFor(EXPIRED_TARGET);
    expect(healthRow.closest(".management-data-table")).not.toBeNull();
    expect(healthRow.querySelector("td")?.getAttribute("data-label")).toBe(
      messages["resources.ip"],
    );
    expect(
      screen
        .getAllByRole("link", { name: ADDRESS })
        .every(
          (link) =>
            link.getAttribute("href") === `/resources?address=${ADDRESS}`,
        ),
    ).toBe(true);
    expect(requests.map(({ path, query }) => path + query)).toEqual([
      "/api/v1/auth/session",
      "/api/v1/proxy/policy",
      "/api/v1/proxy/owner",
      "/api/v1/proxy/health?limit=10",
    ]);
    const originalRequests = requests.slice();
    const pageSize = screen.getByRole("combobox", {
      name: messages["resources.pageSize"],
    });
    expect(pageSize.tabIndex).toBeGreaterThanOrEqual(0);
    pageSize.focus();
    expect(document.activeElement).toBe(pageSize);
    const bind = rowFor(messages["resources.bind"]);
    const tcp = rowFor(TCP_TARGET);
    const expired = rowFor(EXPIRED_TARGET);
    const bindButton = guidance(bind);
    expect(
      within(bind).getByText(messages["resources.guidance.bindSuccess"]),
    ).toBeTruthy();
    guidance(tcp);
    expect(
      within(tcp).getByText(messages["resources.guidance.tcpSuccess"]),
    ).toBeTruthy();
    guidance(expired);
    expect(
      within(expired).getByText(messages["resources.guidance.unknown"]),
    ).toBeTruthy();
    expect(within(expired).getByText("180000")).toBeTruthy();
    bindButton.focus();
    fireEvent.keyDown(bindButton, { key: "Enter", code: "Enter", keyCode: 13 });
    expect(bindButton.getAttribute("aria-expanded")).toBe("false");
    await act(async () => {});
    expect(requests).toEqual(originalRequests);
    expect(mutations()).toHaveLength(0);
    const next = deferred<Response>();
    onRead = (path) =>
      path === "/api/v1/proxy/health" ? next.promise : undefined;
    readLatest();
    await waitFor(() => expect(healthReads()).toHaveLength(2));
    expect(
      screen.queryByText(messages["resources.guidance.bindSuccess"]),
    ).toBeNull();
    expect(
      screen.queryByText(messages["resources.guidance.tcpSuccess"]),
    ).toBeNull();
    expect(
      screen.queryByText(messages["resources.guidance.unknown"]),
    ).toBeNull();
    await act(async () => next.resolve(jsonResponse(unloaded())));
    await screen.findByText(messages["resources.catalogNotLoaded"]);
    expect(screen.getByText(messages["resources.restartHint"])).toBeTruthy();
    expect(screen.getByText(NEW_BOOT)).toBeTruthy();
    expect(screen.queryByText(messages["resources.guidanceTitle"])).toBeNull();
    expect(screen.queryByText(TCP_TARGET)).toBeNull();
    expect(
      requests
        .slice(originalRequests.length)
        .map(({ path, query }) => path + query),
    ).toEqual([
      "/api/v1/proxy/policy",
      "/api/v1/proxy/owner",
      "/api/v1/proxy/health?limit=10",
    ]);
    expect(mutations()).toHaveLength(0);
  });

  it("keeps the remote read chain sequential, accepts its older catalog and never falls back locally after denial", async () => {
    mount(PEER);
    await screen.findByText(EXPIRED_TARGET);
    expect(
      screen
        .getAllByRole("link", { name: ADDRESS })
        .every(
          (link) =>
            link.getAttribute("href") ===
            `/resources?target=${PEER}&address=${ADDRESS}`,
        ),
    ).toBe(true);
    const expected = [
      "/api/v1/node",
      `/api/v1/targets/${PEER}`,
      `/api/v1/targets/${PEER}/command`,
      `/api/v1/targets/${PEER}/policy`,
      `/api/v1/targets/${PEER}/proxy/health?limit=10`,
    ];
    expect(requests.map(({ path, query }) => path + query)).toEqual([
      "/api/v1/auth/session",
      ...expected,
    ]);
    expect(maximumActive).toBe(1);
    const tcp = rowFor(TCP_TARGET);
    guidance(tcp);
    expect(
      within(tcp).getByText(messages["resources.guidance.tcpSuccess"]),
    ).toBeTruthy();
    expect(healthReads(PEER)).toHaveLength(1);
    onRead = (path) =>
      path === `/api/v1/targets/${PEER}/proxy/health`
        ? Promise.resolve(
            jsonResponse({ error: { code: "node_control_denied" } }, 403),
          )
        : undefined;
    readLatest();
    await waitFor(() => expect(screen.queryByText(TCP_TARGET)).toBeNull());
    expect(screen.getByTestId("session-phase").textContent).toBe(
      "authenticated",
    );
    expect(
      screen.queryByText(messages["resources.guidance.tcpSuccess"]),
    ).toBeNull();
    expect(requests.slice(6).map(({ path, query }) => path + query)).toEqual(
      expected,
    );
    expect(healthReads()).toHaveLength(0);
    expect(mutations()).toHaveLength(0);
  });

  it("uses the real Resources Router scope boundary to discard an abort-ignoring old peer observation", async () => {
    const late = deferred<Response>();
    onRead = (path) =>
      path === `/api/v1/targets/${PEER}/proxy/health`
        ? late.promise
        : undefined;
    mount(PEER, true);
    await openHealthTab(PEER);
    await waitFor(() => expect(healthReads(PEER)).toHaveLength(1));
    const oldSignal = healthReads(PEER)[0].signal;
    // An external navigation can change scope while the in-page picker is
    // disabled; use the production adapter, Router and Resources keyed boundary.
    fireEvent.click(screen.getByRole("button", { name: "test.other" }));
    await openHealthTab(OTHER);
    await screen.findAllByText(otherIp);
    expect(oldSignal?.aborted).toBe(true);
    const tcp = rowFor(TCP_TARGET);
    guidance(tcp);
    await act(async () => late.resolve(jsonResponse(loaded(peerIp))));
    expect(screen.getByTestId("location").textContent).toBe(
      `/resources?target=${OTHER}`,
    );
    expect(screen.queryByText(peerIp)).toBeNull();
    expect(screen.getAllByText(otherIp)).toHaveLength(3);
    expect(
      within(tcp).getByText(messages["resources.guidance.tcpSuccess"]),
    ).toBeTruthy();
    expect(healthReads(PEER)).toHaveLength(1);
    expect(healthReads(OTHER)).toHaveLength(1);
    expect(healthReads()).toHaveLength(0);
    expect(mutations()).toHaveLength(0);
  });

  it("removes old guidance on refresh and cannot restore it after the real session gate closes", async () => {
    mount(PEER);
    await screen.findByText(TCP_TARGET);
    guidance(rowFor(TCP_TARGET));
    const late = deferred<Response>();
    onRead = (path) =>
      path === `/api/v1/targets/${PEER}/proxy/health`
        ? late.promise
        : undefined;
    readLatest();
    await waitFor(() => expect(healthReads(PEER)).toHaveLength(2));
    const signal = healthReads(PEER)[1].signal;
    expect(
      screen.queryByText(messages["resources.guidance.tcpSuccess"]),
    ).toBeNull();
    authenticated = false;
    fireEvent.click(screen.getByRole("button", { name: "test.session" }));
    await waitFor(() =>
      expect(screen.getByTestId("session-phase").textContent).toBe("anonymous"),
    );
    expect(signal?.aborted).toBe(true);
    await act(async () => late.resolve(jsonResponse(loaded(peerIp))));
    expect(screen.queryByText(TCP_TARGET)).toBeNull();
    expect(screen.queryByText(messages["resources.guidanceTitle"])).toBeNull();
    expect(
      screen.queryByText(messages["resources.guidance.tcpSuccess"]),
    ).toBeNull();
    expect(healthReads(PEER)).toHaveLength(2);
    expect(healthReads()).toHaveLength(0);
    expect(mutations()).toHaveLength(0);
  });
});
