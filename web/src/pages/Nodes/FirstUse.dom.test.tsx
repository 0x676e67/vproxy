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
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import type { PolicyStatus } from "../../api/proxy";
import type { Owner } from "../../api/targets";
import { ManagementProvider, useManagement } from "../../auth/context";
import messages from "../../locales/en-US";
import FirstUse from "./FirstUse";
import LiveNodes from "./LiveNodes";

// Keep the real Router, Ant Design, page, session and client parsers. Umi's
// Router re-export and the message hook are boundaries, using the real captions.
vi.mock("@umijs/max", async () => ({
  Link: (await import("react-router-dom")).Link,
}));
vi.mock("../../hooks/useMessages", async () => {
  const captions = (await import("../../locales/en-US")).default;
  return {
    useMessages: () => ({
      intl: { locale: "en-US" },
      t: (id: keyof typeof captions) => captions[id],
    }),
  };
});

const LOCAL = "A".repeat(22);
const CHILD = "AQEBAQEBAQEBAQEBAQEBAQ";
const policy = (): PolicyStatus => ({
  saved_revision: "9",
  applied_revision: "9",
  durable_applied_revision: "9",
  proxy_running: true,
  user_count: 400,
  credential_count: 800,
});
const owner = (): Owner => ({
  controller_node_id: null,
  epoch: "1",
  last_terminal_command: "0",
});
let currentPolicy: PolicyStatus;
let currentOwner: Owner;
let authenticated: boolean;
let requests: {
  path: string;
  method: string;
  signal: AbortSignal | null;
}[];
let onRead: (path: string) => Promise<Response> | undefined;

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}

beforeEach(() => {
  currentPolicy = policy();
  currentOwner = owner();
  authenticated = true;
  requests = [];
  onRead = () => undefined;
  vi.stubGlobal("__VPROXY_DEMO__", false);
  // jsdom has no layout. These platform shims do not replace Collapse, Link,
  // Modal, the management gate or any event/state lifecycle under test.
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
      const path = new URL(String(input), "https://manager.example").pathname;
      const method = init?.method ?? "GET";
      requests.push({ path, method, signal: init?.signal ?? null });
      if (method !== "GET") throw new Error("Unexpected fixture mutation");
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
      if (path === "/api/v1/proxy/policy") return jsonResponse(currentPolicy);
      if (path === "/api/v1/proxy/owner") return jsonResponse(currentOwner);
      if (path === "/api/v1/targets")
        return jsonResponse({
          items: [
            {
              node_id: CHILD,
              name: "Remote fixture",
              origin: "https://child.example:9443",
              server_ip: null,
              active: true,
              retired: false,
              revision: "1",
              observed_epoch: null,
              observed_command: null,
              observed_policy_revision: null,
              rollback_detected: false,
            },
          ],
          next_cursor: null,
          controller_available: true,
        });
      throw new Error("Unexpected fixture read");
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function Shell({ children }: { children: ReactNode }) {
  return (
    <ConfigProvider theme={{ token: { motion: false } }}>
      <MemoryRouter initialEntries={[`/nodes?target=${CHILD}`]}>
        {children}
      </MemoryRouter>
    </ConfigProvider>
  );
}
function Harness() {
  const location = useLocation();
  const { controller, state } = useManagement();
  return (
    <>
      <output data-testid="location">
        {location.pathname + location.search}
      </output>
      <output data-testid="session-phase">{state.phase}</output>
      <button onClick={() => void controller.check()}>test.session</button>
      <Routes>
        <Route path="/nodes" element={<LiveNodes />} />
        <Route path="/users" element={<p>Local user destination</p>} />
      </Routes>
    </>
  );
}
function mountNodes() {
  return render(
    <Shell>
      <ManagementProvider>
        <Harness />
      </ManagementProvider>
    </Shell>,
  );
}
const firstUse = () =>
  screen.getByRole("region", { name: messages["setup.firstUse.title"] });
function collapseButton(region: HTMLElement, caption: string) {
  const button = within(region)
    .getByText(caption)
    .closest<HTMLElement>('[role="button"]');
  expect(button).not.toBeNull();
  return button!;
}
function enter(button: HTMLElement) {
  button.focus();
  expect(document.activeElement).toBe(button);
  fireEvent.keyDown(button, { key: "Enter", code: "Enter", keyCode: 13 });
}
function expand() {
  const region = firstUse();
  const button = collapseButton(region, messages["setup.firstUse.title"]);
  if (button.getAttribute("aria-expanded") !== "true") enter(button);
  expect(button.getAttribute("aria-expanded")).toBe("true");
  return region;
}
async function nodesReady() {
  await screen.findByText("Local fixture");
  await waitFor(() => {
    const refresh = screen
      .getByText(messages["nodes.refresh"])
      .closest("button");
    expect(refresh).not.toBeNull();
    expect(refresh!.querySelector(".ant-btn-loading-icon")).toBeNull();
    expect((refresh as HTMLButtonElement).disabled).toBe(false);
  });
}
function refresh() {
  fireEvent.click(
    screen.getByText(messages["nodes.refresh"]).closest("button")!,
  );
}
const mutations = () => requests.filter((request) => request.method !== "GET");

describe("first-use guidance without provisioning side effects", () => {
  it("opens the account, listener and connection steps without requests, and respects manual collapse", () => {
    const view = render(
      <Shell>
        <FirstUse policy={policy()} owner={owner()} unavailable={false} />
      </Shell>,
    );
    const region = firstUse();
    const button = collapseButton(region, messages["setup.firstUse.title"]);
    expect(button.getAttribute("aria-expanded")).toBe("true");
    expect(
      within(region)
        .getAllByText(/^[123]\.\s/)
        .map((label) => label.textContent),
    ).toEqual([
      messages["setup.firstUse.users"],
      messages["setup.firstUse.listener"],
      messages["setup.firstUse.endpoints"],
    ]);
    expect(
      within(region).getByText(messages["setup.firstUse.userHint"]),
    ).toBeTruthy();
    expect(
      within(region).getByText(messages["setup.firstUse.endpointHint"]),
    ).toBeTruthy();
    enter(button);
    expect(button.getAttribute("aria-expanded")).toBe("false");
    view.rerender(
      <Shell>
        <FirstUse policy={null} owner={null} unavailable />
      </Shell>,
    );
    expect(button.getAttribute("aria-expanded")).toBe("false");
    view.rerender(
      <Shell>
        <FirstUse policy={policy()} owner={owner()} unavailable={false} />
      </Shell>,
    );
    expect(button.getAttribute("aria-expanded")).toBe("false");
    enter(button);
    expect(button.getAttribute("aria-expanded")).toBe("true");
    expect(requests).toHaveLength(0);
  });

  it("shows only current runtime and owner facts, never a completion inferred from historical counts", () => {
    const view = render(
      <Shell>
        <FirstUse policy={null} owner={null} unavailable />
      </Shell>,
    );
    const update = (
      value: PolicyStatus | null,
      authority: Owner | null = owner(),
      unavailable = false,
    ) =>
      view.rerender(
        <Shell>
          <FirstUse
            policy={value}
            owner={authority}
            unavailable={unavailable}
          />
        </Shell>,
      );
    const region = expand();
    expect(
      within(region).getByText(messages["setup.firstUse.unread"]),
    ).toBeTruthy();
    expect(
      within(region).getByText(messages["setup.firstUse.ownerUnknown"]),
    ).toBeTruthy();
    expect(
      within(region).queryByText(messages["setup.firstUse.userHint"]),
    ).toBeNull();
    update({ ...policy(), proxy_running: false, applied_revision: null });
    expect(within(region).getByText(messages["users.apiOnly"])).toBeTruthy();
    expect(
      within(region).getByText(messages["setup.firstUse.userHint"]),
    ).toBeTruthy();
    update(policy());
    expect(within(region).getByText(messages["users.running"])).toBeTruthy();
    const withHistory = region.textContent;
    update({ ...policy(), user_count: 0, credential_count: 0 });
    expect(region.textContent).toBe(withHistory);
    update({
      ...policy(),
      applied_revision: "8",
      durable_applied_revision: "8",
    });
    expect(within(region).getByText(messages["users.pending"])).toBeTruthy();
    update({ ...policy(), applied_revision: null });
    expect(within(region).getByText(messages["users.degraded"])).toBeTruthy();
    update(policy(), { ...owner(), controller_node_id: CHILD });
    expect(
      within(region).getByText(messages["setup.firstUse.delegated"]),
    ).toBeTruthy();
    expect(
      within(region).queryByText(messages["setup.firstUse.userHint"]),
    ).toBeNull();
    expect(
      within(region)
        .getByRole("link", { name: messages["setup.firstUse.manageUsers"] })
        .getAttribute("href"),
    ).toBe("/users");
    expect(
      within(region).queryByRole("button", {
        name: messages["control.takeover"],
      }),
    ).toBeNull();
    update(policy(), owner(), true);
    expect(
      within(region).getByText(messages["setup.firstUse.unread"]),
    ).toBeTruthy();
    expect(within(region).queryByText(messages["users.running"])).toBeNull();
    expect(
      within(region).getByText(messages["setup.firstUse.ownerUnknown"]),
    ).toBeTruthy();
    expect(
      within(region).queryByText(messages["setup.firstUse.userHint"]),
    ).toBeNull();
    expect(
      within(region).getByText(messages["setup.firstUse.notTested"]),
    ).toBeTruthy();
    expect(requests).toHaveLength(0);
  });

  it("uses real keyboard Collapse and local Router links without adding reads or mutations", async () => {
    mountNodes();
    await nodesReady();
    expect(requests.map(({ path }) => path)).toEqual([
      "/api/v1/auth/session",
      "/api/v1/node",
      "/api/v1/proxy/policy",
      "/api/v1/proxy/owner",
      "/api/v1/targets",
    ]);
    const originalRequests = requests.slice();
    const region = firstUse();
    const card = region.closest<HTMLElement>(".live-node-card")!;
    expect(card.parentElement?.className).toBe("node-local");
    for (const advanced of [
      screen.getByText(messages["control.registryNotice"]),
      screen.getByRole("searchbox", { name: messages["control.searchNodes"] }),
      within(card).getByText(messages["control.serverIp"]),
    ]) {
      expect(
        region.compareDocumentPosition(advanced) &
          Node.DOCUMENT_POSITION_FOLLOWING,
      ).not.toBe(0);
    }
    const button = collapseButton(region, messages["setup.firstUse.title"]);
    expect(button.getAttribute("aria-expanded")).toBe("true");
    expect(button.tabIndex).toBe(0);
    enter(button);
    expect(button.getAttribute("aria-expanded")).toBe("false");
    enter(button);
    expect(button.getAttribute("aria-expanded")).toBe("true");
    expect(
      within(region)
        .getByRole("link", { name: messages["service.title"] })
        .getAttribute("href"),
    ).toBe("/service");
    expect(within(region).queryByText("--proxy-config")).toBeNull();
    enter(button);
    expect(button.getAttribute("aria-expanded")).toBe("false");
    enter(button);
    const users = within(region).getByRole("link", {
      name: messages["setup.firstUse.manageUsers"],
    });
    expect(users.getAttribute("href")).toBe("/users");
    await act(async () => {});
    expect(requests).toEqual(originalRequests);
    expect(mutations()).toHaveLength(0);
    fireEvent.click(users);
    expect(screen.getByTestId("location").textContent).toBe("/users");
    expect(screen.getByText("Local user destination")).toBeTruthy();
    expect(requests).toEqual(originalRequests);
  });

  it("keeps delegated authority visible before guidance while remote setup follows it", async () => {
    currentOwner = { ...owner(), controller_node_id: CHILD };
    onRead = (path) =>
      path === "/api/v1/targets"
        ? Promise.resolve(
            jsonResponse({
              items: [],
              next_cursor: null,
              controller_available: false,
            }),
          )
        : undefined;
    mountNodes();
    await nodesReady();
    const guide = firstUse();
    const warning = screen.getByText(messages["control.locallyManaged"]);
    expect(
      warning.compareDocumentPosition(guide) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).not.toBe(0);
    expect(
      guide.compareDocumentPosition(
        screen.getByText(messages["control.tlsUnavailable"]),
      ) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).not.toBe(0);
    expect(
      within(guide).getByText(messages["setup.firstUse.delegated"]),
    ).toBeTruthy();
    expect(mutations()).toHaveLength(0);
  });

  it("keeps the local and remote cards when the independent HTTPS status read is unsupported", async () => {
    onRead = (path) =>
      path === "/api/v1/tls/status"
        ? Promise.resolve(jsonResponse({ error: { code: "not_found" } }, 404))
        : undefined;
    mountNodes();
    await nodesReady();
    expect(
      requests.filter(({ path }) => path === "/api/v1/tls/status"),
    ).toHaveLength(0);
    fireEvent.click(
      screen.getByRole("button", { name: messages["certificates.title"] }),
    );
    await screen.findByText(messages["certificates.unsupported"]);
    expect(screen.getByText("Local fixture")).toBeTruthy();
    expect(screen.getByText("Remote fixture")).toBeTruthy();
    expect(requests.filter(({ path }) => path === "/api/v1/node")).toHaveLength(
      1,
    );
    expect(
      requests.filter(({ path }) => path === "/api/v1/tls/status"),
    ).toHaveLength(1);
    expect(mutations()).toHaveLength(0);
  });

  it("withdraws old runtime facts during reads, after failure and across an abort-ignoring late session result", async () => {
    mountNodes();
    await nodesReady();
    const region = expand();
    expect(within(region).getByText(messages["users.running"])).toBeTruthy();
    const failedRead = deferred<Response>();
    onRead = (path) =>
      path === "/api/v1/proxy/policy" ? failedRead.promise : undefined;
    refresh();
    await waitFor(() =>
      expect(
        requests.filter(({ path }) => path === "/api/v1/proxy/policy"),
      ).toHaveLength(2),
    );
    expect(
      within(region).getByText(messages["setup.firstUse.unread"]),
    ).toBeTruthy();
    expect(within(region).queryByText(messages["users.running"])).toBeNull();
    await act(async () => {
      failedRead.resolve(jsonResponse({ error: { code: "policy_busy" } }, 503));
    });
    await waitFor(() => expect(screen.queryByText("Local fixture")).toBeNull());
    const failed = expand();
    expect(
      within(failed).getByText(messages["setup.firstUse.unread"]),
    ).toBeTruthy();
    expect(within(failed).queryByText(messages["users.running"])).toBeNull();
    expect(
      within(failed).getByText(messages["setup.firstUse.ownerUnknown"]),
    ).toBeTruthy();
    expect(
      within(failed).getByText(messages["setup.firstUse.endpointUnavailable"]),
    ).toBeTruthy();
    const failedRequests = requests.slice();
    expect(
      within(failed)
        .getByRole("link", { name: messages["service.title"] })
        .getAttribute("href"),
    ).toBe("/service");
    await act(async () => {});
    expect(requests).toEqual(failedRequests);
    onRead = () => undefined;
    fireEvent.click(screen.getByText(messages["api.retry"]).closest("button")!);
    await nodesReady();
    const recovered = expand();
    expect(within(recovered).getByText(messages["users.running"])).toBeTruthy();
    const late = deferred<Response>();
    onRead = (path) =>
      path === "/api/v1/proxy/policy" ? late.promise : undefined;
    refresh();
    await waitFor(() =>
      expect(
        requests.filter(({ path }) => path === "/api/v1/proxy/policy"),
      ).toHaveLength(4),
    );
    const pending = requests
      .filter(({ path }) => path === "/api/v1/proxy/policy")
      .at(-1)!;
    authenticated = false;
    fireEvent.click(screen.getByRole("button", { name: "test.session" }));
    await waitFor(() =>
      expect(screen.getByTestId("session-phase").textContent).toBe("anonymous"),
    );
    expect(pending.signal?.aborted).toBe(true);
    await act(async () => {
      late.resolve(jsonResponse(policy()));
    });
    expect(
      screen.queryByRole("region", { name: messages["setup.firstUse.title"] }),
    ).toBeNull();
    expect(screen.queryByText(messages["users.running"])).toBeNull();
    expect(mutations()).toHaveLength(0);
  });
});
