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
import { Link, MemoryRouter, useLocation, useNavigate } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import { resourcesHref } from "../../api/targets";
import { ManagementProvider, useManagement } from "../../auth/context";
import messages from "../../locales/en-US";
import ResourcesPage from "./index";

// Keep the session, Router, page, native form, Ant Design and parsers real.
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
        key: keyof typeof captions,
        values?: Record<string, string | number>,
      ) =>
        Object.entries(values ?? {}).reduce<string>(
          (text, [name, value]) => text.replaceAll(`{${name}}`, String(value)),
          captions[key],
        ),
    }),
  };
});
const LOCAL = "A".repeat(22);
const PEER = "AQEBAQEBAQEBAQEBAQEBAQ";
const OTHER_PEER = "AgICAgICAgICAgICAgICAg";
const ADDRESS = "AwMDAwMDAwMDAwMDAwMDAw";
const OTHER_ADDRESS = "BAQEBAQEBAQEBAQEBAQEBA";
const exactPath = (peer: string | null, id = ADDRESS) =>
  peer === null
    ? `/api/v1/proxy/addresses/${id}`
    : `/api/v1/targets/${peer}/proxy/addresses/${id}`;
const target = (node_id: string) => ({
  node_id,
  name: node_id === PEER ? "First child" : "Other child",
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
const record = (ip = "192.0.2.10", id = ADDRESS) => ({
  revision: "9",
  address: {
    id,
    name: "Exact directory entry",
    ip,
    prefix_id: null,
    state: "retired",
    revision: "2",
  },
});
let authenticated: boolean;
let requests: {
  path: string;
  query: string;
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
function Harness() {
  const navigate = useNavigate();
  const location = useLocation();
  const { controller, state } = useManagement();
  return (
    <>
      <output data-testid="location">
        {location.pathname + location.search}
      </output>
      <output data-testid="phase">{state.phase}</output>
      <button onClick={() => navigate(-1)}>test.back</button>
      <button onClick={() => navigate(1)}>test.forward</button>
      <button onClick={() => void controller.check()}>test.session</button>
      <Link to={resourcesHref(null, ADDRESS)}>test.local</Link>
      <Link to={resourcesHref(PEER, ADDRESS)}>test.peer</Link>
      <Link to={resourcesHref(OTHER_PEER, ADDRESS)}>test.other</Link>
      <ResourcesPage />
    </>
  );
}
function mount(location = resourcesHref(null, ADDRESS)) {
  return render(
    <MemoryRouter initialEntries={[location]}>
      <ConfigProvider theme={{ token: { motion: false } }}>
        <ManagementProvider>
          <Harness />
        </ManagementProvider>
      </ConfigProvider>
    </MemoryRouter>,
  );
}
const exactReads = () =>
  requests.filter(({ path }) => /\/proxy\/addresses\/[^/]+$/.test(path));
async function readAgain() {
  const button = screen.getByRole("button", {
    name: messages["users.refresh"],
  });
  await waitFor(() =>
    expect((button as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.click(button);
}
beforeEach(() => {
  authenticated = true;
  requests = [];
  onRead = () => undefined;
  vi.stubGlobal("__VPROXY_DEMO__", false);
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
      const path = url.pathname;
      requests.push({
        path,
        query: url.search,
        method: init?.method ?? "GET",
        signal: init?.signal ?? null,
      });
      const intercepted = onRead(path);
      if (intercepted) return intercepted;
      if (path === "/api/v1/auth/session")
        return authenticated
          ? jsonResponse({
              ...sessionFixture(),
              expires_at: Math.floor(Date.now() / 1000) + 3600,
            })
          : jsonResponse({ error: { code: "authentication_required" } }, 403);
      if (path === "/api/v1/targets")
        return jsonResponse({
          items: [target(PEER), target(OTHER_PEER)],
          next_cursor: null,
          controller_available: true,
        });
      if (path === `/api/v1/targets/${PEER}`) return jsonResponse(target(PEER));
      if (path === `/api/v1/targets/${OTHER_PEER}`)
        return jsonResponse(target(OTHER_PEER));
      if (/\/proxy\/addresses\/[^/]+$/.test(path)) {
        const id = path.split("/").at(-1)!;
        return jsonResponse(
          record(
            path.includes(OTHER_PEER)
              ? "2001:db8::30"
              : path.includes(PEER)
                ? "192.0.2.20"
                : "192.0.2.10",
            id,
          ),
        );
      }
      if (path === "/api/v1/node")
        return jsonResponse({
          node_id: LOCAL,
          name: "Local fixture",
          version: "test",
          os: "linux",
          arch: "x86_64",
          capabilities: ["local_administration"],
        });
      if (path === "/api/v1/proxy/policy")
        return jsonResponse({
          saved_revision: "9",
          applied_revision: null,
          durable_applied_revision: null,
          proxy_running: false,
          user_count: 0,
          credential_count: 0,
        });
      if (path === "/api/v1/proxy/owner")
        return jsonResponse({
          controller_node_id: null,
          epoch: "1",
          last_terminal_command: "0",
        });
      if (path === "/api/v1/proxy/prefixes")
        return jsonResponse({ revision: "9", items: [], next_cursor: null });
      if (path === "/api/v1/proxy/addresses")
        return jsonResponse({
          revision: "9",
          items: [record().address],
          next_cursor: null,
        });
      throw new Error(`Unexpected fixture path ${path}`);
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("exact read-only resource address navigation", () => {
  it("reads the same ID on each selected node without loading a catalog or granting writes", async () => {
    mount();
    await screen.findByText("192.0.2.10");
    expect(screen.getByText(messages["resources.lookupReadOnly"])).toBeTruthy();
    expect(screen.getByText(messages["resources.healthHint"])).toBeTruthy();
    fireEvent.click(screen.getByRole("link", { name: "test.peer" }));
    await screen.findByText("192.0.2.20");
    expect(screen.queryByText("192.0.2.10")).toBeNull();
    fireEvent.click(screen.getByRole("link", { name: "test.other" }));
    await screen.findByText("2001:db8::30");
    expect(screen.queryByText("192.0.2.20")).toBeNull();
    expect(exactReads().map(({ path }) => path)).toEqual([
      exactPath(null),
      exactPath(PEER),
      exactPath(OTHER_PEER),
    ]);
    expect(
      requests.some(({ path }) =>
        /\/(?:policy|owner|command)$|\/proxy\/(?:addresses|prefixes|health)$/.test(
          path,
        ),
      ),
    ).toBe(false);
    expect(requests.every(({ method }) => method === "GET")).toBe(true);
    for (const name of [
      "resources.register",
      "resources.drain",
      "resources.resume",
      "resources.retire",
    ] as const)
      expect(screen.queryByRole("button", { name: messages[name] })).toBeNull();
  });

  it("validates the ID form and explicitly returns to a newly read address list", async () => {
    mount();
    await screen.findByText("192.0.2.10");
    const form = screen.getByRole("form", {
      name: messages["resources.lookupTitle"],
    });
    const input = within(form).getByLabelText(messages["resources.lookupId"]);
    expect((input as HTMLInputElement).maxLength).toBeGreaterThan(
      ADDRESS.length + 1,
    );
    for (const invalid of ["192.0.2.1", `${ADDRESS}x`]) {
      fireEvent.change(input, { target: { value: invalid } });
      fireEvent.submit(form);
      expect(screen.getByText(messages["resources.idRule"])).toBeTruthy();
      expect((input as HTMLInputElement).value).toBe(invalid);
      expect(exactReads()).toHaveLength(1);
    }
    fireEvent.change(input, { target: { value: OTHER_ADDRESS } });
    fireEvent.submit(form);
    await waitFor(() => expect(exactReads()).toHaveLength(2));
    await screen.findByText("192.0.2.10");
    expect(screen.getByTestId("location").textContent).toBe(
      resourcesHref(null, OTHER_ADDRESS),
    );
    fireEvent.click(
      screen.getByRole("button", { name: messages["resources.lookupBrowse"] }),
    );
    await screen.findByRole("button", { name: messages["resources.register"] });
    expect(screen.getByTestId("location").textContent).toBe("/resources");
    expect(
      requests.some(({ path }) => path === "/api/v1/proxy/addresses"),
    ).toBe(true);
    expect(requests.every(({ method }) => method === "GET")).toBe(true);
  });

  it("separates target failure, address absence, unsupported lookup and a failed read", async () => {
    onRead = (path) =>
      path === `/api/v1/targets/${PEER}`
        ? Promise.resolve(
            jsonResponse({ error: { code: "resource_not_found" } }, 404),
          )
        : undefined;
    mount(resourcesHref(PEER, ADDRESS));
    await screen.findByText(messages["resources.lookupTargetFailed"]);
    expect(exactReads()).toHaveLength(0);
    onRead = (path) =>
      path === exactPath(PEER)
        ? Promise.resolve(
            jsonResponse({ error: { code: "resource_not_found" } }, 404),
          )
        : undefined;
    await readAgain();
    await screen.findByText(messages["resources.lookupNotFound"]);
    onRead = (path) =>
      path === exactPath(PEER)
        ? Promise.resolve(
            jsonResponse(
              { error: { code: "address_lookup_unsupported" } },
              502,
            ),
          )
        : undefined;
    await readAgain();
    await screen.findByText(messages["resources.lookupUnsupported"]);
    onRead = (path) =>
      path === exactPath(PEER)
        ? Promise.reject(new TypeError("Synthetic transport failure"))
        : undefined;
    await readAgain();
    await screen.findByText(messages["resources.lookupFailed"]);
    expect(screen.getByTestId("phase").textContent).toBe("authenticated");
    expect(exactReads()).toHaveLength(3);
    expect(
      requests.some(({ path }) => path.startsWith("/api/v1/proxy/addresses")),
    ).toBe(false);
  });

  it("cancels target metadata and exact reads across scope changes and Back/Forward", async () => {
    const oldTarget = deferred<Response>();
    onRead = (path) =>
      path === `/api/v1/targets/${PEER}` ? oldTarget.promise : undefined;
    mount(resourcesHref(PEER, ADDRESS));
    await waitFor(() =>
      expect(
        requests.some(({ path }) => path === `/api/v1/targets/${PEER}`),
      ).toBe(true),
    );
    const targetSignal = requests.find(
      ({ path }) => path === `/api/v1/targets/${PEER}`,
    )?.signal;
    fireEvent.click(screen.getByRole("link", { name: "test.other" }));
    await screen.findByText("2001:db8::30");
    expect(targetSignal?.aborted).toBe(true);
    await act(async () => oldTarget.resolve(jsonResponse(target(PEER))));
    expect(exactReads().some(({ path }) => path === exactPath(PEER))).toBe(
      false,
    );
    const oldAddress = deferred<Response>();
    onRead = (path) =>
      path === exactPath(PEER) ? oldAddress.promise : undefined;
    fireEvent.click(screen.getByRole("button", { name: "test.back" }));
    await waitFor(() =>
      expect(exactReads().some(({ path }) => path === exactPath(PEER))).toBe(
        true,
      ),
    );
    const addressSignal = exactReads().find(
      ({ path }) => path === exactPath(PEER),
    )?.signal;
    fireEvent.click(screen.getByRole("button", { name: "test.forward" }));
    await screen.findByText("2001:db8::30");
    expect(addressSignal?.aborted).toBe(true);
    await act(async () =>
      oldAddress.resolve(jsonResponse(record("192.0.2.99"))),
    );
    expect(screen.queryByText("192.0.2.99")).toBeNull();
    expect(screen.getByTestId("location").textContent).toBe(
      resourcesHref(OTHER_PEER, ADDRESS),
    );
    expect(exactReads().some(({ path }) => path === exactPath(null))).toBe(
      false,
    );
  });

  it("keeps cancelled and session-invalidated reads from restoring a current detail", async () => {
    const cancelled = deferred<Response>();
    onRead = (path) =>
      path === exactPath(PEER) ? cancelled.promise : undefined;
    mount(resourcesHref(PEER, ADDRESS));
    await waitFor(() => expect(exactReads()).toHaveLength(1));
    const cancelledSignal = exactReads()[0].signal;
    fireEvent.click(
      screen.getByRole("button", { name: messages["users.cancel"] }),
    );
    await screen.findByText(messages["resources.lookupCancelled"]);
    expect(cancelledSignal?.aborted).toBe(true);
    await act(async () =>
      cancelled.resolve(jsonResponse(record("192.0.2.98"))),
    );
    expect(screen.queryByText("192.0.2.98")).toBeNull();
    const late = deferred<Response>();
    onRead = (path) => (path === exactPath(PEER) ? late.promise : undefined);
    await readAgain();
    await waitFor(() => expect(exactReads()).toHaveLength(2));
    const signal = exactReads()[1].signal;
    authenticated = false;
    fireEvent.click(screen.getByRole("button", { name: "test.session" }));
    await waitFor(() =>
      expect(screen.getByTestId("phase").textContent).toBe("anonymous"),
    );
    expect(signal?.aborted).toBe(true);
    await act(async () => late.resolve(jsonResponse(record("192.0.2.97"))));
    expect(screen.queryByText("192.0.2.97")).toBeNull();
    expect(screen.queryByText(messages["resources.lookupReadOnly"])).toBeNull();
  });
});
