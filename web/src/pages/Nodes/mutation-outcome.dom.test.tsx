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
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import type { Owner, Target } from "../../api/targets";
import { ManagementProvider, useManagement } from "../../auth/context";
import { JOURNAL_PREFIX } from "../../auth/review-journal";
import LiveNodes from "./LiveNodes";

// Keep the page, target form, confirmation, session and client decoders real.
// Only captions, Umi's Router re-export and the synthetic HTTP boundary differ.
vi.mock("@umijs/max", async () => ({
  Link: (await import("react-router-dom")).Link,
}));
vi.mock("../../hooks/useMessages", () => ({
  useMessages: () => ({
    t: (key: string) => key,
    intl: { locale: "en-US" },
  }),
}));

const LOCAL = "A".repeat(22);
const CHILD = "AQEBAQEBAQEBAQEBAQEBAQ";
const OTHER_CHILD = "AgICAgICAgICAgICAgICAg";
const CHANGED_ORIGIN = "https://changed.example:9443";
const NEXT_ORIGIN = "https://next.example:9443";
const target = (): Target => ({
  node_id: CHILD,
  name: "Remote fixture",
  origin: "https://child.example:9443",
  server_ip: null,
  active: true,
  retired: false,
  revision: "3",
  observed_epoch: null,
  observed_command: null,
  observed_policy_revision: null,
  rollback_detected: false,
});
type RequestRecord = { path: string; method: string; body: unknown };
let requests: RequestRecord[];
let unexpected: string[];
let saved: Target;
let registered: Target | null;
let currentOwner: Owner;
let failure: "malformed" | "network" | "rejected";
let action: "edit" | "pause";
let onRead: (path: string) => Promise<Response> | undefined;
let onWrite: (request: RequestRecord) => Promise<Response> | undefined;
let checkSession: (() => Promise<void>) | null;
let lastWriteSignal: AbortSignal | null;
let targetQueries: URLSearchParams[];

const mutations = () => requests.filter(({ method }) => method !== "GET");
const directoryReads = () =>
  requests.filter(
    ({ path, method }) => path === "/targets" && method === "GET",
  );

beforeEach(() => {
  requests = [];
  unexpected = [];
  saved = target();
  registered = null;
  currentOwner = {
    controller_node_id: null,
    epoch: "1",
    last_terminal_command: "0",
  };
  failure = "malformed";
  action = "edit";
  onRead = () => undefined;
  onWrite = () => undefined;
  checkSession = null;
  lastWriteSignal = null;
  targetQueries = [];
  vi.stubGlobal("__VPROXY_DEMO__", false);
  // These missing jsdom APIs select no geometry or application behavior.
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
      const path = url.pathname.replace(/^\/api\/v1/, "");
      if (path === "/targets") targetQueries.push(url.searchParams);
      const method = init?.method ?? "GET";
      const body = init?.body
        ? (JSON.parse(String(init.body)) as unknown)
        : null;
      requests.push({ path, method, body });
      if (method === "GET") {
        const intercepted = onRead(path);
        if (intercepted) return intercepted;
        if (path === "/auth/session")
          return jsonResponse({
            ...sessionFixture(),
            expires_at: Math.floor(Date.now() / 1000) + 3600,
          });
        if (path === "/node")
          return jsonResponse({
            node_id: LOCAL,
            name: "Local fixture",
            version: "test",
            os: "linux",
            arch: "x86_64",
            capabilities: ["local_administration"],
          });
        if (path === "/proxy/policy")
          return jsonResponse({
            saved_revision: "9",
            applied_revision: null,
            durable_applied_revision: null,
            proxy_running: false,
            user_count: 0,
            credential_count: 0,
          });
        if (path === "/proxy/owner") return jsonResponse(currentOwner);
        if (path === "/targets")
          return jsonResponse({
            items: registered ? [saved, registered] : [saved],
            next_cursor: null,
            controller_available: true,
          });
        if (path === `/targets/${CHILD}`) return jsonResponse(saved);
        if (registered && path === `/targets/${registered.node_id}`)
          return jsonResponse(registered);
      } else {
        lastWriteSignal = init?.signal ?? null;
        const intercepted = onWrite({ path, method, body });
        if (intercepted) return intercepted;
      }
      const expectedPath = `/targets/${CHILD}${action === "pause" ? "/state" : ""}`;
      if (
        path === expectedPath &&
        method === (action === "edit" ? "PUT" : "POST")
      ) {
        expect(body).toEqual(
          action === "edit"
            ? {
                expected_revision: "3",
                origin: CHANGED_ORIGIN,
                active: true,
                server_ip: null,
              }
            : { expected_revision: "3", active: false },
        );
        // The first write is already effective in the model before the client
        // loses its reply. A second dispatch is counted, not simulated as safe.
        if (mutations().length === 1) {
          if (failure === "rejected")
            return jsonResponse({ error: { code: "invalid_csrf" } }, 403);
          saved = {
            ...saved,
            revision: "4",
            ...(action === "edit"
              ? { origin: CHANGED_ORIGIN }
              : { active: false }),
          };
          if (failure === "network")
            throw new TypeError(
              "Synthetic response unavailable after dispatch",
            );
          return new Response("{", {
            status: 200,
            headers: { "Content-Type": "application/json; charset=utf-8" },
          });
        }
        return jsonResponse(saved);
      }
      unexpected.push(`${method} ${path}`);
      throw new Error("Unexpected node mutation fixture request");
    }),
  );
});

afterEach(() => {
  cleanup();
  try {
    expect(unexpected).toEqual([]);
  } finally {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  }
});

function SessionProbe() {
  const { controller, state } = useManagement();
  checkSession = () => controller.check();
  return <output data-testid="session-phase">{state.phase}</output>;
}
function mount() {
  const router = createMemoryRouter(
    [
      { path: "/nodes", element: <LiveNodes /> },
      { path: "/users", element: <p>Other fixture page</p> },
    ],
    { initialEntries: ["/nodes"] },
  );
  const view = render(
    <ConfigProvider
      theme={{ token: { motion: false } }}
      wave={{ disabled: true }}
    >
      <ManagementProvider>
        <SessionProbe />
        <RouterProvider router={router} />
      </ManagementProvider>
    </ConfigProvider>,
  );
  return { ...view, router };
}
function button(caption: string, region: HTMLElement = document.body) {
  const control = within(region)
    .getByText(caption, { exact: true })
    .closest("button");
  if (!(control instanceof HTMLButtonElement))
    throw new Error("Expected a fixture button");
  return control;
}
function remoteCard() {
  const card = screen.getByText("Remote fixture").closest(".node-card");
  if (!(card instanceof HTMLElement))
    throw new Error("Expected the remote card");
  return card;
}
async function ready() {
  await screen.findByText("Remote fixture");
  await waitFor(() => {
    const refresh = button("nodes.refresh");
    expect(refresh.disabled).toBe(false);
    expect(refresh.querySelector(".ant-btn-loading-icon")).toBeNull();
  });
}
async function openDetails() {
  await ready();
  const card = remoteCard();
  const header = within(card)
    .getByText("control.nodeDetails")
    .closest('[role="button"]');
  if (!(header instanceof HTMLElement))
    throw new Error("Expected the details header");
  if (header.getAttribute("aria-expanded") !== "true")
    await act(async () => fireEvent.click(header));
  expect(header.getAttribute("aria-expanded")).toBe("true");
  return card;
}
async function dialog(caption: string) {
  return waitFor(() => {
    const dialogs = screen
      .queryAllByText(caption, { exact: true })
      .map((element) => element.closest('[role="dialog"]'))
      .filter(
        (element): element is HTMLElement => element instanceof HTMLElement,
      );
    expect(dialogs).toHaveLength(1);
    return dialogs[0];
  });
}
async function edit() {
  const card = await openDetails();
  fireEvent.click(button("control.editTarget", card));
  const form = await dialog("control.editTarget");
  fireEvent.change(within(form).getByLabelText("control.origin"), {
    target: { value: CHANGED_ORIGIN },
  });
  const submit = button("users.save", form);
  await act(async () => fireEvent.click(submit));
  return { form, submit };
}
async function unknown(submit: HTMLButtonElement) {
  await screen.findAllByText("users.mutationUncertain");
  await waitFor(() =>
    expect(submit.querySelector(".ant-btn-loading-icon")).toBeNull(),
  );
  expect(mutations()).toHaveLength(1);
  expect(saved.revision).toBe("4");
}
async function closeEditor(form: HTMLElement) {
  if (form.isConnected)
    await act(async () => fireEvent.click(button("users.cancel", form)));
  await waitFor(() => expect(form.isConnected).toBe(false));
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
async function review() {
  const before = requests.length;
  fireEvent.click(button("control.readChangeState"));
  await screen.findByText("control.changeObservationHint");
  await ready();
  return requests.slice(before);
}

describe("node mutations with an unavailable first result", () => {
  it("searches the registry on submit, resets pagination, retains filters and only performs reads", async () => {
    const found = { ...target(), node_id: OTHER_CHILD, name: "Elsewhere node" };
    const settled = () =>
      waitFor(() => {
        expect(button("nodes.refresh").disabled).toBe(false);
        expect(
          button("nodes.refresh").querySelector(".ant-btn-loading-icon"),
        ).toBeNull();
      });
    onRead = (path) => {
      if (path !== "/targets") return;
      const query = targetQueries.at(-1)!;
      return Promise.resolve(
        jsonResponse({
          items: query.get("q") ? [found] : [saved],
          next_cursor: query.get("after")
            ? null
            : query.get("q")
              ? OTHER_CHILD
              : CHILD,
          controller_available: true,
        }),
      );
    };
    mount();
    await ready();
    fireEvent.click(button("users.next"));
    await waitFor(() => expect(targetQueries.at(-1)?.get("after")).toBe(CHILD));
    await ready();
    const search = screen.getByRole("searchbox", {
      name: "control.searchNodes",
    });
    const before = targetQueries.length;
    fireEvent.change(search, { target: { value: "Elsewhere" } });
    expect(targetQueries).toHaveLength(before);
    fireEvent.keyDown(search, { key: "Enter", code: "Enter", keyCode: 13 });
    fireEvent.keyUp(search, { key: "Enter", code: "Enter", keyCode: 13 });
    await screen.findByText("Elsewhere node");
    await settled();
    expect(targetQueries.at(-1)?.get("q")).toBe("Elsewhere");
    expect(targetQueries.at(-1)?.has("after")).toBe(false);
    fireEvent.click(button("users.next"));
    await waitFor(() =>
      expect(targetQueries.at(-1)?.get("after")).toBe(OTHER_CHILD),
    );
    await settled();
    expect(targetQueries.at(-1)?.get("q")).toBe("Elsewhere");
    fireEvent.click(
      screen.getByRole("checkbox", { name: "control.includeRetired" }),
    );
    await waitFor(() =>
      expect(targetQueries.at(-1)?.get("include_retired")).toBe("true"),
    );
    await settled();
    expect(targetQueries.at(-1)?.get("q")).toBe("Elsewhere");
    expect(targetQueries.at(-1)?.has("after")).toBe(false);
    const clear = search
      .closest(".node-filter")
      ?.querySelector(".ant-input-clear-icon");
    expect(clear).toBeTruthy();
    const readsBeforeClear = targetQueries.length;
    fireEvent.click(clear!);
    await screen.findByText("Remote fixture");
    await ready();
    expect(targetQueries.at(-1)?.has("q")).toBe(false);
    expect(targetQueries).toHaveLength(readsBeforeClear + 1);
    expect(targetQueries.at(-1)?.get("include_retired")).toBe("true");
    expect(mutations()).toHaveLength(0);
  });
  it.each(["malformed", "network"] as const)(
    "does not redispatch an edited destination after its effective write has a %s reply",
    async (response) => {
      failure = response;
      mount();
      const { submit } = await edit();
      await unknown(submit);
      expect(saved.origin).toBe(CHANGED_ORIGIN);
      // Closing the obsolete form or rejecting its old button are both valid;
      // another activation must never invoke the original write again.
      if (submit.isConnected) await act(async () => fireEvent.click(submit));
      expect(mutations()).toHaveLength(1);
    },
  );

  it("retains the unknown outcome after an explicit read displays the effective destination", async () => {
    mount();
    const { form, submit } = await edit();
    await unknown(submit);
    if (form.isConnected)
      await act(async () => fireEvent.click(button("users.cancel", form)));
    const before = directoryReads().length;
    fireEvent.click(button("nodes.refresh"));
    await waitFor(() => expect(directoryReads()).toHaveLength(before + 1));
    await ready();
    expect(within(remoteCard()).getByText(CHANGED_ORIGIN)).toBeTruthy();
    expect(mutations()).toHaveLength(1);
    expect(
      screen.queryAllByText("users.mutationUncertain").length,
    ).toBeGreaterThan(0);
  });

  it("does not redispatch an uncertain pause from its original confirmation", async () => {
    action = "pause";
    mount();
    const card = await openDetails();
    fireEvent.click(button("control.pause", card));
    const confirmation = await dialog("control.pause");
    const submit = button("users.confirm", confirmation);
    await act(async () => fireEvent.click(submit));
    await unknown(submit);
    expect(saved.active).toBe(false);
    if (submit.isConnected) await act(async () => fireEvent.click(submit));
    expect(mutations()).toHaveLength(1);
  });

  it("retains the unknown note across route remounts and same-administrator session checks", async () => {
    const view = mount();
    const { form, submit } = await edit();
    await unknown(submit);
    await closeEditor(form);
    await act(async () => {
      await view.router.navigate("/users");
    });
    expect(screen.getByText("Other fixture page")).toBeTruthy();
    await act(async () => {
      await view.router.navigate("/nodes");
    });
    await ready();
    expect(
      screen.queryAllByText("users.mutationUncertain").length,
    ).toBeGreaterThan(0);
    expect(button("control.continueChange").disabled).toBe(true);
    expect(button("setup.title").disabled).toBe(true);
    // Local historical reads stay available while an unknown intent locks writes.
    expect(button("commandHistory.open", remoteCard()).disabled).toBe(false);

    await review();
    expect(button("control.continueChange").disabled).toBe(false);

    await act(async () => {
      await view.router.navigate("/users");
    });
    await act(async () => {
      await view.router.navigate("/nodes");
    });
    await ready();
    expect(button("control.continueChange").disabled).toBe(true);
    await review();
    expect(button("control.continueChange").disabled).toBe(false);

    const checks = requests.filter(
      ({ path }) => path === "/auth/session",
    ).length;
    const check = checkSession;
    if (!check) throw new Error("Expected the real session-check fixture");
    // Automatic checks use this same real method; no timer is shortened here.
    await act(async () => {
      await check();
    });
    await ready();
    expect(
      requests.filter(({ path }) => path === "/auth/session"),
    ).toHaveLength(checks + 1);
    expect(screen.getByTestId("session-phase").textContent).toBe(
      "authenticated",
    );
    expect(
      screen.queryAllByText("users.mutationUncertain").length,
    ).toBeGreaterThan(0);
    expect(button("control.continueChange").disabled).toBe(true);
    expect(button("setup.title").disabled).toBe(true);
    expect(
      requests.filter(
        ({ path, method }) => method === "GET" && path === `/targets/${CHILD}`,
      ),
    ).toHaveLength(2);
    expect(mutations()).toHaveLength(1);
  });

  it("restores an uncertain note after replacing the whole provider without replaying or retaining the old observation", async () => {
    const view = mount();
    const first = await edit();
    await unknown(first.submit);
    await closeEditor(first.form);
    await review();
    expect(button("control.continueChange").disabled).toBe(false);
    const name = `${JOURNAL_PREFIX}nodes.${LOCAL}:${LOCAL}`;
    const stored = window.localStorage.getItem(name)!;
    expect(JSON.parse(stored).value).toEqual({
      scope: { administratorId: LOCAL, nodeId: LOCAL },
      intent: {
        kind: "target",
        action: "configure",
        targetId: CHILD,
        expectedRevision: "3",
      },
      phase: "unknown",
    });
    expect(stored).not.toContain(CHANGED_ORIGIN);
    expect(stored).not.toMatch(/csrf|observation|Remote fixture/);

    view.unmount();
    const before = requests.length;
    mount();
    await ready();
    await screen.findAllByText("users.mutationUncertain");
    expect(button("control.continueChange").disabled).toBe(true);
    expect(button("setup.title").disabled).toBe(true);
    expect(screen.queryByText("control.changeObservationHint")).toBeNull();
    expect(requests.slice(before).every(({ method }) => method === "GET")).toBe(
      true,
    );
    expect(mutations()).toHaveLength(1);

    await review();
    await act(async () => fireEvent.click(button("control.continueChange")));
    await waitFor(() =>
      expect(screen.queryByText("control.readChangeState")).toBeNull(),
    );
    expect(window.localStorage.getItem(name)).toBeNull();
    onWrite = async () => {
      saved = { ...saved, origin: NEXT_ORIGIN, revision: "5" };
      return jsonResponse(saved);
    };
    const card = await openDetails();
    fireEvent.click(button("control.editTarget", card));
    const fresh = await dialog("control.editTarget");
    fireEvent.change(within(fresh).getByLabelText("control.origin"), {
      target: { value: NEXT_ORIGIN },
    });
    await act(async () => fireEvent.click(button("users.save", fresh)));
    await waitFor(() => expect(mutations()).toHaveLength(2));
    await ready();
    expect(mutations()[1].body).toEqual({
      expected_revision: "4",
      origin: NEXT_ORIGIN,
      active: true,
      server_ip: null,
    });
  });

  it("does not send a mutation when its review note cannot be saved and leaves reads available", async () => {
    mount();
    await ready();
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("Synthetic full storage", "QuotaExceededError");
    });
    const { submit } = await edit();
    await screen.findByText("control.changeStorage.unavailable");
    await waitFor(() =>
      expect(submit.querySelector(".ant-btn-loading-icon")).toBeNull(),
    );
    expect(mutations()).toEqual([]);
    expect(saved.revision).toBe("3");
    expect(window.localStorage.length).toBe(0);
    const reads = directoryReads().length;
    fireEvent.click(button("nodes.refresh"));
    await waitFor(() => expect(directoryReads()).toHaveLength(reads + 1));
    await ready();
    expect(mutations()).toEqual([]);
  });

  it("does not dispatch a stale editor when authentication changes during journal admission", async () => {
    mount();
    await ready();
    const lockRequests = vi.spyOn(navigator.locks, "request");
    const entered = deferred<void>();
    const held = deferred<void>();
    const registry = navigator.locks.request(
      `${JOURNAL_PREFIX}nodes.registry`,
      async () => {
        entered.resolve();
        await held.promise;
      },
    );
    await entered.promise;
    try {
      await edit();
      await screen.findByText("control.changePending");
      await waitFor(() =>
        expect(
          lockRequests.mock.calls.filter(
            ([name]) => name === `${JOURNAL_PREFIX}nodes.registry`,
          ),
        ).toHaveLength(2),
      );
      expect(mutations()).toEqual([]);
      const check = checkSession;
      if (!check) throw new Error("Expected the real session-check fixture");
      await act(async () => {
        await check();
      });
    } finally {
      await act(async () => {
        held.resolve();
        await registry;
      });
    }
    await waitFor(() =>
      expect(screen.queryByText("control.changePending")).toBeNull(),
    );
    expect(mutations()).toEqual([]);
    expect(window.localStorage.length).toBe(0);
    expect(saved.revision).toBe("3");
  });

  it("requires an exact target and owner read before acknowledgement, then uses a fresh editor and revision", async () => {
    mount();
    const first = await edit();
    await unknown(first.submit);
    await closeEditor(first.form);
    fireEvent.click(button("nodes.refresh"));
    await ready();
    expect(button("control.continueChange").disabled).toBe(true);
    expect(
      requests.filter(
        ({ path, method }) => method === "GET" && path === `/targets/${CHILD}`,
      ),
    ).toHaveLength(0);

    const exact = deferred<Response>();
    onRead = (path) =>
      path === `/targets/${CHILD}` ? exact.promise : undefined;
    const start = requests.length;
    try {
      fireEvent.click(button("control.readChangeState"));
      await waitFor(() =>
        expect(
          requests.filter(
            ({ path, method }) =>
              method === "GET" && path === `/targets/${CHILD}`,
          ),
        ).toHaveLength(1),
      );
      expect(button("control.continueChange").disabled).toBe(true);
      expect(mutations()).toHaveLength(1);
    } finally {
      await act(async () => exact.resolve(jsonResponse(saved)));
    }
    await ready();
    expect(
      requests.slice(start).map(({ path, method }) => [method, path]),
    ).toEqual([
      ["GET", "/node"],
      ["GET", "/proxy/owner"],
      ["GET", `/targets/${CHILD}`],
    ]);
    expect(button("control.continueChange").disabled).toBe(false);
    await act(async () => fireEvent.click(button("control.continueChange")));
    expect(mutations()).toHaveLength(1);
    expect(first.form.isConnected).toBe(false);
    expect(screen.queryByText("control.readChangeState")).toBeNull();

    onRead = () => undefined;
    onWrite = async () => {
      saved = { ...saved, origin: NEXT_ORIGIN, revision: "5" };
      return jsonResponse(saved);
    };
    const card = await openDetails();
    fireEvent.click(button("control.editTarget", card));
    const fresh = await dialog("control.editTarget");
    const origin = within(fresh).getByLabelText(
      "control.origin",
    ) as HTMLInputElement;
    expect(origin.value).toBe(CHANGED_ORIGIN);
    fireEvent.change(origin, { target: { value: NEXT_ORIGIN } });
    await act(async () => fireEvent.click(button("users.save", fresh)));
    await waitFor(() => expect(mutations()).toHaveLength(2));
    await ready();
    expect(mutations()[1]).toEqual({
      path: `/targets/${CHILD}`,
      method: "PUT",
      body: {
        expected_revision: "4",
        origin: NEXT_ORIGIN,
        active: true,
        server_ip: null,
      },
    });
    expect(within(remoteCard()).getByText(NEXT_ORIGIN)).toBeTruthy();
  });

  it("keeps a guide registration's parent lock after the guide is closed and the registry is refreshed", async () => {
    onWrite = async () => {
      registered = {
        ...target(),
        node_id: OTHER_CHILD,
        name: "New destination fixture",
        origin: NEXT_ORIGIN,
        revision: "1",
      };
      return new Response("{", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    mount();
    await ready();
    fireEvent.click(button("setup.title"));
    const guide = await dialog("setup.title");
    for (let step = 0; step < 3; step++)
      await act(async () => fireEvent.click(button("setup.next", guide)));
    fireEvent.change(within(guide).getByLabelText("control.nodeId"), {
      target: { value: OTHER_CHILD },
    });
    fireEvent.change(within(guide).getByLabelText("control.origin"), {
      target: { value: NEXT_ORIGIN },
    });
    await act(async () => fireEvent.click(button("setup.saveAction", guide)));
    await screen.findAllByText("users.mutationUncertain");
    expect(mutations()).toEqual([
      {
        path: "/targets",
        method: "POST",
        body: {
          node_id: OTHER_CHILD,
          origin: NEXT_ORIGIN,
          active: true,
          server_ip: null,
        },
      },
    ]);
    await waitFor(() =>
      expect(button("setup.saveAction", guide).disabled).toBe(true),
    );
    await act(async () => fireEvent.click(button("setup.close", guide)));
    await waitFor(() => expect(guide.isConnected).toBe(false));
    expect(button("setup.title").disabled).toBe(true);
    fireEvent.click(button("setup.title"));
    fireEvent.click(button("nodes.refresh"));
    await ready();
    expect(screen.getByText("New destination fixture")).toBeTruthy();
    expect(button("setup.title").disabled).toBe(true);
    expect(button("control.continueChange").disabled).toBe(true);
    expect(mutations()).toHaveLength(1);
  });

  it("retains an unknown owner grant and reviews the owner without another grant", async () => {
    onWrite = async () => {
      currentOwner = {
        controller_node_id: OTHER_CHILD,
        epoch: "2",
        last_terminal_command: "0",
      };
      throw new TypeError("Synthetic owner reply unavailable after dispatch");
    };
    mount();
    await ready();
    const heading = screen
      .getByText("control.localOwner")
      .closest('[role="button"]');
    if (!(heading instanceof HTMLElement))
      throw new Error("Expected the owner header");
    await act(async () => fireEvent.click(heading));
    fireEvent.click(button("control.grant"));
    const form = await dialog("control.grant");
    fireEvent.change(within(form).getByLabelText("control.nodeId"), {
      target: { value: OTHER_CHILD },
    });
    const submit = button("users.confirm", form);
    await act(async () => fireEvent.click(submit));
    await screen.findAllByText("users.mutationUncertain");
    await waitFor(() =>
      expect(submit.querySelector(".ant-btn-loading-icon")).toBeNull(),
    );
    if (submit.isConnected) await act(async () => fireEvent.click(submit));
    expect(mutations()).toEqual([
      {
        path: "/proxy/owner",
        method: "PUT",
        body: { expected_epoch: "1", controller_node_id: OTHER_CHILD },
      },
    ]);
    await closeEditor(form);
    expect(button("control.continueChange").disabled).toBe(true);
    const reads = await review();
    expect(reads.map(({ path, method }) => [method, path])).toEqual([
      ["GET", "/node"],
      ["GET", "/proxy/owner"],
    ]);
    expect(button("control.continueChange").disabled).toBe(false);
    expect(
      screen.queryAllByText("users.mutationUncertain").length,
    ).toBeGreaterThan(0);
    expect(currentOwner.epoch).toBe("2");
    expect(mutations()).toHaveLength(1);
  });

  it("labels a known invalid-CSRF rejection separately but still requires current-state review", async () => {
    failure = "rejected";
    mount();
    const { form, submit } = await edit();
    await screen.findAllByText("users.operationRejected");
    await waitFor(() =>
      expect(submit.querySelector(".ant-btn-loading-icon")).toBeNull(),
    );
    expect(saved.revision).toBe("3");
    expect(screen.queryByText("users.mutationUncertain")).toBeNull();
    if (submit.isConnected) await act(async () => fireEvent.click(submit));
    expect(mutations()).toHaveLength(1);
    await closeEditor(form);
    expect(button("control.continueChange").disabled).toBe(true);
    const reads = await review();
    expect(reads.map(({ path }) => path)).toEqual([
      "/node",
      "/proxy/owner",
      `/targets/${CHILD}`,
    ]);
    expect(button("control.continueChange").disabled).toBe(false);
    expect(
      screen.queryAllByText("users.operationRejected").length,
    ).toBeGreaterThan(0);
    expect(mutations()).toHaveLength(1);
  });

  it("treats an exact destination 404 as currently not queryable, not proof the unknown write failed", async () => {
    mount();
    const { form, submit } = await edit();
    await unknown(submit);
    await closeEditor(form);
    onRead = (path) =>
      path === `/targets/${CHILD}`
        ? Promise.resolve(
            jsonResponse({ error: { code: "resource_not_found" } }, 404),
          )
        : undefined;
    const start = requests.length;
    fireEvent.click(button("control.readChangeState"));
    await screen.findByText("control.changeMissing");
    await waitFor(() =>
      expect(button("control.continueChange").disabled).toBe(false),
    );
    expect(
      requests.slice(start).map(({ path, method }) => [method, path]),
    ).toEqual([
      ["GET", "/node"],
      ["GET", "/proxy/owner"],
      ["GET", `/targets/${CHILD}`],
    ]);
    expect(
      screen.queryAllByText("users.mutationUncertain").length,
    ).toBeGreaterThan(0);
    expect(mutations()).toHaveLength(1);
  });

  it.each(["route", "session"] as const)(
    "retains an admitted write as unknown after %s cancellation and ignores its late success",
    async (boundary) => {
      const late = deferred<Response>();
      onWrite = () => {
        saved = { ...saved, origin: CHANGED_ORIGIN, revision: "4" };
        return late.promise;
      };
      const view = mount();
      const first = await edit();
      await screen.findByText("control.changePending");
      expect(mutations()).toHaveLength(1);
      const signal = lastWriteSignal;
      if (!signal) throw new Error("Expected the admitted write signal");
      expect(signal.aborted).toBe(false);
      try {
        if (boundary === "route") {
          await act(async () => {
            await view.router.navigate("/users");
          });
          expect(screen.getByText("Other fixture page")).toBeTruthy();
          await act(async () => {
            await view.router.navigate("/nodes");
          });
        } else {
          const check = checkSession;
          if (!check)
            throw new Error("Expected the real session-check fixture");
          await act(async () => {
            await check();
          });
        }
        await ready();
        expect(signal.aborted).toBe(true);
        await screen.findAllByText("users.mutationUncertain");
        await waitFor(() => expect(first.form.isConnected).toBe(false));
        expect(button("control.continueChange").disabled).toBe(true);
        expect(button("setup.title").disabled).toBe(true);
      } finally {
        // Even a failed assertion releases the synthetic transport before the
        // session/provider fixture is cleaned up. It deliberately ignores abort.
        await act(async () => late.resolve(jsonResponse(saved)));
      }
      expect(
        screen.queryAllByText("users.mutationUncertain").length,
      ).toBeGreaterThan(0);
      expect(screen.queryByText("control.changePending")).toBeNull();
      expect(button("control.continueChange").disabled).toBe(true);
      expect(first.form.isConnected).toBe(false);
      expect(mutations()).toEqual([
        {
          path: `/targets/${CHILD}`,
          method: "PUT",
          body: {
            expected_revision: "3",
            origin: CHANGED_ORIGIN,
            active: true,
            server_ip: null,
          },
        },
      ]);
    },
  );

  it("discards the previous exact observation when another review fails and never unlocks from a list refresh", async () => {
    mount();
    const first = await edit();
    await unknown(first.submit);
    await closeEditor(first.form);
    await review();
    expect(button("control.continueChange").disabled).toBe(false);
    const failed = deferred<Response>();
    onRead = (path) =>
      path === `/targets/${CHILD}` ? failed.promise : undefined;
    const start = requests.length;
    try {
      fireEvent.click(button("control.readChangeState"));
      await waitFor(() =>
        expect(
          requests.filter(
            ({ path, method }) =>
              method === "GET" && path === `/targets/${CHILD}`,
          ),
        ).toHaveLength(2),
      );
      expect(screen.queryByText("control.changeObservationHint")).toBeNull();
      expect(button("control.continueChange").disabled).toBe(true);
    } finally {
      await act(async () =>
        failed.resolve(jsonResponse({ error: { code: "policy_busy" } }, 503)),
      );
    }
    await screen.findByText("users.busy");
    await ready();
    expect(
      requests.slice(start).map(({ path, method }) => [method, path]),
    ).toEqual([
      ["GET", "/node"],
      ["GET", "/proxy/owner"],
      ["GET", `/targets/${CHILD}`],
    ]);
    expect(screen.queryByText("control.changeObservationHint")).toBeNull();
    expect(button("control.continueChange").disabled).toBe(true);
    fireEvent.click(button("nodes.refresh"));
    await ready();
    expect(screen.queryByText("control.changeObservationHint")).toBeNull();
    expect(button("control.continueChange").disabled).toBe(true);
    expect(
      screen.queryAllByText("users.mutationUncertain").length,
    ).toBeGreaterThan(0);
    expect(
      requests.filter(
        ({ path, method }) => method === "GET" && path === `/targets/${CHILD}`,
      ),
    ).toHaveLength(2);
    expect(mutations()).toHaveLength(1);
  });
});
