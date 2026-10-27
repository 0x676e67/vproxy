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
import type { Pool } from "../../api/routing";
import type { PolicyJob } from "../../api/targets";
import { ManagementProvider, useManagement } from "../../auth/context";
import ResourcesPage from "./index";

// Keep Resources, forms, session ownership and strict response decoders real.
// Only Umi exports, captions, synthetic fetch and missing jsdom APIs differ.
vi.mock("@umijs/max", async () => {
  const router = await import("react-router-dom");
  return {
    Link: router.Link,
    useLocation: router.useLocation,
    useNavigate: router.useNavigate,
  };
});
vi.mock("../../hooks/useMessages", () => ({
  useMessages: () => ({
    t: (key: string) => key,
    intl: { locale: "en-US" },
  }),
}));

const LOCAL = "A".repeat(22);
const POOL = "AQEBAQEBAQEBAQEBAQEBAQ";
const ADDRESS = "AgICAgICAgICAgICAgICAg";
const PEER = "AwMDAwMDAwMDAwMDAwMDAw";
const JOB = "BAQEBAQEBAQEBAQEBAQEBA";
const OTHER_JOB = "BQUFBQUFBQUFBQUFBQUFBQ";
const POOL_NAME = "Shared fixture pool";
const NEXT_NAME = "Explicit new pool";
type RequestRecord = { path: string; method: string; body: unknown };
let requests: RequestRecord[];
let unexpected: string[];
let revision: string;
let savedPool: Pool | null;
let nextPool: Pool | null;
let memberIds: string[];
let currentPreset: "linux" | "windows" | null;
let failure: "malformed" | "network";
let checkSession: (() => Promise<void>) | null;
let onRead: (path: string) => Promise<Response> | undefined;
let heldWrite: Promise<Response> | null;
let lastWriteSignal: AbortSignal | null;
let allowNextCreate: boolean;
let remote: boolean;
let currentJob: PolicyJob | null;
let rejection: "authentication_required" | null;
let memberSuccess: boolean;
let presetSuccess: boolean;

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
const poolValue = (): Pool => ({
  id: POOL,
  name: POOL_NAME,
  family: "v4",
  state: "active",
  member_count: memberIds.length,
  revision,
});
const policyValue = () => ({
  saved_revision: revision,
  applied_revision: null,
  durable_applied_revision: null,
  proxy_running: false,
  user_count: 0,
  credential_count: 0,
});
const jobValue = (state: PolicyJob["state"], id = JOB): PolicyJob => ({
  node_id: PEER,
  job_id: id,
  controller_epoch: "2",
  command_id: "1",
  expected_policy_revision: "1",
  state,
  policy_revision: state === "saved" || state === "applied" ? "2" : null,
  outcome_code: state === "blocked" ? "node_permission_or_state" : null,
  attempts: state === "pending" ? 0 : 1,
  next_attempt: "0",
  ...(state === "saved" || state === "applied"
    ? { routing: { kind: "pool" as const, id: POOL } }
    : {}),
});
const validCreation = () =>
  jsonResponse(
    { revision: "2", entity: { kind: "pool", data: savedPool } },
    201,
  );

const mutations = () => requests.filter(({ method }) => method !== "GET");
const poolReads = () =>
  requests.filter(
    ({ path, method }) => path === "/proxy/pools" && method === "GET",
  );

beforeEach(() => {
  requests = [];
  unexpected = [];
  revision = "1";
  savedPool = null;
  nextPool = null;
  memberIds = [];
  currentPreset = null;
  failure = "malformed";
  checkSession = null;
  onRead = () => undefined;
  heldWrite = null;
  lastWriteSignal = null;
  allowNextCreate = false;
  remote = false;
  currentJob = null;
  rejection = null;
  memberSuccess = false;
  presetSuccess = false;
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
      const path = new URL(
        String(input),
        "https://manager.example",
      ).pathname.replace(/^\/api\/v1/, "");
      const method = init?.method ?? "GET";
      const body = init?.body
        ? (JSON.parse(String(init.body)) as unknown)
        : null;
      requests.push({ path, method, body });
      if (method !== "GET") lastWriteSignal = init?.signal ?? null;
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
            name: "Local resource fixture",
            version: "test",
            os: "linux",
            arch: "x86_64",
            capabilities: ["local_administration"],
          });
        if (path === "/targets")
          return jsonResponse({
            items: remote
              ? [
                  {
                    node_id: PEER,
                    name: "Remote resource fixture",
                    origin: "https://child.example:9443",
                    server_ip: null,
                    active: true,
                    retired: false,
                    revision: "1",
                    observed_epoch: "2",
                    observed_command: "0",
                    observed_policy_revision: "1",
                    rollback_detected: false,
                  },
                ]
              : [],
            next_cursor: null,
            controller_available: true,
          });
        if (remote && path === `/targets/${PEER}`)
          return jsonResponse({
            node_id: PEER,
            name: "Remote resource fixture",
            origin: "https://child.example:9443",
            server_ip: null,
            active: true,
            retired: false,
            revision: "1",
            observed_epoch: "2",
            observed_command: "0",
            observed_policy_revision: "1",
            rollback_detected: false,
          });
        if (remote && path === `/targets/${PEER}/command`)
          return jsonResponse(currentJob);
        if (remote && path === `/targets/${PEER}/policy`)
          return jsonResponse({
            ...policyValue(),
            controller_node_id: LOCAL,
            controller_epoch: "2",
            last_terminal_command:
              currentJob?.state === "saved" || currentJob?.state === "applied"
                ? currentJob.command_id
                : "0",
          });
        if (
          remote &&
          path.startsWith(`/targets/${PEER}/proxy/`) &&
          ["prefixes", "addresses", "pools"].includes(path.split("/").at(-1)!)
        )
          return jsonResponse({
            revision,
            items: path.endsWith("/pools") && savedPool ? [savedPool] : [],
            next_cursor: null,
          });
        if (path === "/proxy/policy") return jsonResponse(policyValue());
        if (path === "/proxy/owner")
          return jsonResponse({
            controller_node_id: null,
            epoch: "1",
            last_terminal_command: "0",
          });
        if (
          ["/proxy/prefixes", "/proxy/addresses", "/proxy/pools"].includes(path)
        )
          return jsonResponse({
            revision,
            items:
              path === "/proxy/pools"
                ? [savedPool, nextPool].filter((pool) => pool !== null)
                : [],
            next_cursor: null,
          });
        if (path === `/proxy/pools/${POOL}/members`)
          return jsonResponse({
            revision,
            items: memberIds,
            next_cursor: null,
          });
        if (path === "/proxy/presets")
          return jsonResponse({
            node_id: LOCAL,
            capability_version: 1,
            backend_state: "ready",
            reason_code: null,
            preset_revision: "1",
            abi_version: 1,
            available_presets: ["windows", "linux", "android", "macos", "ios"],
            operations: ["http_forward", "http_connect", "socks5_connect"],
            observed_at_unix_ms: null,
          });
        if (path === `/proxy/pools/${POOL}/presets`)
          return jsonResponse({
            revision,
            preset: { pool_id: POOL, default_preset: currentPreset },
          });
      }
      if (
        memberSuccess &&
        method === "POST" &&
        (path === `/proxy/pools/${POOL}/members` ||
          path === `/proxy/pools/${POOL}/members/remove`)
      ) {
        const removing = path.endsWith("/remove");
        expect(body).toEqual({
          expected_revision: removing ? "2" : "1",
          address_id: ADDRESS,
        });
        expect(memberIds).toEqual(removing ? [ADDRESS] : []);
        expect(mutations()).toHaveLength(removing ? 2 : 1);
        memberIds = removing ? [] : [ADDRESS];
        revision = removing ? "3" : "2";
        savedPool = poolValue();
        return jsonResponse({
          revision,
          entity: { kind: "pool", data: savedPool },
        });
      }
      if (
        presetSuccess &&
        method === "PUT" &&
        path === `/proxy/pools/${POOL}/presets`
      ) {
        expect(body).toEqual({
          expected_revision: "2",
          preset: { pool_id: POOL, default_preset: "windows" },
        });
        expect(mutations()).toHaveLength(2);
        revision = "3";
        currentPreset = "windows";
        savedPool = poolValue();
        return jsonResponse({
          revision,
          preset: { pool_id: POOL, default_preset: currentPreset },
        });
      }
      if (method === "POST" && path === "/proxy/pools") {
        if (allowNextCreate && mutations().length === 2) {
          expect(body).toEqual({
            expected_revision: "2",
            name: NEXT_NAME,
            family: "v4",
          });
          revision = "3";
          nextPool = { ...poolValue(), id: ADDRESS, name: NEXT_NAME };
          return jsonResponse(
            { revision, entity: { kind: "pool", data: nextPool } },
            201,
          );
        }
        expect(body).toEqual({
          expected_revision: "1",
          name: POOL_NAME,
          family: "v4",
        });
        expect(mutations()).toHaveLength(1);
        if (rejection) return jsonResponse({ error: { code: rejection } }, 403);
        // The mutation takes effect before its first response is lost. Tests
        // inspect admission instead of dispatching a second creation as a probe.
        revision = "2";
        savedPool = poolValue();
        if (heldWrite) return heldWrite;
        if (failure === "network")
          throw new TypeError("Synthetic reply unavailable after dispatch");
        return new Response("{", {
          status: 201,
          headers: { "Content-Type": "application/json; charset=utf-8" },
        });
      }
      if (method === "POST" && path === `/proxy/pools/${POOL}/members`) {
        expect(body).toEqual({ expected_revision: "1", address_id: ADDRESS });
        expect(mutations()).toHaveLength(1);
        revision = "2";
        memberIds = [ADDRESS];
        savedPool = poolValue();
        throw new TypeError(
          "Synthetic membership reply unavailable after dispatch",
        );
      }
      if (method === "PUT" && path === `/proxy/pools/${POOL}/presets`) {
        expect(body).toEqual({
          expected_revision: "1",
          preset: { pool_id: POOL, default_preset: "linux" },
        });
        expect(mutations()).toHaveLength(1);
        revision = "2";
        currentPreset = "linux";
        savedPool = poolValue();
        if (heldWrite) return heldWrite;
        throw new TypeError(
          "Synthetic preset reply unavailable after dispatch",
        );
      }
      if (
        remote &&
        method === "POST" &&
        path === `/targets/${PEER}/routing/commands`
      ) {
        expect(body).toEqual({
          expected_target_revision: "1",
          controller_epoch: "2",
          command_id: "1",
          expected_policy_revision: "1",
          mutation: { action: "create_pool", name: POOL_NAME, family: "v4" },
        });
        expect(mutations()).toHaveLength(1);
        currentJob = jobValue("pending");
        return jsonResponse({ job: currentJob, response: null }, 202);
      }
      unexpected.push(`${method} ${path}`);
      throw new Error("Unexpected resource mutation fixture request");
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
function mount(peer: string | null = null) {
  const router = createMemoryRouter(
    [
      { path: "/resources", element: <ResourcesPage /> },
      { path: "/users", element: <p>Other fixture page</p> },
    ],
    { initialEntries: [peer ? `/resources?target=${peer}` : "/resources"] },
  );
  render(
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
  return router;
}
function button(caption: string, region: HTMLElement = document.body) {
  const control = within(region)
    .getByText(caption, { exact: true })
    .closest("button");
  if (!(control instanceof HTMLButtonElement))
    throw new Error("Expected fixture button");
  return control;
}
function catalogRefresh() {
  const catalog = document.querySelector(".ant-pro-table");
  if (!(catalog instanceof HTMLElement))
    throw new Error("Expected resource catalog");
  return button("users.refresh", catalog);
}
function tab(caption: string) {
  const matches = new Set<HTMLElement>();
  for (const text of screen.queryAllByText(caption, { exact: true })) {
    const control = text.closest('[role="tab"]');
    const parent = control?.parentElement;
    // The catalog title can share this caption without being another tab.
    if (
      control instanceof HTMLElement &&
      parent &&
      within(parent).queryAllByRole("tab", { name: caption }).includes(control)
    )
      matches.add(control);
  }
  const [control] = matches;
  if (matches.size !== 1 || !control)
    throw new Error("Expected one accessible fixture tab");
  return control;
}
async function ready() {
  await waitFor(() => tab("resources.pools"));
  await waitFor(() => {
    const refresh = catalogRefresh();
    expect(refresh.querySelector(".ant-btn-loading-icon")).toBeNull();
    expect(screen.getByTestId("session-phase").textContent).toBe(
      "authenticated",
    );
  });
}
async function openPools() {
  await ready();
  fireEvent.click(tab("resources.pools"));
  await waitFor(() =>
    expect(catalogRefresh().querySelector(".ant-btn-loading-icon")).toBeNull(),
  );
}
async function submitPool(name = POOL_NAME) {
  await openPools();
  expect(button("resources.register").disabled).toBe(false);
  fireEvent.click(button("resources.register"));
  // ModalForm's caption is rendered in the real modal, but its accessible name
  // is not assumed to equal the unformatted dictionary key.
  const dialog = await screen.findByRole("dialog");
  expect(
    within(dialog).getByText("resources.register", { exact: true }),
  ).toBeTruthy();
  fireEvent.change(within(dialog).getByLabelText("resources.name"), {
    target: { value: name },
  });
  await act(async () => fireEvent.click(button("users.save", dialog)));
  return dialog;
}
async function createWithLostReply() {
  const dialog = await submitPool();
  await screen.findAllByText("users.mutationUncertain");
  expect(mutations()).toHaveLength(1);
  expect(revision).toBe("2");
  expect(savedPool?.id).toBe(POOL);
  if (dialog.isConnected)
    await act(async () => fireEvent.click(button("users.cancel", dialog)));
  await waitFor(() => expect(dialog.isConnected).toBe(false));
}
async function expectStillUncertain() {
  await screen.findByText(POOL_NAME);
  await waitFor(() =>
    expect(catalogRefresh().querySelector(".ant-btn-loading-icon")).toBeNull(),
  );
  // A fresh inventory observes the resource, not the original creation result.
  // It must not silently acknowledge uncertainty or admit a new creation.
  expect(button("resources.register").disabled).toBe(true);
  expect(
    screen.queryAllByText("users.mutationUncertain").length,
  ).toBeGreaterThan(0);
  expect(mutations()).toHaveLength(1);
  expect(revision).toBe("2");
}
function poolRow() {
  const row = screen.getByText(POOL_NAME, { exact: true }).closest("tr");
  if (!(row instanceof HTMLElement)) throw new Error("Expected pool row");
  return row;
}
async function review(canContinue: boolean) {
  const reads = requests.filter(
    ({ path, method }) => method === "GET" && path.endsWith("/proxy/pools"),
  ).length;
  await act(async () => fireEvent.click(button("resources.readChangeState")));
  await waitFor(() => {
    expect(
      requests.filter(
        ({ path, method }) => method === "GET" && path.endsWith("/proxy/pools"),
      ).length,
    ).toBeGreaterThan(reads);
    expect(
      button("resources.readChangeState").querySelector(
        ".ant-btn-loading-icon",
      ),
    ).toBeNull();
    expect(
      screen.queryAllByText("resources.changeObservationHint").length,
    ).toBeGreaterThan(0);
    expect(button("control.continueChange").disabled).toBe(!canContinue);
  });
}
async function openMembers(writable: boolean) {
  fireEvent.click(button("resources.members", poolRow()));
  const drawer = await screen.findByRole("dialog");
  if (writable)
    await waitFor(() =>
      expect(button("resources.addMember", drawer).disabled).toBe(false),
    );
  else {
    await within(drawer).findByText(ADDRESS, { exact: true });
    expect(button("resources.addMember", drawer).disabled).toBe(true);
  }
  return drawer;
}
async function closeDrawer(drawer: HTMLElement) {
  await act(async () =>
    fireEvent.click(within(drawer).getByRole("button", { name: "关闭" })),
  );
  await waitFor(() => expect(drawer.isConnected).toBe(false));
}
async function openPresets() {
  fireEvent.click(button("presets.title", poolRow()));
  const drawer = await screen.findByRole("dialog");
  await within(drawer).findByLabelText("presets.default");
  return drawer;
}

async function proposePoolPreset(preset: "linux" | "windows") {
  const drawer = await openPresets();
  const input = within(drawer).getByLabelText("presets.default");
  fireEvent.mouseDown(input);
  const dropdown = await waitFor(() => {
    expect(input.getAttribute("aria-expanded")).toBe("true");
    const list = document.getElementById(
      input.getAttribute("aria-controls") ?? "",
    );
    const value = list?.closest<HTMLElement>(".ant-select-dropdown");
    if (!value) throw new Error("Expected preset choices");
    return value;
  });
  fireEvent.click(
    within(dropdown).getByText(preset, {
      selector: ".ant-select-item-option-content",
    }),
  );
  await act(async () => fireEvent.click(button("users.save", drawer)));
  const caption = await screen.findByText("presets.confirm");
  const confirmation = caption.closest('[role="dialog"]');
  if (!(confirmation instanceof HTMLElement))
    throw new Error("Expected preset confirmation");
  return button("users.confirm", confirmation);
}

describe("resource mutation outcomes", () => {
  it("retains a lost-reply fence across a new provider and only clears after fresh review", async () => {
    mount();
    await createWithLostReply();
    const note = Array.from({ length: localStorage.length }, (_, index) =>
      localStorage.key(index),
    ).find((key) => key?.startsWith("vproxy.review.v1.routing."));
    expect(note).toBeTruthy();
    expect(localStorage.getItem(note!)).not.toContain(POOL_NAME);
    cleanup();

    mount();
    await openPools();
    await screen.findByText("resources.changeRestored");
    expect(button("resources.register").disabled).toBe(true);
    expect(mutations()).toHaveLength(1);
    await review(true);
    await act(async () => fireEvent.click(button("control.continueChange")));
    await waitFor(() =>
      expect(button("resources.register").disabled).toBe(false),
    );
    expect(localStorage.getItem(note!)).toBeNull();
    expect(mutations()).toHaveLength(1);
  });

  it("does not promote a restored task hint into retry or supersession authority", async () => {
    remote = true;
    mount(PEER);
    await submitPool();
    await screen.findByText("users.operationPending");
    expect(mutations()).toHaveLength(1);
    cleanup();

    mount(PEER);
    await openPools();
    await screen.findByText("resources.changeRestored");
    expect(button("control.retry").disabled).toBe(true);
    expect(button("control.supersede").disabled).toBe(true);
    expect(button("control.readTicket").disabled).toBe(false);
    await act(async () => fireEvent.click(button("control.readTicket")));
    await waitFor(() =>
      expect(
        button("control.readTicket").querySelector(".ant-btn-loading-icon"),
      ).toBeNull(),
    );
    expect(button("control.retry").disabled).toBe(true);
    expect(button("control.supersede").disabled).toBe(true);
    expect(button("resources.register").disabled).toBe(true);
    expect(mutations()).toHaveLength(1);
  });

  it("keeps member editing usable across successful add and remove with the updated CAS", async () => {
    memberSuccess = true;
    savedPool = poolValue();
    mount();
    await openPools();
    let drawer = await openMembers(true);
    fireEvent.click(button("resources.addMember", drawer));
    const input = await screen.findByLabelText("resources.id");
    const modal = input.closest('[role="dialog"]');
    if (!(modal instanceof HTMLElement))
      throw new Error("Expected member form");
    fireEvent.change(input, { target: { value: ADDRESS } });
    await act(async () => fireEvent.click(button("users.save", modal)));
    drawer = await waitFor(() => {
      const current = screen.getByRole("dialog");
      expect(within(current).getByText(ADDRESS, { exact: true })).toBeTruthy();
      expect(button("resources.removeMember", current).disabled).toBe(false);
      return current;
    });
    expect(mutations()).toHaveLength(1);
    expect(revision).toBe("2");
    fireEvent.click(button("resources.removeMember", drawer));
    const removal = await waitFor(() => {
      const current = screen.queryAllByRole("dialog").find((candidate) =>
        within(candidate).queryByText("resources.removeHint", {
          exact: true,
        }),
      );
      if (!current) throw new Error("Expected member removal confirmation");
      return current;
    });
    await act(async () => fireEvent.click(button("users.confirm", removal)));
    await waitFor(() => {
      const current = screen.getByRole("dialog");
      expect(button("resources.addMember", current).disabled).toBe(false);
      expect(within(current).queryByText(ADDRESS, { exact: true })).toBeNull();
      expect(memberIds).toEqual([]);
      expect(revision).toBe("3");
    });
    expect(mutations().map(({ path, body }) => ({ path, body }))).toEqual([
      {
        path: `/proxy/pools/${POOL}/members`,
        body: { expected_revision: "1", address_id: ADDRESS },
      },
      {
        path: `/proxy/pools/${POOL}/members/remove`,
        body: { expected_revision: "2", address_id: ADDRESS },
      },
    ]);
    expect(screen.queryAllByText("users.mutationUncertain")).toHaveLength(0);
  });

  it("allows a distinct pool preset only after lost-reply review and acknowledgement with the new CAS", async () => {
    savedPool = poolValue();
    mount();
    await openPools();
    const first = await proposePoolPreset("linux");
    await act(async () => fireEvent.click(first));
    await screen.findAllByText("users.mutationUncertain");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(mutations()).toHaveLength(1);
    expect(currentPreset).toBe("linux");
    expect(revision).toBe("2");
    await review(true);
    expect(mutations()).toHaveLength(1);
    await act(async () => fireEvent.click(button("control.continueChange")));
    await waitFor(() =>
      expect(button("resources.register").disabled).toBe(false),
    );
    expect(mutations()).toHaveLength(1);
    presetSuccess = true;
    const next = await proposePoolPreset("windows");
    await act(async () => fireEvent.click(next));
    await waitFor(() => {
      expect(button("resources.register").disabled).toBe(false);
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(currentPreset).toBe("windows");
      expect(revision).toBe("3");
    });
    expect(mutations().map(({ path, body }) => ({ path, body }))).toEqual([
      {
        path: `/proxy/pools/${POOL}/presets`,
        body: {
          expected_revision: "1",
          preset: { pool_id: POOL, default_preset: "linux" },
        },
      },
      {
        path: `/proxy/pools/${POOL}/presets`,
        body: {
          expected_revision: "2",
          preset: { pool_id: POOL, default_preset: "windows" },
        },
      },
    ]);
    expect(screen.queryAllByText("users.mutationUncertain")).toHaveLength(0);
    expect(screen.queryAllByText("users.operationUnknown")).toHaveLength(0);
  });

  it.each(["malformed", "network"] as const)(
    "does not silently unlock a committed pool creation after %s and ordinary refresh",
    async (lostReply) => {
      failure = lostReply;
      mount();
      await createWithLostReply();
      const before = poolReads().length;
      // Close the old editor; refresh is GET-only and cannot prove rollback.
      await act(async () => fireEvent.click(catalogRefresh()));
      await waitFor(() => expect(poolReads().length).toBeGreaterThan(before));
      await expectStillUncertain();
    },
  );

  it("retains an unknown pool creation across tabs, route remount and same-administrator session check", async () => {
    failure = "network";
    const router = mount();
    await createWithLostReply();
    fireEvent.click(tab("resources.prefixes"));
    await ready();
    await openPools();
    await expectStillUncertain();

    await act(async () => {
      await router.navigate("/users");
    });
    await screen.findByText("Other fixture page");
    await act(async () => {
      await router.navigate("/resources");
    });
    await openPools();
    await expectStillUncertain();

    const check = checkSession;
    if (!check) throw new Error("Expected real session controller");
    await act(async () => {
      await check();
    });
    await openPools();
    await expectStillUncertain();
  });

  it("requires an explicit fresh review and starts only a new editor with the new CAS", async () => {
    mount();
    await createWithLostReply();
    expect(button("control.continueChange").disabled).toBe(true);
    await review(true);
    expect(mutations()).toHaveLength(1);
    expect(button("resources.register").disabled).toBe(true);
    await act(async () => fireEvent.click(button("control.continueChange")));
    await waitFor(() =>
      expect(button("resources.register").disabled).toBe(false),
    );
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(mutations()).toHaveLength(1);
    allowNextCreate = true;
    await submitPool(NEXT_NAME);
    await waitFor(() => expect(mutations()).toHaveLength(2));
    expect(mutations()[1].body).toEqual({
      expected_revision: "2",
      name: NEXT_NAME,
      family: "v4",
    });
    expect(revision).toBe("3");
  });

  it("invalidates an earlier acknowledgement as ordinary refresh starts and keeps failure fenced", async () => {
    mount();
    await createWithLostReply();
    await review(true);
    const late = deferred<Response>();
    onRead = (path) => (path === "/proxy/policy" ? late.promise : undefined);
    try {
      await act(async () => fireEvent.click(catalogRefresh()));
      expect(button("control.continueChange").disabled).toBe(true);
      await act(async () =>
        late.resolve(
          new Response("{", {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        ),
      );
      await waitFor(() =>
        expect(
          catalogRefresh().querySelector(".ant-btn-loading-icon"),
        ).toBeNull(),
      );
      expect(button("control.continueChange").disabled).toBe(true);
      expect(button("resources.register").disabled).toBe(true);
      expect(
        screen.queryAllByText("users.mutationUncertain").length,
      ).toBeGreaterThan(0);
      fireEvent.click(button("control.continueChange"));
      expect(mutations()).toHaveLength(1);
    } finally {
      late.resolve(jsonResponse(policyValue()));
    }
  });

  it.each([
    ["route", "valid"],
    ["check", "valid"],
    ["route", "rejected"],
  ] as const)(
    "keeps pending creation unknown after %s cancellation and ignores its late %s reply",
    async (boundary, reply) => {
      const late = deferred<Response>();
      heldWrite = late.promise;
      const router = mount();
      try {
        await submitPool();
        await waitFor(() => expect(mutations()).toHaveLength(1));
        expect(revision).toBe("2");
        if (boundary === "route") {
          await act(async () => {
            await router.navigate("/users");
          });
          await screen.findByText("Other fixture page");
          await act(async () => {
            await router.navigate("/resources");
          });
        } else {
          const check = checkSession;
          if (!check) throw new Error("Expected real session controller");
          await act(async () => {
            await check();
          });
        }
        await openPools();
        await expectStillUncertain();
        expect(lastWriteSignal?.aborted).toBe(true);
        await act(async () =>
          late.resolve(
            reply === "valid"
              ? validCreation()
              : jsonResponse(
                  { error: { code: "authentication_required" } },
                  403,
                ),
          ),
        );
        expect(screen.queryByRole("dialog")).toBeNull();
        expect(screen.queryByText("resources.saved")).toBeNull();
        expect(button("resources.register").disabled).toBe(true);
        expect(
          screen.queryAllByText("users.mutationUncertain").length,
        ).toBeGreaterThan(0);
        expect(mutations()).toHaveLength(1);
      } finally {
        late.resolve(validCreation());
      }
    },
  );

  it("retains a definitive authentication rejection before session loss rather than calling it unknown", async () => {
    rejection = "authentication_required";
    mount();
    await submitPool();
    await waitFor(() =>
      expect(screen.getByTestId("session-phase").textContent).toBe("anonymous"),
    );
    expect(mutations()).toHaveLength(1);
    expect(revision).toBe("1");
    const check = checkSession;
    if (!check) throw new Error("Expected real session controller");
    await act(async () => {
      await check();
    });
    await openPools();
    await screen.findByText("users.operationRejected");
    expect(screen.queryAllByText("users.mutationUncertain")).toHaveLength(0);
    expect(button("resources.register").disabled).toBe(true);
    expect(mutations()).toHaveLength(1);
  });

  it("shares the parent unknown fence with member reload, drawer close and reopen", async () => {
    savedPool = poolValue();
    mount();
    await openPools();
    const drawer = await openMembers(true);
    fireEvent.click(button("resources.addMember", drawer));
    const input = await screen.findByLabelText("resources.id");
    const modal = input.closest('[role="dialog"]');
    if (!(modal instanceof HTMLElement))
      throw new Error("Expected member form");
    fireEvent.change(input, { target: { value: ADDRESS } });
    await act(async () => fireEvent.click(button("users.save", modal)));
    await screen.findAllByText("users.mutationUncertain");
    await waitFor(() => expect(drawer.isConnected).toBe(false));
    expect(memberIds).toEqual([ADDRESS]);
    expect(revision).toBe("2");
    const reopened = await openMembers(false);
    const reads = requests.filter(
      ({ path, method }) => method === "GET" && path.endsWith("/members"),
    ).length;
    const memberTable = reopened.querySelector(".ant-pro-table");
    if (!(memberTable instanceof HTMLElement))
      throw new Error("Expected member table");
    await act(async () =>
      fireEvent.click(button("users.refresh", memberTable)),
    );
    await waitFor(() =>
      expect(
        requests.filter(
          ({ path, method }) => method === "GET" && path.endsWith("/members"),
        ).length,
      ).toBeGreaterThan(reads),
    );
    await within(reopened).findByText(ADDRESS, { exact: true });
    expect(button("resources.addMember", reopened).disabled).toBe(true);
    await closeDrawer(reopened);
    const again = await openMembers(false);
    expect(button("resources.addMember", again).disabled).toBe(true);
    expect(button("resources.register").disabled).toBe(true);
    expect(mutations()).toHaveLength(1);
  });

  it("routes a pool preset through the parent claim and keeps reopening read-only after a lost reply", async () => {
    savedPool = poolValue();
    const late = deferred<Response>();
    heldWrite = late.promise;
    mount();
    try {
      await openPools();
      const drawer = await openPresets();
      const input = within(drawer).getByLabelText("presets.default");
      fireEvent.mouseDown(input);
      const dropdown = await waitFor(() => {
        expect(input.getAttribute("aria-expanded")).toBe("true");
        const list = document.getElementById(
          input.getAttribute("aria-controls") ?? "",
        );
        const value = list?.closest<HTMLElement>(".ant-select-dropdown");
        if (!value) throw new Error("Expected preset choices");
        return value;
      });
      fireEvent.click(
        within(dropdown).getByText("linux", {
          selector: ".ant-select-item-option-content",
        }),
      );
      await act(async () => fireEvent.click(button("users.save", drawer)));
      const caption = await screen.findByText("presets.confirm");
      const confirmation = caption.closest('[role="dialog"]');
      if (!(confirmation instanceof HTMLElement))
        throw new Error("Expected preset confirmation");
      const confirm = button("users.confirm", confirmation);
      // Both editor and catalog actions occur before React commits busy state.
      // The synchronous parent claim must refuse a competing resource editor.
      await act(async () => {
        fireEvent.click(confirm);
        fireEvent.click(confirm);
        fireEvent.click(button("resources.register"));
      });
      await waitFor(() => expect(mutations()).toHaveLength(1));
      expect(currentPreset).toBe("linux");
      expect(revision).toBe("2");
      await act(async () =>
        late.resolve(
          new Response("{", {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        ),
      );
      await screen.findAllByText("users.mutationUncertain");
      if (drawer.isConnected) await closeDrawer(drawer);
      const reopened = await openPresets();
      expect(button("users.save", reopened).disabled).toBe(true);
      const presetReads = requests.filter(
        ({ method, path }) =>
          method === "GET" && path.endsWith(`/${POOL}/presets`),
      ).length;
      await act(async () => fireEvent.click(button("users.refresh", reopened)));
      await waitFor(() =>
        expect(
          requests.filter(
            ({ method, path }) =>
              method === "GET" && path.endsWith(`/${POOL}/presets`),
          ).length,
        ).toBeGreaterThan(presetReads),
      );
      await within(reopened).findByLabelText("presets.default");
      expect(button("users.save", reopened).disabled).toBe(true);
      expect(button("resources.register").disabled).toBe(true);
      expect(mutations()).toHaveLength(1);
    } finally {
      late.resolve(
        jsonResponse({
          revision: "2",
          preset: { pool_id: POOL, default_preset: "linux" },
        }),
      );
    }
  });

  it("retains a remote 202 ticket through pending and blocked reads until explicit terminal review", async () => {
    remote = true;
    mount(PEER);
    await submitPool();
    await screen.findByText("users.operationPending");
    expect(currentJob?.job_id).toBe(JOB);
    expect(mutations()).toHaveLength(1);
    await act(async () => fireEvent.click(catalogRefresh()));
    await ready();
    expect(button("resources.register").disabled).toBe(true);
    await review(false);
    currentJob = jobValue("blocked");
    await review(false);
    expect(button("resources.register").disabled).toBe(true);
    expect(mutations()).toHaveLength(1);
    revision = "2";
    savedPool = poolValue();
    currentJob = jobValue("saved");
    await review(true);
    await screen.findByText(POOL_NAME);
    expect(button("resources.register").disabled).toBe(true);
    await act(async () => fireEvent.click(button("control.continueChange")));
    await waitFor(() =>
      expect(button("resources.register").disabled).toBe(false),
    );
    expect(mutations()).toHaveLength(1);
  });

  it("shows replacement as different current work without adopting its ID or creating again", async () => {
    remote = true;
    mount(PEER);
    await submitPool();
    await screen.findByText("users.operationPending");
    currentJob = jobValue("blocked");
    await review(false);
    await waitFor(() => expect(button("control.retry").disabled).toBe(false));
    revision = "3";
    savedPool = { ...poolValue(), revision: "2" };
    currentJob = {
      ...jobValue("saved", OTHER_JOB),
      command_id: "2",
      expected_policy_revision: "2",
      policy_revision: "3",
    };
    await act(async () => fireEvent.click(button("control.readTicket")));
    await screen.findByText(OTHER_JOB, { exact: true });
    expect(button("control.retry").disabled).toBe(true);
    fireEvent.click(button("control.retry"));
    expect(mutations()).toHaveLength(1);
    await review(true);
    const panel = button("resources.readChangeState").closest(".ant-alert");
    if (!(panel instanceof HTMLElement))
      throw new Error("Expected change review");
    expect(
      within(panel).getByText("resources.changeTicketChanged"),
    ).toBeTruthy();
    fireEvent.click(
      within(panel).getByRole("button", { name: "users.operationDetails" }),
    );
    await within(panel).findByText(JOB, { exact: true });
    expect(within(panel).queryByText(OTHER_JOB, { exact: true })).toBeNull();
    expect(
      screen.getAllByText(OTHER_JOB, { exact: true }).length,
    ).toBeGreaterThan(0);
    expect(button("resources.register").disabled).toBe(true);
    expect(mutations()).toHaveLength(1);
  });
});
