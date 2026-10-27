// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://localhost/"}
import { Buffer } from "node:buffer";
import { createRequire } from "node:module";
import {
  act,
  cleanup,
  fireEvent,
  isInaccessible,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { ConfigProvider } from "antd";
import { useId } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import type { UserOperation } from "../../api/userOperations";
import { ManagementProvider, useManagement } from "../../auth/context";
import { useScopeNavigation } from "../../routing/ScopeNavigation";
import { scopeHref } from "../../routing/scope";
import UsersPage from "./index";

const require = createRequire(import.meta.url);
const rcIdModule = require("@rc-component/util/lib/hooks/useId") as {
  default: (id?: string) => string;
};

// Keep real forms, Portal/Drawer, session generations and transport parsers.
// Only captions, Umi Router exports and the bounded RAM transport are replaced.
vi.mock("@umijs/max", async () => {
  const router = await import("react-router-dom");
  return {
    history: { action: "POP" },
    Link: router.Link,
    useLocation: router.useLocation,
    useNavigate: router.useNavigate,
  };
});
vi.mock("../../hooks/useMessages", () => ({
  useMessages: () => ({ t: (key: string) => key, intl: { locale: "en-US" } }),
}));

const LOCAL = "A".repeat(22);
const PEER = "AQEBAQEBAQEBAQEBAQEBAQ";
const USER = "AgICAgICAgICAgICAgICAg";
const NEW_USER = "BgYGBgYGBgYGBgYGBgYGBg";
const CREDENTIAL = "AwMDAwMDAwMDAwMDAwMDAw";
const BASE = "/proxy/user-operations";
function operationId(sequence: number) {
  const bytes = Buffer.alloc(16, 9);
  bytes.writeBigUInt64BE(BigInt(sequence), 8);
  return bytes.toString("base64url");
}
const OP = operationId(1);
const OTHER_OP = operationId(2);
const makeUser = (id = USER, name = "Existing user") => ({
  id,
  name,
  active: true,
  deleted: false,
  protocols: ["http"],
  concurrent_limit: 8,
  revision: "9",
});
function record(
  state: UserOperation["state"] = "reserved",
  id = OP,
  sequence = "1",
): UserOperation {
  return {
    id,
    node_id: LOCAL,
    sequence,
    expected_revision: "9",
    expected_epoch: "1",
    action: "create_user",
    user_id: state === "saved" ? NEW_USER : null,
    state,
    saved_revision: state === "saved" ? "10" : null,
    rejection: state === "rejected" ? "policy_conflict" : null,
  };
}
interface RequestRecord {
  path: string;
  query: string;
  method: string;
  body: unknown;
  signal: AbortSignal | null;
}
let requests: RequestRecord[];
let unexpected: string[];
let revision: string;
let users: ReturnType<typeof makeUser>[];
let records: UserOperation[];
let authenticated: boolean;
let csrf: string;
let onWrite: (path: string, init: RequestInit) => Promise<Response>;
let onList: (url: URL) => Promise<Response>;
let onExact: (id: string) => Promise<Response>;
let onSearch: (url: URL) => Promise<Response>;

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
function invalidJson(status = 200) {
  return new Response("{", {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
function policy() {
  return {
    saved_revision: revision,
    applied_revision: null,
    durable_applied_revision: null,
    proxy_running: false,
    user_count: users.length,
    credential_count: 1,
  };
}
function target() {
  return {
    node_id: PEER,
    name: "Remote fixture",
    origin: "https://child.example:9443",
    server_ip: null,
    active: true,
    retired: false,
    revision: "3",
    observed_epoch: "2",
    observed_command: "7",
    observed_policy_revision: revision,
    rollback_detected: false,
  };
}
function failUnexpected(method: string, path: string): never {
  unexpected.push(`${method} ${path}`);
  throw new Error(`Unexpected fixture request ${method} ${path}`);
}
const mutations = () => requests.filter(({ method }) => method !== "GET");
const operationReads = () =>
  requests.filter(
    ({ method, path }) => method === "GET" && path.startsWith(BASE),
  );
const exactReads = () => operationReads().filter(({ path }) => path !== BASE);

beforeEach(() => {
  // rc-util test mode otherwise merges the Drawer and Modal Escape IDs. This
  // bypasses only its test override, retaining real React IDs and all Portals.
  vi.spyOn(rcIdModule, "default").mockImplementation((id?: string) => {
    const generated = useId();
    return id || generated;
  });
  requests = [];
  unexpected = [];
  revision = "9";
  users = [makeUser()];
  records = [];
  authenticated = true;
  csrf = "B".repeat(43);
  onList = async () => jsonResponse({ items: records, next_cursor: null });
  onSearch = async (url) =>
    jsonResponse({
      revision,
      items: users.filter(({ id }) => id === url.searchParams.get("q")),
      next_cursor: null,
    });
  onExact = async (id) => {
    const found = records.find((value) => value.id === id);
    return found
      ? jsonResponse(found)
      : jsonResponse({ error: { code: "operation_not_queryable" } }, 404);
  };
  onWrite = async (path, init) => {
    if (path === BASE) {
      records = [record()];
      return jsonResponse(records[0], 201);
    }
    if (path === `${BASE}/${OP}/execute`) {
      const input = JSON.parse(String(init.body)) as {
        change: { name: string };
      };
      records = [record("saved")];
      revision = "10";
      users = [
        ...users,
        { ...makeUser(NEW_USER, input.change.name), revision },
      ];
      return jsonResponse(records[0]);
    }
    return failUnexpected(init.method ?? "GET", path);
  };
  vi.stubGlobal("__VPROXY_DEMO__", false);
  // Layout observers are absent in jsdom; no assertion relies on fake geometry.
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
      const url = new URL(String(input), "https://localhost");
      const path = url.pathname.replace(/^\/api\/v1/, "");
      const method = init?.method ?? "GET";
      requests.push({
        path,
        query: url.search,
        method,
        body: init?.body ? JSON.parse(String(init.body)) : null,
        signal: init?.signal ?? null,
      });
      if (method !== "GET") return onWrite(path, init!);
      if (path === "/auth/session")
        return authenticated
          ? jsonResponse({ ...sessionFixture(), csrf_token: csrf })
          : jsonResponse({ error: { code: "authentication_required" } }, 403);
      if (path === BASE) return onList(url);
      if (path.startsWith(`${BASE}/`))
        return onExact(path.slice(BASE.length + 1));
      if (path === "/node")
        return jsonResponse({
          node_id: LOCAL,
          name: "Local fixture",
          version: "test",
          os: "linux",
          arch: "x86_64",
          capabilities: ["local_administration"],
        });
      if (path === "/targets")
        return jsonResponse({
          items: [target()],
          next_cursor: null,
          controller_available: true,
        });
      if (path === `/targets/${PEER}`) return jsonResponse(target());
      if (path === `/targets/${PEER}/command`) return jsonResponse(null);
      if (path === "/proxy/owner")
        return jsonResponse({
          controller_node_id: null,
          epoch: "1",
          last_terminal_command: "0",
        });
      if (path === "/proxy/policy") return jsonResponse(policy());
      if (path === `/targets/${PEER}/policy`)
        return jsonResponse({
          ...policy(),
          controller_node_id: LOCAL,
          controller_epoch: "2",
          last_terminal_command: "7",
        });
      if (path === "/proxy/users" || path === `/targets/${PEER}/users`) {
        const items = users.slice(0, 25);
        return jsonResponse({
          revision,
          items,
          next_cursor: users.length > 25 ? items.at(-1)!.id : null,
        });
      }
      if (path === "/proxy/users/search") return onSearch(url);
      if (
        path === "/proxy/credentials" ||
        path === `/targets/${PEER}/credentials`
      )
        return jsonResponse({
          revision,
          items:
            url.searchParams.get("user_id") === NEW_USER
              ? []
              : [
                  {
                    id: CREDENTIAL,
                    user_id: USER,
                    login: `vp2_${"03".repeat(16)}`,
                    syntax_version: 2,
                    active: true,
                    revoked: false,
                    verifier_revision: "1",
                  },
                ],
          next_cursor: null,
        });
      return failUnexpected(method, path);
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  expect(unexpected).toEqual([]);
});

function Harness() {
  const moveScope = useScopeNavigation();
  const { controller } = useManagement();
  return (
    <>
      <button onClick={() => moveScope(scopeHref("/users", null))}>
        test.local
      </button>
      <button onClick={() => moveScope(scopeHref("/users", PEER))}>
        test.remote
      </button>
      <button onClick={() => void controller.check()}>test.session</button>
      <UsersPage />
    </>
  );
}
function mount(remote = false) {
  return render(
    <ConfigProvider theme={{ token: { motion: false } }}>
      <MemoryRouter
        initialEntries={[remote ? `/users?target=${PEER}` : "/users"]}
      >
        <ManagementProvider>
          <Harness />
        </ManagementProvider>
      </MemoryRouter>
    </ConfigProvider>,
  );
}
async function userRow(id = USER) {
  const row = (await screen.findByText(id)).closest("tr");
  expect(row).not.toBeNull();
  return row!;
}
async function createUser() {
  const button = (await screen.findByText("users.create")).closest("button");
  expect(button?.tagName).toBe("BUTTON");
  await waitFor(() =>
    expect((button as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.click(button!);
  const dialog = await screen.findByRole("dialog");
  fireEvent.change(within(dialog).getByLabelText("users.name"), {
    target: { value: "Same-name fixture user" },
  });
  fireEvent.click(within(dialog).getByRole("button", { name: "users.save" }));
}
async function openHistory() {
  const button = (await screen.findByText("users.localOperations")).closest(
    "button",
  );
  expect(button?.tagName).toBe("BUTTON");
  await waitFor(() =>
    expect((button as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.click(button!);
  return screen.findByRole("dialog", { name: "users.localOperations" });
}
async function inspect(drawer: HTMLElement, id: string) {
  const identity = await within(drawer).findByText(id);
  const row = identity.closest("tr");
  expect(row).not.toBeNull();
  const button = within(row!).getByRole("button", {
    name: "users.historyInspect",
  });
  await waitFor(() =>
    expect((button as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.click(button);
}
async function unknownExecute() {
  const normal = onWrite;
  onWrite = async (path, init) => {
    const response = await normal(path, init);
    return path.endsWith("/execute") ? invalidJson() : response;
  };
  const mounted = mount();
  await createUser();
  await screen.findByText("users.operationUnknown");
  return mounted;
}

describe("local operation history is an explicit read, not a replay", () => {
  it("keeps an unknown execute locked after a fresh same-name snapshot and another operation's exact result", async () => {
    await unknownExecute();
    expect(mutations().map(({ path }) => path)).toEqual([
      BASE,
      `${BASE}/${OP}/execute`,
    ]);
    expect(mutations()[0].body).toEqual(mutations()[1].body);
    expect(operationReads()).toHaveLength(0);
    // The list may contain a competing same-name row as well as the saved one.
    // Neither a name nor a fresh count identifies the acknowledged reservation.
    users[0] = { ...users[0], name: "Same-name fixture user" };
    const refresh = screen.getByText("users.refresh").closest("button")!;
    fireEvent.click(refresh);
    await userRow(NEW_USER);
    expect(screen.getByText("users.operationUnknown")).toBeTruthy();
    const createButtons = screen
      .getAllByText("users.create")
      .map((element) => element.closest("button"))
      .filter((button) => button !== null);
    expect(createButtons).toHaveLength(1);
    expect(createButtons[0].tagName).toBe("BUTTON");
    expect(createButtons[0].disabled).toBe(true);
    records = [record("saved", OTHER_OP, "2"), record("saved")];
    const drawer = await openHistory();
    await inspect(drawer, OTHER_OP);
    await waitFor(() => expect(exactReads()).toHaveLength(1));
    expect(screen.getByText("users.operationUnknown")).toBeTruthy();
    fireEvent.click(within(drawer).getByRole("button", { name: "关闭" }));
    const notice = screen
      .getByText("users.operationUnknown")
      .closest<HTMLElement>(".ant-alert");
    expect(notice?.isConnected).toBe(true);
    const check = within(notice!).getByRole("button", {
      name: "users.checkOperation",
    });
    await waitFor(() =>
      expect((check as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(check);
    await waitFor(() =>
      expect(screen.queryByText("users.operationUnknown")).toBeNull(),
    );
    expect(exactReads().map(({ path }) => path)).toEqual([
      `${BASE}/${OTHER_OP}`,
      `${BASE}/${OP}`,
    ]);
    expect(mutations()).toHaveLength(2);
    expect(mutations().some(({ path }) => path === "/proxy/users")).toBe(false);
  });

  it("finds records after unmount and a new session only when the administrator opens and inspects history", async () => {
    const previous = await unknownExecute();
    previous.unmount();
    csrf = "D".repeat(43);
    mount();
    await userRow();
    expect(operationReads()).toHaveLength(0);
    const drawer = await openHistory();
    await inspect(drawer, OP);
    expect(
      (await within(drawer).findAllByText("users.historySaved")).length,
    ).toBeGreaterThan(0);
    expect(operationReads().map(({ path }) => path)).toEqual([
      BASE,
      `${BASE}/${OP}`,
    ]);
    expect(mutations()).toHaveLength(2);
    expect(screen.queryByLabelText("users.name")).toBeNull();
    expect(screen.queryByText("users.operationUnknown")).toBeNull();
  });

  it("does not fall back to a legacy user POST when the old schema rejects reservation", async () => {
    onWrite = async (path, init) =>
      path === BASE
        ? jsonResponse({ error: { code: "management_upgrade_required" } }, 503)
        : failUnexpected(init.method ?? "GET", path);
    mount();
    await createUser();
    await waitFor(() => expect(mutations()).toHaveLength(1));
    await waitFor(() =>
      expect(screen.queryByLabelText("users.name")).toBeNull(),
    );
    expect(mutations().map(({ path }) => path)).toEqual([BASE]);
    expect(records).toHaveLength(0);
    expect(users).toHaveLength(1);
  });

  it("does not execute after the reservation reply itself is unparseable", async () => {
    onWrite = async (path, init) => {
      if (path !== BASE) return failUnexpected(init.method ?? "GET", path);
      records = [record()];
      return invalidJson(201);
    };
    mount();
    await createUser();
    await waitFor(() => expect(mutations()).toHaveLength(1));
    await waitFor(() =>
      expect(screen.queryByLabelText("users.name")).toBeNull(),
    );
    expect(mutations().map(({ path }) => path)).toEqual([BASE]);
    expect(operationReads()).toHaveLength(0);
    expect(revision).toBe("9");
  });

  it("does not execute a late reservation after the administrator session has changed", async () => {
    const late = deferred<Response>();
    onWrite = async (path, init) => {
      if (path !== BASE) return failUnexpected(init.method ?? "GET", path);
      records = [record()];
      return late.promise;
    };
    mount();
    await createUser();
    await waitFor(() => expect(mutations()).toHaveLength(1));
    const signal = mutations()[0].signal;
    authenticated = false;
    // An external session check invalidates the resource while reservation is
    // in flight. Its ignored abort must not turn a late 201 into execution.
    fireEvent.click(screen.getByRole("button", { name: "test.session" }));
    await screen.findByRole("button", { name: "auth.signIn" });
    await waitFor(() => expect(signal?.aborted).toBe(true));
    await act(async () => late.resolve(jsonResponse(record(), 201)));
    expect(mutations().map(({ path }) => path)).toEqual([BASE]);
    expect(operationReads()).toHaveLength(0);
    expect(revision).toBe("9");
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("continues directly to credential review for the exact saved user outside the first 25 rows", async () => {
    users = [
      makeUser(),
      ...Array.from({ length: 24 }, (_, index) => {
        const bytes = Buffer.alloc(16, 2);
        bytes.writeUInt16BE(index, 14);
        return makeUser(bytes.toString("base64url"), `Other fixture ${index}`);
      }),
    ].sort((left, right) =>
      left.id < right.id ? -1 : left.id > right.id ? 1 : 0,
    );
    expect(users).toHaveLength(25);
    expect(users.every(({ id }) => id < NEW_USER)).toBe(true);
    const normal = onWrite;
    onWrite = async (path, init) =>
      path === `/proxy/users/${NEW_USER}/credentials`
        ? jsonResponse({ error: { code: "policy_busy" } }, 503)
        : normal(path, init);
    mount();
    await createUser();
    await screen.findByText("users.deliveryCreated");
    const drawer = await screen.findByRole("dialog", {
      name: "users.credentialsFor",
    });
    expect(users).toHaveLength(26);
    expect(screen.queryByText(NEW_USER)).toBeNull();
    const search = requests.filter(
      ({ path }) => path === "/proxy/users/search",
    );
    expect(search).toHaveLength(1);
    expect(Object.fromEntries(new URLSearchParams(search[0].query))).toEqual({
      mode: "id",
      q: NEW_USER,
      limit: "1",
    });
    expect(mutations()).toHaveLength(2);
    const create = within(drawer).getByRole("button", {
      name: "users.createCredentialAndConnect",
    });
    await waitFor(() =>
      expect((create as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(create);
    expect(mutations()).toHaveLength(2);
    // The exact review label identifies the real confirmation Modal without
    // repeatedly enumerating dialogs over the 25-row background table.
    const reviewLabel = await screen.findByText("users.reviewUser");
    const review = reviewLabel.closest<HTMLElement>('[role="dialog"]');
    expect(review?.getAttribute("role")).toBe("dialog");
    expect(review).not.toBe(drawer);
    expect(isInaccessible(review!)).toBe(false);
    expect(
      document.getElementById(review!.getAttribute("aria-labelledby")!)
        ?.textContent,
    ).toBe("users.createCredential");
    const reviewControls = within(review!);
    const userField = reviewLabel.closest("tr")!;
    expect(within(userField).getByText(NEW_USER)).toBeTruthy();
    expect(within(userField).getByText("Same-name fixture user")).toBeTruthy();
    fireEvent.click(reviewControls.getByText("users.operationDetails"));
    const version = reviewControls
      .getByText("users.reviewRevision")
      .closest("tr")!;
    expect(within(version).getByText("10")).toBeTruthy();
    const submit = reviewControls.getByRole("button", {
      name: "users.createCredential",
    });
    expect((submit as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(submit);
    await screen.findByText("users.operationUnknown");
    expect(mutations().map(({ path }) => path)).toEqual([
      BASE,
      `${BASE}/${OP}/execute`,
      `/proxy/users/${NEW_USER}/credentials`,
    ]);
    expect(mutations()[2].body).toEqual({ expected_revision: "10" });
    expect(screen.queryByText("users.secretTitle")).toBeNull();
  });

  it("keeps Saved after the first exact user read fails and retries only that read on an explicit action", async () => {
    const normal = onSearch;
    let calls = 0;
    onSearch = async (url) =>
      ++calls === 1
        ? jsonResponse({ error: { code: "policy_busy" } }, 503)
        : normal(url);
    mount();
    await createUser();
    await screen.findByText("users.operationSaved");
    expect(screen.queryByText("users.operationUnknown")).toBeNull();
    expect(screen.queryByText("users.deliveryCreated")).toBeNull();
    expect(calls).toBe(1);
    expect(mutations()).toHaveLength(2);
    const retry = await screen.findByRole("button", {
      name: "users.readSavedUser",
    });
    await waitFor(() =>
      expect((retry as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(retry);
    await screen.findByText("users.deliveryCreated");
    expect(screen.getByText("users.operationSaved")).toBeTruthy();
    expect(calls).toBe(2);
    expect(
      requests
        .filter(({ path }) => path === "/proxy/users/search")
        .map(({ query }) => Object.fromEntries(new URLSearchParams(query))),
    ).toEqual([
      { mode: "id", q: NEW_USER, limit: "1" },
      { mode: "id", q: NEW_USER, limit: "1" },
    ]);
    expect(mutations().map(({ path }) => path)).toEqual([
      BASE,
      `${BASE}/${OP}/execute`,
    ]);
    expect(operationReads()).toHaveLength(0);
  });

  it("keeps a remote user mutation outside the local operation ledger", async () => {
    onWrite = async (path, init) =>
      path === `/targets/${PEER}/commands`
        ? jsonResponse({ error: { code: "node_unavailable" } }, 503)
        : failUnexpected(init.method ?? "GET", path);
    mount(true);
    await createUser();
    await screen.findByText("users.operationUnknown");
    expect(mutations().map(({ path }) => path)).toEqual([
      `/targets/${PEER}/commands`,
    ]);
    expect(operationReads()).toHaveLength(0);
    expect(
      screen.queryByRole("button", { name: "users.localOperations" }),
    ).toBeNull();
  });

  it("keeps an explicitly confirmed credential action outside reservation and history", async () => {
    onWrite = async (path, init) =>
      path === `/proxy/users/${USER}/credentials`
        ? jsonResponse({ error: { code: "policy_busy" } }, 503)
        : failUnexpected(init.method ?? "GET", path);
    mount();
    const row = await userRow();
    const credentials = within(row).getByRole("button", {
      name: "users.credentials",
    });
    await waitFor(() =>
      expect((credentials as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(credentials);
    const drawer = await screen.findByRole("dialog");
    const create = await within(drawer).findByRole("button", {
      name: "users.createCredential",
    });
    await waitFor(() =>
      expect((create as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(create);
    const review = screen
      .getAllByRole("dialog")
      .find((element) => element !== drawer)!;
    fireEvent.click(
      within(review).getByRole("button", { name: "users.createCredential" }),
    );
    await screen.findByText("users.operationUnknown");
    expect(mutations().map(({ path }) => path)).toEqual([
      `/proxy/users/${USER}/credentials`,
    ]);
    expect(operationReads()).toHaveLength(0);
    expect(screen.queryByText("users.secretTitle")).toBeNull();
  });

  it("does not let an abort-ignoring list from a closed drawer overwrite the reopened list", async () => {
    const late = deferred<Response>();
    let calls = 0;
    onList = async () =>
      ++calls === 1
        ? late.promise
        : jsonResponse({
            items: [record("saved", OTHER_OP, "2")],
            next_cursor: null,
          });
    mount();
    await userRow();
    const entry = screen.getByText("users.localOperations").closest("button")!;
    expect(entry.tagName).toBe("BUTTON");
    entry.focus();
    expect(document.activeElement).toBe(entry);
    // fireEvent does not synthesize a native Enter click. Focus and click the
    // actual button, then exercise Escape through the real Drawer below.
    const old = await openHistory();
    await waitFor(() => expect(operationReads()).toHaveLength(1));
    const signal = operationReads()[0].signal;
    fireEvent.click(within(old).getByRole("button", { name: "关闭" }));
    await waitFor(() => expect(signal?.aborted).toBe(true));
    await waitFor(() => expect(document.activeElement).toBe(entry));
    const current = await openHistory();
    await within(current).findByText(OTHER_OP);
    await act(async () =>
      late.resolve(
        jsonResponse({ items: [record("saved")], next_cursor: null }),
      ),
    );
    expect(within(current).queryByText(OP)).toBeNull();
    expect(within(current).getByText(OTHER_OP)).toBeTruthy();
    const input = within(current).getByRole("textbox", {
      name: "users.operationId",
    });
    expect((input as HTMLInputElement).disabled).toBe(false);
    input.focus();
    expect(document.activeElement).toBe(input);
    fireEvent.keyDown(input, {
      key: "Escape",
      code: "Escape",
      keyCode: 27,
      which: 27,
    });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(entry));
    expect(mutations()).toHaveLength(0);
  });

  it("discards a late exact result when checking the session proves authentication was lost", async () => {
    const late = deferred<Response>();
    records = [record("reserved")];
    onExact = async () => late.promise;
    mount();
    await userRow();
    const drawer = await openHistory();
    await inspect(drawer, OP);
    await waitFor(() => expect(exactReads()).toHaveLength(1));
    const signal = exactReads()[0].signal;
    authenticated = false;
    // This is a controlled external session transition, not a claim that a
    // person can click an underlay control through the Drawer mask.
    fireEvent.click(screen.getByRole("button", { name: "test.session" }));
    await screen.findByRole("button", { name: "auth.signIn" });
    await waitFor(() => expect(signal?.aborted).toBe(true));
    await act(async () => late.resolve(jsonResponse(record("saved"))));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByText(OP)).toBeNull();
    expect(screen.queryByText("users.historySaved")).toBeNull();
    expect(mutations()).toHaveLength(0);
  });

  it("does not move a late local history list into a newly selected remote scope", async () => {
    const late = deferred<Response>();
    onList = async () => late.promise;
    mount();
    await userRow();
    await openHistory();
    await waitFor(() => expect(operationReads()).toHaveLength(1));
    const signal = operationReads()[0].signal;
    // Exercise the real Router/Users key boundary using an external scope
    // transition, without mocking the page's unmount or cancellation effects.
    fireEvent.click(screen.getByRole("button", { name: "test.remote" }));
    await waitFor(() => expect(signal?.aborted).toBe(true));
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: "users.localOperations" }),
      ).toBeNull(),
    );
    await act(async () =>
      late.resolve(
        jsonResponse({ items: [record("saved")], next_cursor: null }),
      ),
    );
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByText(OP)).toBeNull();
    expect(operationReads()).toHaveLength(1);
    expect(mutations()).toHaveLength(0);
  });
});
