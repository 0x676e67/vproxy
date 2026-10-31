// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://localhost/"}
import { createRequire } from "node:module";
import {
  act,
  cleanup,
  createEvent,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { ConfigProvider } from "antd";
import { createMemoryHistory } from "history";
import { useId } from "react";
import {
  createMemoryRouter,
  MemoryRouter,
  RouterProvider,
  useNavigationType,
} from "react-router-dom";
import { renderClient } from "@umijs/renderer-react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import { capabilityFixture } from "../../api/presets.fixtures";
import { ManagementProvider, useManagement } from "../../auth/context";
import { useScopeNavigation } from "../../routing/ScopeNavigation";
import { scopeHref } from "../../routing/scope";
import UsersPage from "./index";

const require = createRequire(import.meta.url);
const rcIdModule = require("@rc-component/util/lib/hooks/useId") as {
  default: (id?: string) => string;
};
const navigation = vi.hoisted(() => ({ action: "POP" as string }));

// Keep the actual page, forms, drawers, Router, session and transport parsers.
// Boundaries are requests, captions, Umi re-exports and the documented adapters.
vi.mock("@umijs/max", async () => {
  const router = await import("react-router-dom");
  return {
    history: navigation,
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
const OTHER_USER = "BgYGBgYGBgYGBgYGBgYGBg";
const CREDENTIAL = "AwMDAwMDAwMDAwMDAwMDAw";
const JOB = "BAQEBAQEBAQEBAQEBAQEBA";
const OTHER_JOB = "BQUFBQUFBQUFBQUFBQUFBQ";
const OPERATIONS = "/proxy/user-operations";
const OPERATION = "CQkJCQkJCQkAAAAAAAAAAQ";

// These cases inject a failure after dispatch. The reservation must first be
// acknowledged, otherwise they only exercise preparation and cannot be Unknown.
function localUserWrite(execute: typeof onWrite): typeof onWrite {
  return async (path, init) => {
    if (init.method !== "POST") throw new Error("Unexpected fixture method");
    if (path === OPERATIONS)
      return jsonResponse(
        {
          id: OPERATION,
          node_id: LOCAL,
          sequence: "1",
          expected_revision: "9",
          expected_epoch: "1",
          action: "create_user",
          user_id: null,
          state: "reserved",
          saved_revision: null,
          rejection: null,
        },
        201,
      );
    if (path !== `${OPERATIONS}/${OPERATION}/execute`)
      throw new Error(`Unexpected fixture mutation ${path}`);
    return execute(path, init);
  };
}
const user = () => ({
  id: USER,
  name: "Existing user",
  active: true,
  deleted: false,
  protocols: ["http"],
  concurrent_limit: 8,
  revision: "9",
});
const credential = () => ({
  id: CREDENTIAL,
  user_id: USER,
  login: `vp2_${"03".repeat(16)}`,
  syntax_version: 2,
  active: true,
  revoked: false,
  verifier_revision: "1",
});
const target = () => ({
  node_id: PEER,
  name: "Remote fixture",
  origin: "https://child.example:9443",
  server_ip: null,
  active: true,
  retired: false,
  revision: targetRevision,
  observed_epoch: "2",
  observed_command: "7",
  observed_policy_revision: "9",
  rollback_detected: false,
});
const ticket = (state = "pending", id = JOB, userCreation?: boolean) => ({
  node_id: PEER,
  job_id: id,
  controller_epoch: "2",
  command_id: "8",
  expected_policy_revision: "9",
  state,
  policy_revision: state === "saved" || state === "applied" ? "10" : null,
  outcome_code: state === "rejected" ? "remote_rejected" : null,
  attempts: 1,
  next_attempt: "0",
  ...(userCreation === undefined ? {} : { user_creation: userCreation }),
});
let revision: string;
let lastCommand: string;
let targetRevision: string;
let controllerEpoch: string;
let controllerNodeId: string | null;
let users: ReturnType<typeof user>[];
let currentJob: ReturnType<typeof ticket> | null;
let readFailure: boolean;
let requests: {
  path: string;
  query: string;
  method: string;
  body: unknown;
  signal: AbortSignal | null;
}[];
let onWrite: (path: string, init: RequestInit) => Promise<Response>;
let onRead: (path: string) => Promise<Response> | undefined;
let onSearch: (url: URL) => Promise<Response>;

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
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
function remotePolicy() {
  return {
    ...policy(),
    controller_node_id: controllerNodeId,
    controller_epoch: controllerEpoch,
    last_terminal_command: lastCommand,
  };
}
beforeEach(() => {
  navigation.action = "POP";
  // rc-util's test mode replaces every ID with "test-id". Portal deduplicates
  // Escape handlers by ID, falsely merging a real Drawer and Modal into one.
  // Bypass only that test override, not the components or their event handling.
  vi.spyOn(rcIdModule, "default").mockImplementation((id?: string) => {
    const generatedId = useId();
    return id || generatedId;
  });
  revision = "9";
  lastCommand = "7";
  targetRevision = "3";
  controllerEpoch = "2";
  controllerNodeId = LOCAL;
  users = [user()];
  currentJob = null;
  readFailure = false;
  requests = [];
  onWrite = async () => {
    throw new Error("Unexpected fixture mutation");
  };
  onRead = () => undefined;
  onSearch = async () =>
    jsonResponse({ revision, items: [], next_cursor: null });
  vi.stubGlobal("__VPROXY_DEMO__", false);
  // jsdom has no layout/resize observer. No workflow assertion relies on a
  // synthetic size or resize callback; all forms and state transitions stay real.
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
      const intercepted = onRead(path);
      if (intercepted) return intercepted;
      if (path.endsWith("/users/search")) return onSearch(url);
      if (path === "/auth/session") return jsonResponse(sessionFixture());
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
      if (path === `/targets/${PEER}/command`) return jsonResponse(currentJob);
      if (path === "/proxy/owner")
        return jsonResponse({
          controller_node_id: null,
          epoch: "1",
          last_terminal_command: "0",
        });
      if (readFailure && path.endsWith("/policy"))
        return jsonResponse({ error: { code: "policy_busy" } }, 503);
      if (path === "/proxy/policy") return jsonResponse(policy());
      if (path === `/targets/${PEER}/policy`)
        return jsonResponse(remotePolicy());
      if (path === "/proxy/users" || path === `/targets/${PEER}/users`)
        return jsonResponse({ revision, items: users, next_cursor: null });
      if (
        path === "/proxy/credentials" ||
        path === `/targets/${PEER}/credentials`
      )
        return jsonResponse({
          revision,
          items: [credential()],
          next_cursor: null,
        });
      throw new Error(`Unexpected fixture read ${path}`);
    }),
  );
});

const searchRequests = () =>
  requests.filter((request) => request.path.endsWith("/users/search"));
async function searchFor(query: string, enter = false) {
  const form = screen.getByRole("form", { name: "users.searchTitle" });
  fireEvent.change(within(form).getByLabelText("users.searchQuery"), {
    target: { value: query },
  });
  await act(async () => {
    // Submitting the native form is the browser's Enter path; no key handler
    // or component hook is replaced in this test.
    if (enter) fireEvent.submit(form);
    else
      fireEvent.click(
        within(form).getByRole("button", { name: "users.searchSubmit" }),
      );
  });
}
async function listingReady() {
  await waitFor(() => {
    const refresh = screen.getByText("users.refresh").closest("button")!;
    expect(refresh.tagName).toBe("BUTTON");
    expect(refresh.querySelector(".ant-btn-loading-icon")).toBeNull();
    expect((refresh as HTMLButtonElement).disabled).toBe(false);
  });
}

describe("remote command ticket observation", () => {
  it("does not claim an empty ticket before its first successful read", async () => {
    onRead = (path) =>
      path === `/targets/${PEER}`
        ? Promise.resolve(jsonResponse({ error: { code: "policy_busy" } }, 503))
        : undefined;
    mount(true);
    await screen.findByText("users.readFailedHint");
    expect(screen.getByText("control.jobUnread")).toBeTruthy();
    expect(screen.queryByText("control.noJob")).toBeNull();
    const ticketReads = () =>
      requests.filter((request) => request.path === `/targets/${PEER}/command`);
    expect(ticketReads()).toHaveLength(0);
    expect(namedButton("users.create").disabled).toBe(true);

    fireEvent.click(namedButton("control.readTicket"));
    await screen.findByText("control.noJob");
    expect(screen.queryByText("control.jobUnread")).toBeNull();
    expect(ticketReads()).toHaveLength(1);
    expect(namedButton("users.create").disabled).toBe(true);
    expect(mutations()).toHaveLength(0);
  });

  it("retains an explicitly read ticket when the remote details still fail", async () => {
    currentJob = ticket("saved");
    onRead = (path) =>
      path === `/targets/${PEER}`
        ? Promise.resolve(jsonResponse({ error: { code: "policy_busy" } }, 503))
        : undefined;
    mount(true);
    await screen.findByText("users.readFailedHint");
    expect(screen.getByText("control.jobUnread")).toBeTruthy();
    fireEvent.click(namedButton("control.readTicket"));
    await screen.findByText(JOB);
    expect(screen.queryByText("control.jobUnread")).toBeNull();
    expect(screen.queryByText("control.noJob")).toBeNull();

    const targetReads = () =>
      requests.filter((request) => request.path === `/targets/${PEER}`);
    const previous = targetReads().length;
    fireEvent.click(namedButton("users.readAgain"));
    await waitFor(() => {
      expect(targetReads()).toHaveLength(previous + 1);
      expect(namedButton("users.readAgain").disabled).toBe(false);
    });
    expect(screen.getByText(JOB)).toBeTruthy();
    expect(screen.queryByText("control.jobUnread")).toBeNull();
    expect(screen.queryByText("control.noJob")).toBeNull();
    expect(namedButton("users.create").disabled).toBe(true);
    expect(mutations()).toHaveLength(0);
  });
});

describe("local user view during transient policy admission busy", () => {
  it("recovers the complete view without manual refresh or any write", async () => {
    let samples = 0;
    onRead = (path) =>
      path === "/proxy/policy" && samples++ === 0
        ? Promise.resolve(jsonResponse({ error: { code: "policy_busy" } }, 503))
        : undefined;
    mount();
    await waitFor(() => expect(samples).toBe(2), { timeout: 2500 });
    await userRow();
    await listingReady();
    expect(samples).toBe(2);
    expect(screen.queryByText("users.readFailedHint")).toBeNull();
    expect(namedButton("users.create").disabled).toBe(false);
    expect(mutations()).toHaveLength(0);
  });

  it("stops after three busy samples and keeps explicit read recovery", async () => {
    readFailure = true;
    mount();
    await screen.findByText("users.readFailedHint", {}, { timeout: 2500 });
    expect(
      requests.filter((item) => item.path === "/proxy/policy"),
    ).toHaveLength(3);
    expect(namedButton("users.create").disabled).toBe(true);
    readFailure = false;
    fireEvent.click(namedButton("users.readAgain"));
    await userRow();
    await listingReady();
    expect(
      requests.filter((item) => item.path === "/proxy/policy"),
    ).toHaveLength(4);
    expect(mutations()).toHaveLength(0);
  });
});

describe("cross-node search handoff to the managed user page", () => {
  const match = (name = "Search-only account") => ({
    ...user(),
    id: OTHER_USER,
    name,
  });
  const located = () => match("Fresh located account");
  const exactRequests = () =>
    searchRequests().filter(
      ({ query }) => new URLSearchParams(query).get("mode") === "id",
    );
  const main = () =>
    screen.getByLabelText("users.title", { selector: "section" });
  function control(label: string, region: HTMLElement) {
    // Keep the real button and its disabled/handler behavior without repeatedly
    // calculating every underlay row's accessible name. Form labels stay strict.
    const element = within(region)
      .getByText(label, { exact: true })
      .closest("button");
    if (!(element instanceof HTMLButtonElement))
      throw new Error("Expected the cross-node fixture's real button");
    return element;
  }
  const rowIn = (region: HTMLElement, id: string) => {
    const row = within(region).getByText(id).closest("tr");
    expect(row).not.toBeNull();
    return row!;
  };
  async function crossMatch(remote = false, includeDeleted = false) {
    const region = main();
    const open = control("users.crossOpen", region);
    await waitFor(() =>
      expect((open as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(open);
    return matchInOpenModal(remote, includeDeleted);
  }
  async function matchInOpenModal(remote: boolean, includeDeleted = false) {
    const title = await screen.findByText("users.crossNodeSearch", {
      exact: true,
    });
    const modal = title.closest<HTMLElement>('[role="dialog"]');
    if (!modal) throw new Error("Cross-node search must be a real dialog");
    const caption = remote ? `Remote fixture · ${PEER}` : "control.localScope";
    const checkbox = await within(modal).findByLabelText(caption);
    await waitFor(() =>
      expect((checkbox as HTMLInputElement).disabled).toBe(false),
    );
    fireEvent.click(checkbox);
    if (includeDeleted)
      fireEvent.click(within(modal).getByLabelText("users.includeDeleted"));
    const form = within(modal).getByLabelText("users.crossSearchForm", {
      selector: "form",
    });
    const query = within(form).getByLabelText("users.searchQuery");
    const queryIds = screen
      .getAllByLabelText("users.searchQuery")
      .map((field) => field.id);
    expect(queryIds).toHaveLength(2);
    expect(queryIds.every(Boolean)).toBe(true);
    expect(new Set(queryIds).size).toBe(2);
    fireEvent.change(query, {
      target: { value: "Search-only account" },
    });
    await act(async () => {
      fireEvent.submit(form);
    });
    const groupCaption = remote
      ? `Remote fixture · ${PEER}`
      : "control.localScope · control.localScope";
    const submit = control("users.searchSubmit", form);
    await waitFor(() =>
      expect((submit as HTMLButtonElement).disabled).toBe(false),
    );
    const headers = within(modal)
      .getAllByText(groupCaption, { exact: true })
      .map((element) => element.closest('[role="button"]'))
      .filter(
        (element): element is HTMLElement => element instanceof HTMLElement,
      );
    expect(headers).toHaveLength(1);
    expect(headers[0].getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(headers[0]);
    expect(headers[0].getAttribute("aria-expanded")).toBe("true");
    const result = await within(modal).findByLabelText(groupCaption, {
      selector: "section",
    });
    await within(result).findByText(OTHER_USER);
    return control("users.crossLocate", result);
  }

  it.each(["Close", "Escape"] as const)(
    "returns ordinary cross-search %s focus to its connected trigger without searching",
    async (action) => {
      mount();
      await userRow();
      await listingReady();
      const region = main();
      const open = control("users.crossOpen", region);
      open.focus();
      fireEvent.click(open);
      const title = await screen.findByText("users.crossNodeSearch", {
        exact: true,
      });
      const modal = title.closest<HTMLElement>('[role="dialog"]');
      if (!modal) throw new Error("Cross-node search must be a real dialog");
      await within(modal).findByLabelText("control.localScope");
      await waitFor(() =>
        expect(modal.contains(document.activeElement)).toBe(true),
      );
      if (action === "Close")
        fireEvent.click(control("users.crossClose", modal));
      else {
        const focused = document.activeElement;
        if (!(focused instanceof HTMLElement))
          throw new Error("The real modal must own focus");
        fireEvent.keyDown(focused, {
          key: "Escape",
          code: "Escape",
          keyCode: 27,
          which: 27,
        });
      }
      await waitFor(() =>
        expect(
          screen.queryByText("users.crossNodeSearch", { exact: true }),
        ).toBeNull(),
      );
      await waitFor(() => expect(document.activeElement).toBe(open));
      expect(open.isConnected).toBe(true);
      expect(main()).toBe(region);
      expect(open.disabled).toBe(false);
      expect(searchRequests()).toHaveLength(0);
      expect(mutations()).toHaveLength(0);
    },
  );

  it("reserves the same page before background handlers can race, cancels exact lookup and explicitly reads it again", async () => {
    const late = deferred<Response>();
    onSearch = async (url) =>
      url.searchParams.get("mode") === "id"
        ? late.promise
        : jsonResponse({ revision, items: [match()], next_cursor: null });
    mount();
    await userRow();
    await listingReady();
    const region = main();
    const oldRow = rowIn(region, USER);
    const credentials = control("users.credentials", oldRow);
    const refresh = control("users.refresh", region);
    const open = control("users.crossOpen", region);
    const policyReads = requests.filter(
      ({ path }) => path === "/proxy/policy",
    ).length;
    // Deliberate underlay dispatch is a handler-race test, not a claim that the
    // browser lets a person click through the real Modal's mask.
    await act(async () => {
      fireEvent.click(open);
      fireEvent.click(refresh);
      fireEvent.click(credentials);
    });
    const locate = await matchInOpenModal(false);
    expect(
      requests.filter(({ path }) => path === "/proxy/policy"),
    ).toHaveLength(policyReads);
    expect(requests.some(({ path }) => path === "/proxy/credentials")).toBe(
      false,
    );
    await act(async () => {
      fireEvent.click(locate);
      fireEvent.click(refresh);
      fireEvent.click(credentials);
    });
    await waitFor(() => expect(exactRequests()).toHaveLength(1));
    expect(main()).toBe(region);
    expect(
      Object.fromEntries(new URLSearchParams(exactRequests()[0].query)),
    ).toEqual({
      mode: "id",
      q: OTHER_USER,
      limit: "1",
      include_deleted: "false",
    });
    expect(within(region).queryByText(USER)).toBeNull();
    expect(within(region).queryByText(OTHER_USER)).toBeNull();
    expect(
      requests.filter(({ path }) => path === "/proxy/policy"),
    ).toHaveLength(policyReads + 1);
    expect(requests.some(({ path }) => path.endsWith("/credentials"))).toBe(
      false,
    );
    fireEvent.click(control("users.crossLocateCancel", region));
    await within(region).findByText("users.crossLocationCancelled");
    expect(exactRequests()[0].signal?.aborted).toBe(true);
    await act(async () =>
      late.resolve(
        jsonResponse({
          revision,
          items: [match("Late cancelled account")],
          next_cursor: null,
        }),
      ),
    );
    expect(within(region).queryByText("Late cancelled account")).toBeNull();
    onSearch = async () =>
      jsonResponse({ revision, items: [located()], next_cursor: null });
    fireEvent.click(control("users.refresh", region));
    await within(region).findByText("Fresh located account");
    await within(region).findByText("users.crossLocated");
    expect(
      within(region).queryByText("users.crossLocationCancelled"),
    ).toBeNull();
    expect(within(region).queryByText("Search-only account")).toBeNull();
    expect(exactRequests()).toHaveLength(2);
    const form = within(region).getByLabelText("users.searchTitle", {
      selector: "form",
    });
    const query = within(form).getByLabelText(
      "users.searchQuery",
    ) as HTMLInputElement;
    expect(query.value).toBe(OTHER_USER);
    fireEvent.change(query, { target: { value: "Unsubmitted draft" } });
    fireEvent.click(within(region).getByLabelText("users.includeDeleted"));
    await waitFor(() => expect(exactRequests()).toHaveLength(3));
    await listingReady();
    expect(query.value).toBe("Unsubmitted draft");
    expect(new URLSearchParams(exactRequests()[2].query).get("q")).toBe(
      OTHER_USER,
    );
    expect(
      new URLSearchParams(exactRequests()[2].query).get("include_deleted"),
    ).toBe("true");
    // Repeating the already-applied ID is still an explicit location intent;
    // unlike an ordinary filter read, it must replace the unsubmitted draft.
    fireEvent.click(await crossMatch(false, true));
    await waitFor(() => expect(exactRequests()).toHaveLength(4));
    await within(region).findByText("users.crossLocated");
    expect(main()).toBe(region);
    expect(query.value).toBe(OTHER_USER);
    expect(new URLSearchParams(exactRequests()[3].query).get("limit")).toBe(
      "1",
    );
    expect(
      searchRequests().some(
        ({ query: value }) =>
          new URLSearchParams(value).get("q") === "Unsubmitted draft",
      ),
    ).toBe(false);
    expect(mutations()).toHaveLength(0);
  });

  it("locks the old local page until remote fresh-ID lookup commits and uses only the fresh row for edit and credentials", async () => {
    const fresh = deferred<Response>();
    onSearch = async (url) =>
      url.searchParams.get("mode") === "id"
        ? fresh.promise
        : jsonResponse({ revision, items: [match()], next_cursor: null });
    onRead = (path) =>
      path.endsWith("/credentials")
        ? Promise.resolve(
            jsonResponse({ revision, items: [], next_cursor: null }),
          )
        : undefined;
    mount();
    await userRow();
    await listingReady();
    const oldRegion = main();
    const oldCredentials = control("users.credentials", rowIn(oldRegion, USER));
    const oldRefresh = control("users.refresh", oldRegion);
    const locate = await crossMatch(true, true);
    const localPolicyReads = requests.filter(
      ({ path }) => path === "/proxy/policy",
    ).length;
    await act(async () => {
      fireEvent.click(locate);
      fireEvent.click(oldRefresh);
      fireEvent.click(oldCredentials);
    });
    await waitFor(() => expect(exactRequests()).toHaveLength(1));
    expect(exactRequests()[0].path).toBe(`/targets/${PEER}/users/search`);
    expect(new URLSearchParams(exactRequests()[0].query).get("limit")).toBe(
      "1",
    );
    expect(
      new URLSearchParams(exactRequests()[0].query).get("include_deleted"),
    ).toBe("true");
    expect(main()).not.toBe(oldRegion);
    expect(within(main()).queryByText(USER)).toBeNull();
    expect(within(main()).queryByText(OTHER_USER)).toBeNull();
    expect(
      requests.filter(({ path }) => path === "/proxy/policy"),
    ).toHaveLength(localPolicyReads);
    expect(requests.some(({ path }) => path.endsWith("/credentials"))).toBe(
      false,
    );
    await act(async () =>
      fresh.resolve(
        jsonResponse({ revision, items: [located()], next_cursor: null }),
      ),
    );
    const region = main();
    await within(region).findByText("Fresh located account");
    const { item: edit } = await rowAction(
      rowIn(region, OTHER_USER),
      "users.edit",
    );
    fireEvent.click(edit);
    const form = await screen.findByRole("dialog", { name: "users.edit" });
    expect(
      (within(form).getByLabelText("users.name") as HTMLInputElement).value,
    ).toBe("Fresh located account");
    fireEvent.click(control("users.cancel", form));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const credentials = control("users.credentials", rowIn(region, OTHER_USER));
    fireEvent.click(credentials);
    await screen.findByRole("dialog", { name: "users.credentialsFor" });
    await waitFor(() =>
      expect(
        requests.filter(({ path }) => path === `/targets/${PEER}/credentials`),
      ).toHaveLength(1),
    );
    const read = requests.find(
      ({ path }) => path === `/targets/${PEER}/credentials`,
    )!;
    expect(new URLSearchParams(read.query).get("user_id")).toBe(OTHER_USER);
    expect(requests.some(({ path }) => path === "/proxy/credentials")).toBe(
      false,
    );
    expect(mutations()).toHaveLength(0);
  });

  it.each(["malformed", "missing", "wrong-id", "revision", "denied"] as const)(
    "does not install a search snapshot, old row or local fallback after a %s remote lookup",
    async (failure) => {
      onSearch = async (url) => {
        if (url.searchParams.get("mode") !== "id")
          return jsonResponse({
            revision,
            items: [match()],
            next_cursor: null,
          });
        if (failure === "malformed")
          return jsonResponse({ revision, items: [match()] });
        return jsonResponse({
          revision: failure === "revision" ? "10" : revision,
          items:
            failure === "missing"
              ? []
              : failure === "wrong-id"
                ? [user()]
                : [located()],
          next_cursor: null,
        });
      };
      mount();
      await userRow();
      await listingReady();
      const locate = await crossMatch(true);
      if (failure === "denied")
        onRead = (path) =>
          path === `/targets/${PEER}/policy`
            ? Promise.resolve(
                jsonResponse({ error: { code: "node_control_denied" } }, 403),
              )
            : undefined;
      const lists = requests.filter(
        ({ path }) => path === "/proxy/users",
      ).length;
      const oldRegion = main();
      fireEvent.click(locate);
      const expected =
        failure === "missing"
          ? "users.crossMissing"
          : failure === "revision"
            ? "users.searchChangedHint"
            : failure === "denied"
              ? "control.denied"
              : "api.format";
      await waitFor(() => expect(main()).not.toBe(oldRegion));
      const region = main();
      await within(region).findByText(expected);
      expect(within(region).queryByText(USER)).toBeNull();
      expect(within(region).queryByText("Search-only account")).toBeNull();
      expect(within(region).queryByText("Fresh located account")).toBeNull();
      expect(
        requests.filter(({ path }) => path === "/proxy/users"),
      ).toHaveLength(lists);
      expect(
        searchRequests().every(
          ({ path }) => path === `/targets/${PEER}/users/search`,
        ),
      ).toBe(true);
      expect(exactRequests()).toHaveLength(failure === "denied" ? 0 : 1);
      expect(requests.some(({ path }) => path.endsWith("/credentials"))).toBe(
        false,
      );
      expect(mutations()).toHaveLength(0);
    },
  );

  it("keeps an unknown user write reserved instead of opening another cross-node journey", async () => {
    onWrite = localUserWrite(async () => jsonResponse({}, 200));
    mount();
    await createUser();
    await screen.findByText("users.operationUnknown");
    const region = main();
    const cross = within(region).getByRole("button", {
      name: "users.crossOpen",
    });
    expect((cross as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(cross);
    expect(
      screen.queryByRole("dialog", { name: "users.crossNodeSearch" }),
    ).toBeNull();
    expect(within(region).getByText("users.operationUnknown")).toBeTruthy();
    expect(
      (
        within(region).getByRole("button", {
          name: "users.create",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(searchRequests()).toHaveLength(0);
    expect(mutations().map(({ path }) => path)).toEqual([
      OPERATIONS,
      `${OPERATIONS}/${OPERATION}/execute`,
    ]);
  });

  it("consumes a pushed handoff once without persisting it or replaying it through history", async () => {
    const storage = vi.spyOn(Storage.prototype, "setItem");
    onSearch = async (url) =>
      jsonResponse({
        revision,
        items: [url.searchParams.get("mode") === "id" ? located() : match()],
        next_cursor: null,
      });
    const router = createMemoryRouter(
      [{ path: "/users", element: <Harness /> }],
      {
        initialEntries: ["/users"],
      },
    );
    render(
      <ConfigProvider theme={{ token: { motion: false } }}>
        <ManagementProvider>
          <RouterProvider router={router} />
        </ManagementProvider>
      </ConfigProvider>,
    );
    await userRow();
    await listingReady();
    fireEvent.click(await crossMatch(true));
    await waitFor(() => expect(exactRequests()).toHaveLength(1));
    await within(main()).findByText("Fresh located account");
    expect(router.state.location.search).toBe(`?target=${PEER}`);
    expect(router.state.location.state).toBeNull();
    expect(exactRequests()).toHaveLength(1);
    await act(async () => {
      await router.navigate(-1);
    });
    await userRow();
    await listingReady();
    await act(async () => {
      await router.navigate(1);
    });
    await waitFor(() =>
      expect(
        requests.filter(({ path }) => path === `/targets/${PEER}/users`),
      ).toHaveLength(1),
    );
    await userRow();
    await listingReady();
    expect(router.state.location.search).toBe(`?target=${PEER}`);
    expect(exactRequests()).toHaveLength(1);
    expect(
      requests.filter(({ path }) => path === `/targets/${PEER}/users`),
    ).toHaveLength(1);
    expect(within(main()).queryByText("users.crossLocated")).toBeNull();
    expect(within(main()).queryByText(OTHER_USER)).toBeNull();
    expect(storage).not.toHaveBeenCalled();
    expect(mutations()).toHaveLength(0);
  });

  it("locates the original user with Umi's actual Router and does not replay it on POP", async () => {
    onSearch = async (url) =>
      jsonResponse({
        revision,
        items: [url.searchParams.get("mode") === "id" ? located() : match()],
        next_cursor: null,
      });
    const history = createMemoryHistory({ initialEntries: ["/users"] });
    navigation.action = history.action;
    const unlisten = history.listen(({ action }) => {
      navigation.action = action;
    });
    const Browser = renderClient({
      routes: { users: { id: "users", path: "/users" } },
      routeComponents: { users: UsersPage },
      history,
      rootElement: {} as HTMLElement,
      components: true,
      pluginManager: {
        applyPlugins: ({ initialValue }: { initialValue?: unknown }) =>
          initialValue,
      },
      __INTERNAL_DO_NOT_USE_OR_YOU_WILL_BE_FIRED: { pureApp: true },
    });
    if (!Browser) throw new Error("Umi must return its real browser component");
    try {
      render(
        <ConfigProvider theme={{ token: { motion: false } }}>
          <ManagementProvider>
            <Browser />
          </ManagementProvider>
        </ConfigProvider>,
      );
      await userRow();
      await listingReady();
      fireEvent.click(await crossMatch(true));
      await waitFor(() => expect(exactRequests()).toHaveLength(1));
      await within(main()).findByText("Fresh located account");
      expect(history.location.search).toBe(`?target=${PEER}`);
      expect(history.location.state).toBeNull();
      await act(async () => history.back());
      await userRow();
      await listingReady();
      await act(async () => history.forward());
      await userRow();
      await listingReady();
      expect(exactRequests()).toHaveLength(1);
      expect(within(main()).queryByText("users.crossLocated")).toBeNull();
      expect(mutations()).toHaveLength(0);
    } finally {
      unlisten();
    }
  });
});

describe("node-scoped user search", () => {
  it("submits only on Search/Enter, keeps the explicit mode and does not send an unsubmitted draft on filter changes", async () => {
    mount();
    await userRow();
    await listingReady();
    const form = screen.getByRole("form", { name: "users.searchTitle" });
    fireEvent.change(within(form).getByLabelText("users.searchQuery"), {
      target: { value: "  %_用户 + /  " },
    });
    expect(searchRequests()).toHaveLength(0);
    await searchFor("  %_用户 + /  ", true);
    await screen.findByText("users.searchEmpty");
    expect(searchRequests()).toHaveLength(1);
    expect(new URLSearchParams(searchRequests()[0].query).get("q")).toBe(
      "%_用户 + /",
    );
    expect(new URLSearchParams(searchRequests()[0].query).get("mode")).toBe(
      "name",
    );
    fireEvent.change(screen.getByLabelText("users.searchQuery"), {
      target: { value: "draft not submitted" },
    });
    fireEvent.click(
      screen.getByRole("checkbox", { name: "users.includeDeleted" }),
    );
    await waitFor(() => expect(searchRequests()).toHaveLength(2));
    await listingReady();
    const applied = new URLSearchParams(searchRequests()[1].query);
    expect(applied.get("q")).toBe("%_用户 + /");
    expect(applied.get("include_deleted")).toBe("true");
    fireEvent.mouseDown(screen.getByLabelText("users.searchMode"));
    fireEvent.click(
      await screen.findByText("users.searchId", {
        selector: ".ant-select-item-option-content",
      }),
    );
    await searchFor(USER);
    await waitFor(() => expect(searchRequests()).toHaveLength(3));
    await listingReady();
    expect(new URLSearchParams(searchRequests()[2].query).get("mode")).toBe(
      "id",
    );
    expect(mutations()).toHaveLength(0);
  });

  it("keeps unsupported remote search explicit and returns to that node's legacy pages only after Clear", async () => {
    onSearch = async () =>
      jsonResponse({ error: { code: "user_search_unsupported" } }, 502);
    mount(true);
    await userRow();
    await listingReady();
    const oldPages = requests.filter(
      (request) => request.path === `/targets/${PEER}/users`,
    ).length;
    await searchFor("outside first page");
    await screen.findByText("users.searchUnsupportedHint");
    await listingReady();
    expect(searchRequests()[0].path).toBe(`/targets/${PEER}/users/search`);
    expect(
      requests.filter((request) => request.path === `/targets/${PEER}/users`),
    ).toHaveLength(oldPages);
    expect(requests.some((request) => request.path === "/proxy/users")).toBe(
      false,
    );
    fireEvent.click(namedButton("users.searchClear"));
    await userRow();
    await listingReady();
    expect(
      requests.filter((request) => request.path === `/targets/${PEER}/users`),
    ).toHaveLength(oldPages + 1);
    expect(searchRequests()).toHaveLength(1);
  });

  it("stops opaque pagination at a changed revision and explicitly restarts from the first page", async () => {
    const cursor = `us1_${"A".repeat(98)}`;
    const matches = Array.from({ length: 25 }, (_, index) => ({
      ...user(),
      id: String.fromCharCode(65 + index) + "A".repeat(21),
    }));
    onSearch = async (url) =>
      url.searchParams.has("after")
        ? jsonResponse({ error: { code: "user_search_changed" } }, 409)
        : revision === "10"
          ? jsonResponse({ revision, items: [], next_cursor: null })
          : jsonResponse({ revision, items: matches, next_cursor: cursor });
    mount();
    await userRow();
    await listingReady();
    await searchFor("same name");
    const next = () => screen.getByText("users.next").closest("button")!;
    await waitFor(() => expect(next().disabled).toBe(false));
    expect(next().tagName).toBe("BUTTON");
    fireEvent.click(next());
    await screen.findByText("users.searchChangedHint");
    await listingReady();
    expect(searchRequests()).toHaveLength(2);
    expect(new URLSearchParams(searchRequests()[1].query).get("after")).toBe(
      cursor,
    );
    expect(next().disabled).toBe(true);
    revision = "10";
    fireEvent.click(namedButton("users.readAgain"));
    await waitFor(() => expect(searchRequests()).toHaveLength(3));
    await listingReady();
    expect(new URLSearchParams(searchRequests()[2].query).has("after")).toBe(
      false,
    );
    expect(screen.queryByText("users.searchChangedHint")).toBeNull();
    expect(mutations()).toHaveLength(0);
  });

  it("cancels replaced queries and ignores late results even when the transport ignores abort", async () => {
    const late = deferred<Response>();
    onSearch = async (url) =>
      url.searchParams.get("q") === "old query"
        ? late.promise
        : jsonResponse({
            revision,
            items: [{ ...user(), id: OTHER_USER, name: "New search result" }],
            next_cursor: null,
          });
    mount();
    await userRow();
    await listingReady();
    await searchFor("old query");
    await waitFor(() => expect(searchRequests()).toHaveLength(1));
    await searchFor("new query");
    await screen.findByText("New search result");
    await listingReady();
    expect(searchRequests()[0].signal?.aborted).toBe(true);
    await act(async () =>
      late.resolve(
        jsonResponse({
          revision,
          items: [{ ...user(), name: "Late obsolete result" }],
          next_cursor: null,
        }),
      ),
    );
    expect(screen.queryByText("Late obsolete result")).toBeNull();
    expect(screen.getByText("New search result")).toBeTruthy();
    expect(mutations()).toHaveLength(0);
  });

  it("does not unlock an unknown write after searching, clearing or successfully reading another row", async () => {
    onWrite = localUserWrite(async () => jsonResponse({}, 200));
    onSearch = async () =>
      jsonResponse({
        revision,
        items: [{ ...user(), id: OTHER_USER, name: "Search fixture" }],
        next_cursor: null,
      });
    mount();
    await createUser();
    await screen.findByText("users.operationUnknown");
    await searchFor("Search fixture");
    await screen.findByText("Search fixture", { selector: "strong" });
    await listingReady();
    expect(namedButton("users.create").disabled).toBe(true);
    fireEvent.click(namedButton("users.searchClear"));
    await userRow();
    await listingReady();
    expect(screen.getByText("users.operationUnknown")).toBeTruthy();
    expect(namedButton("users.create").disabled).toBe(true);
    expect(mutations().map(({ path }) => path)).toEqual([
      OPERATIONS,
      `${OPERATIONS}/${OPERATION}/execute`,
    ]);
  });

  it("drops a late remote query after a scope change without searching the local node", async () => {
    const late = deferred<Response>();
    onSearch = async () => late.promise;
    mount(true);
    await userRow();
    await listingReady();
    await searchFor("remote draft");
    await waitFor(() => expect(searchRequests()).toHaveLength(1));
    fireEvent.click(namedButton("test.local"));
    await userRow();
    await listingReady();
    expect(searchRequests()[0].signal?.aborted).toBe(true);
    await act(async () =>
      late.resolve(
        jsonResponse({
          revision,
          items: [{ ...user(), name: "Late remote result" }],
          next_cursor: null,
        }),
      ),
    );
    expect(screen.queryByText("Late remote result")).toBeNull();
    expect(searchRequests()).toHaveLength(1);
    expect(
      (screen.getByLabelText("users.searchQuery") as HTMLInputElement).value,
    ).toBe("");
    expect(mutations()).toHaveLength(0);
  });
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function Harness() {
  navigation.action = useNavigationType();
  const selectScope = useScopeNavigation();
  const { controller } = useManagement();
  return (
    <>
      <button onClick={() => selectScope(scopeHref("/users", null))}>
        test.local
      </button>
      <button onClick={() => selectScope(scopeHref("/users", PEER))}>
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
const mutations = () => requests.filter((request) => request.method !== "GET");
// Identify a caption cheaply, then keep the real role/name/visibility check in
// its smallest parent. A page-wide role lookup computes names for every button.
function namedButton(name: string) {
  const matches = new Set<HTMLButtonElement>();
  for (const caption of screen.queryAllByText(name, { exact: true })) {
    const control = caption.closest("button");
    const parent = control?.parentElement;
    if (
      control instanceof HTMLButtonElement &&
      parent &&
      within(parent).queryAllByRole("button", { name }).includes(control)
    )
      matches.add(control);
  }
  const [control] = matches;
  if (matches.size !== 1 || !control)
    throw new Error("Expected one accessible fixture button");
  return control;
}
async function userRow(id = USER) {
  const identity = await screen.findByText(id);
  const row = identity.closest("tr");
  expect(row).not.toBeNull();
  return row!;
}
async function rowAction(row: HTMLElement, action: string) {
  const direct = within(row).queryByRole("button", { name: action });
  if (direct) {
    await waitFor(() =>
      expect((direct as HTMLButtonElement).disabled).toBe(false),
    );
    return { source: direct, item: direct };
  }
  const source = within(row).getByRole("button", { name: "users.moreActions" });
  await waitFor(() =>
    expect((source as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.click(source);
  const item = await screen.findByRole("menuitem", { name: action });
  await waitFor(() =>
    expect(item.getAttribute("aria-disabled")).not.toBe("true"),
  );
  return { source, item };
}
async function openUserReview(action: string, id = USER) {
  const { item } = await rowAction(await userRow(id), action);
  fireEvent.click(item);
  return screen.findByRole("dialog");
}
async function openCredentials() {
  const row = await userRow();
  const button = within(row).getByRole("button", {
    name: "users.credentials",
  });
  await waitFor(() =>
    expect((button as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.click(button);
  return screen.findByRole("dialog");
}

it("consumes Enter activation before focus moves from a menu item into the editor", async () => {
  mount();
  await listingReady();
  const { source, item } = await rowAction(await userRow(), "users.edit");
  const region = source.closest("section")!;
  item.focus();
  const enter = createEvent.keyDown(item, {
    key: "Enter",
    code: "Enter",
    keyCode: 13,
    which: 13,
  });
  fireEvent(item, enter);
  expect(enter.defaultPrevented).toBe(true);
  const dialog = await screen.findByRole("dialog", { name: "users.edit" });
  expect(mutations()).toHaveLength(0);
  fireEvent.click(within(dialog).getByRole("button", { name: "users.cancel" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await returnedFocus(source, region);
});

it.each([
  ["users.credentials", "关闭"],
  ["users.edit", "users.cancel"],
  ["resources.permission", "关闭"],
  ["presets.title", "关闭"],
  ["users.create", "users.cancel"],
] as const)(
  "returns %s dismissal to its control or scoped list without writing",
  async (action, cancel) => {
    mount();
    await listingReady();
    const { source, item } =
      action === "users.create"
        ? { source: namedButton(action), item: namedButton(action) }
        : await rowAction(await userRow(), action);
    const region = source.closest("section")!;
    fireEvent.click(item);
    const dialog = await screen.findByRole("dialog");
    await waitFor(() =>
      expect(dialog.querySelector(".ant-btn-loading")).toBeNull(),
    );
    const close = within(dialog).getByRole("button", { name: cancel });
    close.focus();
    fireEvent.click(close);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await returnedFocus(source, region);
    if (source.isConnected && !source.hasAttribute("disabled"))
      expect(document.activeElement).toBe(source);
    expect(mutations()).toHaveLength(0);
  },
);

async function openCredentialReview(drawer: HTMLElement, action: string) {
  const button = await within(drawer).findByRole("button", { name: action });
  await waitFor(() =>
    expect((button as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.click(button);
  return waitFor(() => {
    const dialog = screen
      .getAllByRole("dialog")
      .find((element) => element !== drawer);
    expect(dialog).toBeTruthy();
    return dialog!;
  });
}
function reviewField(dialog: HTMLElement, label: string) {
  const row = within(dialog).getByText(label).closest("tr");
  expect(row).not.toBeNull();
  return within(row!);
}
async function returnedFocus(source: HTMLElement, region: HTMLElement) {
  await waitFor(() => {
    const focused = document.activeElement;
    expect(focused?.isConnected).toBe(true);
    expect(focused).not.toBe(document.body);
    expect(focused === source || focused === region).toBe(true);
  });
}
async function createUser() {
  const create = await waitFor(() => namedButton("users.create"));
  await waitFor(() => expect(create.disabled).toBe(false));
  fireEvent.click(create);
  const dialog = await screen.findByRole("dialog", { name: "users.create" });
  fireEvent.change(within(dialog).getByLabelText("users.name"), {
    target: { value: "New fixture user" },
  });
  fireEvent.click(within(dialog).getByRole("button", { name: "users.save" }));
}
async function readLatest() {
  const previous = requests.filter((request) =>
    request.path.endsWith("/policy"),
  ).length;
  await screen.findAllByText("users.readLatest");
  const latest = () => {
    for (const caption of screen.getAllByText("users.readLatest")) {
      const container = caption.closest("button")?.parentElement;
      const button = container
        ? within(container).queryByRole("button", { name: "users.readLatest" })
        : null;
      if (button) return button;
    }
    throw new Error("Latest-state control is unavailable");
  };
  await act(async () => {
    fireEvent.click(latest());
  });
  await waitFor(() =>
    expect(
      requests.filter((request) => request.path.endsWith("/policy")).length,
    ).toBeGreaterThan(previous),
  );
  await waitFor(() =>
    expect((latest() as HTMLButtonElement).disabled).toBe(false),
  );
}

describe("selected proxy service visibility", () => {
  it.each([
    [false, false],
    [false, true],
    [true, false],
    [true, true],
  ])(
    "shows the stopped warning only for the selected stopped node (remote=%s, running=%s)",
    async (remote, running) => {
      const path = remote ? `/targets/${PEER}/policy` : "/proxy/policy";
      onRead = (requested) =>
        requested === path
          ? Promise.resolve(
              jsonResponse({
                ...(remote ? remotePolicy() : policy()),
                proxy_running: running,
                applied_revision: running ? revision : null,
              }),
            )
          : undefined;
      mount(remote);
      await listingReady();
      expect(!!screen.queryByText("users.proxyNotStarted")).toBe(!running);
      expect(!!screen.queryByText("users.proxyNotStartedHint")).toBe(!running);
      expect(
        screen.getByText(running ? "users.running" : "users.apiOnly"),
      ).toBeTruthy();
      expect(!!screen.queryByRole("link", { name: "service.start" })).toBe(
        !remote && !running,
      );
      expect(screen.queryByText("users.savedRevision")).toBeNull();
      expect(screen.getByText("users.admissionHint")).toBeTruthy();
      expect(mutations()).toHaveLength(0);
    },
  );

  it.each([false, true])(
    "expands observed policy details without making requests (remote=%s)",
    async (remote) => {
      mount(remote);
      await listingReady();
      const before = requests.length;
      fireEvent.click(screen.getByRole("button", { name: "users.policy" }));
      expect(await screen.findByText("users.savedRevision")).toBeTruthy();
      expect(screen.getByText("users.appliedRevision")).toBeTruthy();
      expect(screen.getByText("users.durableRevision")).toBeTruthy();
      expect(screen.getByText("users.userCount")).toBeTruthy();
      expect(screen.getByText("users.credentialCount")).toBeTruthy();
      expect(screen.getByText("users.revisionHint")).toBeTruthy();
      expect(requests).toHaveLength(before);
      expect(mutations()).toHaveLength(0);
    },
  );

  it.each([
    [null, "users.degraded"],
    ["8", "users.pending"],
  ] as const)(
    "keeps a non-current runtime visible with details collapsed (%s)",
    async (applied, caption) => {
      onRead = (requested) =>
        requested === "/proxy/policy"
          ? Promise.resolve(
              jsonResponse({
                ...policy(),
                proxy_running: true,
                applied_revision: applied,
              }),
            )
          : undefined;
      mount();
      await listingReady();
      expect(screen.getByText(caption)).toBeTruthy();
      expect(screen.queryByText("users.savedRevision")).toBeNull();
      expect(screen.queryByText("users.running")).toBeNull();
      expect(screen.queryByRole("link", { name: "service.start" })).toBeNull();
      expect(mutations()).toHaveLength(0);
    },
  );
});

describe("safe next steps after user and credential mutations", () => {
  function savedLocalCreation() {
    const created = {
      ...user(),
      id: OTHER_USER,
      name: "New fixture user",
      revision: "10",
    };
    onWrite = localUserWrite(async () => {
      revision = "10";
      users = [created];
      return jsonResponse({
        id: OPERATION,
        node_id: LOCAL,
        sequence: "1",
        expected_revision: "9",
        expected_epoch: "1",
        action: "create_user",
        user_id: OTHER_USER,
        state: "saved",
        saved_revision: "10",
        rejection: null,
      });
    });
    onSearch = async () =>
      jsonResponse({ revision, items: [created], next_cursor: null });
    onRead = (path) =>
      path === "/proxy/credentials"
        ? Promise.resolve(
            jsonResponse({ revision, items: [], next_cursor: null }),
          )
        : undefined;
  }

  it("continues a freshly saved local user directly to credential review without another write or manual reset", async () => {
    savedLocalCreation();
    const create = onWrite;
    const credentialReply = deferred<Response>();
    onWrite = (path, init) =>
      path.endsWith("/credentials")
        ? credentialReply.promise
        : create(path, init);
    mount();
    await createUser();
    const drawer = await screen.findByRole("dialog", {
      name: "users.credentialsFor",
    });
    const next = await within(drawer).findByRole("button", {
      name: "users.createCredentialAndConnect",
    });
    await waitFor(() =>
      expect((next as HTMLButtonElement).disabled).toBe(false),
    );
    expect(mutations()).toHaveLength(2);
    expect(
      next.compareDocumentPosition(
        within(drawer).getByText("users.operationSaved"),
      ) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    await act(async () => {
      fireEvent.click(next);
      fireEvent.click(next);
    });
    const review = screen.getByRole("dialog", {
      name: "users.createCredential",
    });
    expect(
      reviewField(review, "users.reviewUser").getByText(OTHER_USER),
    ).toBeTruthy();
    expect(mutations()).toHaveLength(2);
    fireEvent.click(
      within(review).getByRole("button", { name: "users.cancel" }),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("dialog", { name: "users.createCredential" }),
      ).toBeNull(),
    );
    const reopened = await openCredentialReview(
      drawer,
      "users.createCredentialAndConnect",
    );
    const submit = within(reopened).getByRole("button", {
      name: "users.createCredential",
    });
    await waitFor(() =>
      expect((submit as HTMLButtonElement).disabled).toBe(false),
    );
    await act(async () => {
      fireEvent.click(submit);
      fireEvent.click(submit);
    });
    const credentials = mutations().filter((request) =>
      request.path.endsWith("/credentials"),
    );
    expect(credentials).toHaveLength(1);
    expect(credentials[0]).toMatchObject({
      path: `/proxy/users/${OTHER_USER}/credentials`,
      body: { expected_revision: "10" },
    });
    expect(
      mutations().filter((request) => request.path === OPERATIONS),
    ).toHaveLength(1);
  });

  it.each(["policy", "owner", "credentials"] as const)(
    "keeps the saved-user continuation blocked when its %s observation changes, including the old enabled handler",
    async (changed) => {
      savedLocalCreation();
      mount();
      await createUser();
      const drawer = await screen.findByRole("dialog", {
        name: "users.credentialsFor",
      });
      const next = await within(drawer).findByRole("button", {
        name: "users.createCredentialAndConnect",
      });
      await waitFor(() =>
        expect((next as HTMLButtonElement).disabled).toBe(false),
      );
      const pending = deferred<Response>();
      const previousRead = onRead;
      onRead = (path) => {
        if (
          path ===
          (changed === "credentials" ? "/proxy/credentials" : "/proxy/policy")
        )
          return pending.promise;
        if (changed === "owner" && path === "/proxy/owner")
          return Promise.resolve(
            jsonResponse({
              controller_node_id: null,
              epoch: "2",
              last_terminal_command: "0",
            }),
          );
        return previousRead(path);
      };
      if (changed === "policy") revision = "11";
      const refresh = await within(drawer).findByRole("button", {
        name: changed === "credentials" ? "users.refresh" : "users.readLatest",
      });
      await act(async () => {
        fireEvent.click(refresh);
        fireEvent.click(next);
      });
      expect(
        screen.queryByRole("dialog", { name: "users.createCredential" }),
      ).toBeNull();
      expect(mutations()).toHaveLength(2);
      await act(async () =>
        pending.resolve(
          changed === "credentials"
            ? jsonResponse({ revision: "9", items: [], next_cursor: null })
            : jsonResponse(policy()),
        ),
      );
      const blocked = await screen.findByRole("button", {
        name: "users.createCredentialAndConnect",
      });
      await waitFor(() =>
        expect((blocked as HTMLButtonElement).disabled).toBe(true),
      );
      expect(screen.getByText("users.operationSaved")).toBeTruthy();
      expect(mutations()).toHaveLength(2);
    },
  );

  it("shows a maintenance ticket without user replay controls and refreshes its exact retained job", async () => {
    currentJob = Object.assign(ticket(), { maintenance: { accepting: false } });
    onWrite = async (path, init) => {
      expect(path).toBe(`/targets/${PEER}/maintenance/commands/refresh`);
      expect(JSON.parse(String(init.body))).toEqual({ job_id: JOB });
      return jsonResponse(currentJob);
    };
    mount(true);
    await userRow();
    const panel = await screen.findByRole("region", {
      name: "control.command",
    });
    expect(within(panel).getByText("maintenance.paused")).toBeTruthy();
    expect(
      within(panel).queryByRole("button", { name: "control.retry" }),
    ).toBeNull();
    expect(
      within(panel).queryByRole("button", { name: "control.supersede" }),
    ).toBeNull();
    const refresh = within(panel).getByRole("button", {
      name: "control.refresh",
    });
    await waitFor(() =>
      expect((refresh as HTMLButtonElement).disabled).toBe(false),
    );
    await act(async () => {
      fireEvent.click(refresh);
      fireEvent.click(refresh);
    });
    await waitFor(() =>
      expect((refresh as HTMLButtonElement).disabled).toBe(false),
    );
    const posts = requests.filter((request) => request.method === "POST");
    expect(posts).toHaveLength(1);
    expect(posts[0]).toMatchObject({
      path: `/targets/${PEER}/maintenance/commands/refresh`,
      body: { job_id: JOB },
    });
  });
  it.each(["create", "rotate"] as const)(
    "hands a successful remote credential %s to one secret modal without reloading the background drawer",
    async (action) => {
      const secret = "A".repeat(43);
      const returnedCredential = {
        ...credential(),
        ...(action === "create"
          ? { id: OTHER_JOB, login: `vp2_${"04".repeat(16)}` }
          : { verifier_revision: "2" }),
      };
      const modalPolicy = deferred<Response>();
      let postWrite = false;
      let postWritePolicyReads = 0;
      onRead = (path) => {
        if (path === `/targets/${PEER}/policy` && postWrite) {
          postWritePolicyReads++;
          if (postWritePolicyReads === 2) return modalPolicy.promise;
        }
        if (path === `/targets/${PEER}/proxy/presets`)
          return Promise.resolve(
            jsonResponse({ ...capabilityFixture(), node_id: PEER }),
          );
        if (path === `/targets/${PEER}/proxy/users/${USER}/presets`)
          return Promise.resolve(
            jsonResponse({
              revision,
              presets: {
                user_id: USER,
                default_preset: null,
                allowed_presets: [],
              },
            }),
          );
        if (path === `/targets/${PEER}/proxy/users/${USER}/routing`)
          return Promise.resolve(
            jsonResponse({
              revision,
              permission: {
                user_id: USER,
                legacy_allowed: true,
                exits: [],
                pools: [],
              },
            }),
          );
        if (path === `/targets/${PEER}/proxy/endpoints`)
          return Promise.resolve(
            jsonResponse({
              node_id: PEER,
              proxy_running: true,
              listeners: [
                {
                  protocol: "http",
                  bind: "127.0.0.1:28080",
                  public_address: "proxy.example:18080",
                },
                {
                  protocol: "https",
                  bind: "127.0.0.1:28443",
                  public_address: "proxy.example:18443",
                },
                {
                  protocol: "socks5",
                  bind: "127.0.0.1:21080",
                  public_address: "proxy.example:11080",
                },
              ],
            }),
          );
        return undefined;
      };
      onWrite = async (path) => {
        expect(path).toBe(`/targets/${PEER}/commands`);
        postWrite = true;
        revision = "10";
        lastCommand = "8";
        currentJob = ticket("saved");
        return jsonResponse({
          job: currentJob,
          response: {
            receipt: {
              controller_epoch: "2",
              command_id: "8",
              status: "saved",
              policy_revision: "10",
              rejection: null,
              user_id: USER,
              credential_id: returnedCredential.id,
            },
            replayed: false,
            user: user(),
            credential: returnedCredential,
            secret,
            secret_available: true,
          },
        });
      };
      mount(true);
      const drawer = await openCredentials();
      const caption =
        action === "create" ? "users.createCredential" : "users.rotate";
      const review = await openCredentialReview(drawer, caption);
      fireEvent.click(within(review).getByRole("button", { name: caption }));
      const modal = await screen.findByRole("dialog", {
        name: "users.secretTitle",
      });
      await waitFor(() => expect(postWritePolicyReads).toBe(2));
      const credentialReads = () =>
        requests.filter(
          (request) => request.path === `/targets/${PEER}/credentials`,
        );
      // The first read opened the drawer. The handoff must not mount a second
      // credential consumer while the real modal's serial snapshot is pending.
      expect(credentialReads()).toHaveLength(1);
      expect(
        screen.queryByRole("dialog", { name: "users.credentialsFor" }),
      ).toBeNull();
      expect(screen.getAllByRole("dialog")).toEqual([modal]);
      const password = within(modal).getByLabelText(
        "users.secret",
      ) as HTMLInputElement;
      expect(password.value).toBe(secret);
      password.focus();
      await act(async () => modalPolicy.resolve(jsonResponse(remotePolicy())));
      await within(modal).findByText("connections.notTested");
      const generate = within(modal).getByRole("button", {
        name: "presets.generate",
      });
      await waitFor(() =>
        expect((generate as HTMLButtonElement).disabled).toBe(false),
      );
      expect(modal.contains(document.activeElement)).toBe(true);
      fireEvent.click(generate);
      await within(modal).findByText("http://proxy.example:18080", {
        selector: "code",
      });
      expect(password.value).toBe(secret);
      expect(credentialReads()).toHaveLength(1);
      expect(mutations()).toHaveLength(1);
      expect(mutations()[0].body).toEqual({
        expected_target_revision: "3",
        controller_epoch: "2",
        command_id: "8",
        expected_policy_revision: "9",
        mutation:
          action === "create"
            ? { action: "create_credential", user_id: USER }
            : { action: "rotate_credential", id: CREDENTIAL },
      });
    },
  );

  it.each([403, 409, 503])(
    "keeps post-dispatch generic storage %i unknown after a successful read",
    async (status) => {
      onWrite = localUserWrite(async () => {
        revision = "10";
        return jsonResponse(
          {
            error: {
              code:
                status === 403
                  ? "policy_denied"
                  : status === 409
                    ? "policy_conflict"
                    : "policy_busy",
            },
          },
          status,
        );
      });
      mount();
      await createUser();
      await screen.findByText("users.operationUnknown");
      if (status === 503) {
        const notice = screen
          .getByText("users.operationUnknown")
          .closest(".ant-alert")!;
        expect(
          within(notice as HTMLElement).queryByText("users.operationOnLocal"),
        ).toBeNull();
        expect(
          screen
            .getByText("users.operationUnknownHint")
            .closest(".ant-collapse"),
        ).toBeNull();
        fireEvent.click(
          within(notice as HTMLElement).getByText("users.operationDetails"),
        );
        await within(notice as HTMLElement).findByText(
          "users.operationOnLocal",
        );
      }
      expect(mutations().map(({ path }) => path)).toEqual([
        OPERATIONS,
        `${OPERATIONS}/${OPERATION}/execute`,
      ]);
      expect(screen.queryByRole("dialog")).toBeNull();
      await readLatest();
      await screen.findByText("users.operationUnknown");
      const create = namedButton("users.create");
      expect((create as HTMLButtonElement).disabled).toBe(true);
      fireEvent.click(create);
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(
        screen.queryByRole("button", {
          name: "users.reviewNewOperation",
        }),
      ).toBeNull();
      expect(mutations()).toHaveLength(2);
    },
  );

  it("preserves unknown write evidence when its follow-up read also fails", async () => {
    onWrite = localUserWrite(async () => {
      throw new TypeError("Lost first response");
    });
    mount();
    await createUser();
    await screen.findByText("users.operationUnknown");
    readFailure = true;
    await readLatest();
    await screen.findByText("users.operationUnknown");
    expect(mutations().map(({ path }) => path)).toEqual([
      OPERATIONS,
      `${OPERATIONS}/${OPERATION}/execute`,
    ]);
    expect(namedButton("users.create").disabled).toBe(true);
  });

  it("does not claim a competing latest ticket after the remote first response is lost", async () => {
    onWrite = async () => {
      currentJob = ticket("applied", OTHER_JOB);
      lastCommand = "8";
      revision = "10";
      throw new TypeError("Lost first response");
    };
    mount(true);
    await createUser();
    await screen.findByText("users.operationUnknown");
    const notice = () => {
      const alert = screen
        .getByText("users.operationUnknown")
        .closest<HTMLElement>(".ant-alert");
      expect(alert?.isConnected).toBe(true);
      return within(alert!);
    };
    const command = () => {
      const card = screen
        .getByText("control.command")
        .closest<HTMLElement>(".ant-pro-card");
      expect(card?.isConnected).toBe(true);
      return within(card!);
    };
    const latest = () => {
      const button = notice().getByRole("button", { name: "users.readLatest" });
      expect(button.tagName).toBe("BUTTON");
      return button as HTMLButtonElement;
    };
    const ticketReads = () =>
      requests.filter((request) => request.path === `/targets/${PEER}/command`);
    const policyReads = () =>
      requests.filter((request) => request.path === `/targets/${PEER}/policy`);
    const userReads = () =>
      requests.filter((request) => request.path === `/targets/${PEER}/users`);
    const recent = notice().getByRole("button", {
      name: "users.readRecentTask",
    });
    expect(recent.tagName).toBe("BUTTON");
    expect((recent as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(recent);
    const readTicket = command().getByRole("button", {
      name: "control.readTicket",
    });
    expect(readTicket.tagName).toBe("BUTTON");
    expect((readTicket as HTMLButtonElement).disabled).toBe(false);
    const previousTickets = ticketReads().length;
    fireEvent.click(readTicket);
    // Starting a GET is not completion. Wait for the actual ticket and its
    // controls before making a separate, explicit snapshot read.
    await waitFor(() => {
      expect(ticketReads()).toHaveLength(previousTickets + 1);
      expect(command().getByText(OTHER_JOB)).toBeTruthy();
      const button = command().getByRole("button", {
        name: "control.readTicket",
      }) as HTMLButtonElement;
      expect(button.disabled).toBe(false);
      expect(button.querySelector(".ant-btn-loading-icon")).toBeNull();
      expect(latest().disabled).toBe(false);
    });
    const previousPolicies = policyReads().length;
    const previousUsers = userReads().length;
    fireEvent.click(latest());
    await waitFor(() => {
      expect(policyReads()).toHaveLength(previousPolicies + 1);
      expect(userReads()).toHaveLength(previousUsers + 1);
      expect(latest().disabled).toBe(false);
      const refresh = screen.getByText("users.refresh").closest("button");
      expect(refresh?.isConnected).toBe(true);
      expect(refresh!.querySelector(".ant-btn-loading-icon")).toBeNull();
      expect(refresh!.disabled).toBe(false);
    });
    const currentRow = await userRow();
    expect(currentRow.isConnected).toBe(true);
    expect(within(currentRow).getByText("Existing user")).toBeTruthy();
    await screen.findByText("users.operationUnknown");
    expect(
      screen.queryByRole("button", {
        name: "users.reviewNewOperation",
      }),
    ).toBeNull();
    expect(mutations()).toHaveLength(1);
  });

  it("accepts a terminal 202 ticket without recovering a secret or resending the command", async () => {
    onWrite = async () => {
      currentJob = ticket("saved");
      revision = "10";
      lastCommand = "8";
      return jsonResponse({ job: currentJob, response: null }, 202);
    };
    mount(true);
    await createUser();
    await screen.findByText("users.operationFinished");
    expect(mutations()).toHaveLength(1);
    await readLatest();
    const review = await waitFor(() => namedButton("users.reviewNewOperation"));
    fireEvent.click(review);
    await waitFor(() =>
      expect(namedButton("users.create").disabled).toBe(false),
    );
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(mutations()).toHaveLength(1);
  });

  it("requires a fresh read and an explicit new-operation action after reservation preparation fails", async () => {
    onWrite = async (path) => {
      if (path !== OPERATIONS)
        throw new Error(`Unexpected fixture mutation ${path}`);
      return jsonResponse({ error: { code: "invalid_json" } }, 400);
    };
    mount();
    await createUser();
    await screen.findByText("users.operationPreparationFailed");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(
      screen.queryByRole("button", {
        name: "users.reviewNewOperation",
      }),
    ).toBeNull();
    await readLatest();
    fireEvent.click(
      await waitFor(() => namedButton("users.reviewNewOperation")),
    );
    await waitFor(() =>
      expect(namedButton("users.create").disabled).toBe(false),
    );
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(mutations().map(({ path }) => path)).toEqual([OPERATIONS]);
  });

  it.each(["policy", "command"])(
    "does not mark a consistent but lagging %s observation fresh",
    async (lag) => {
      onWrite = async () => {
        currentJob = ticket("saved");
        revision = lag === "policy" ? "9" : "10";
        lastCommand = lag === "command" ? "7" : "8";
        return jsonResponse({ job: currentJob, response: null }, 202);
      };
      mount(true);
      await createUser();
      await screen.findByText("users.operationFinished");
      await readLatest();
      expect(
        screen.queryByRole("button", { name: "users.reviewNewOperation" }),
      ).toBeNull();
      revision = "10";
      lastCommand = "8";
      await readLatest();
      await waitFor(() => namedButton("users.reviewNewOperation"));
      expect(mutations()).toHaveLength(1);
    },
  );

  it("does not replace a known pending attempt with a different terminal latest ticket", async () => {
    onWrite = async () => {
      currentJob = ticket();
      return jsonResponse({ job: currentJob, response: null }, 202);
    };
    mount(true);
    await createUser();
    await screen.findByText("users.operationPending");
    currentJob = ticket("applied", OTHER_JOB);
    revision = "10";
    lastCommand = "8";
    await readLatest();
    expect(
      screen.queryByRole("button", {
        name: "users.reviewNewOperation",
      }),
    ).toBeNull();
    expect(screen.queryByText("users.operationFinished")).toBeNull();
    expect(namedButton("users.create").disabled).toBe(true);
    expect(mutations()).toHaveLength(1);
  });

  it("locks credential creation, rotation and state changes after losing a one-time result", async () => {
    onWrite = async () => {
      revision = "10";
      return new Response("{", {
        status: 201,
        headers: { "Content-Type": "application/json" },
      });
    };
    mount();
    const drawer = await openCredentials();
    const create = within(drawer).getByRole("button", {
      name: "users.createCredential",
    });
    await waitFor(() =>
      expect((create as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(create);
    const confirmation = screen
      .getAllByRole("dialog")
      .find((element) => element !== drawer)!;
    fireEvent.click(
      within(confirmation).getByRole("button", {
        name: "users.createCredential",
      }),
    );
    await screen.findByText("users.operationUnknown");
    expect(screen.getAllByText("users.operationUnknown")).toHaveLength(1);
    expect(mutations()).toHaveLength(1);
    const previousPolicyReads = requests.filter(
      (request) => request.path === "/proxy/policy",
    ).length;
    const previousCredentialReads = requests.filter(
      (request) => request.path === "/proxy/credentials",
    ).length;
    const notice = screen
      .getByText("users.operationUnknown")
      .closest(".ant-alert")!;
    await act(async () => {
      fireEvent.click(
        within(notice as HTMLElement).getByRole("button", {
          name: "users.readLatest",
        }),
      );
    });
    let currentDrawer: HTMLElement | null = null;
    await waitFor(() => {
      expect(
        requests.filter((request) => request.path === "/proxy/policy").length,
      ).toBeGreaterThan(previousPolicyReads);
      expect(
        requests.filter((request) => request.path === "/proxy/credentials")
          .length,
      ).toBeGreaterThan(previousCredentialReads);
      // Parent reads remount the drawer. Query its current notice, then wait
      // for its own credential response rather than mistaking loading for a lock.
      currentDrawer = screen
        .getByText("users.operationUnknown")
        .closest('[role="dialog"]') as HTMLElement | null;
      expect(currentDrawer?.isConnected).toBe(true);
      expect(currentDrawer?.getAttribute("role")).toBe("dialog");
      const current = within(currentDrawer!);
      expect(
        (
          current.getByRole("button", {
            name: "users.readLatest",
          }) as HTMLButtonElement
        ).disabled,
      ).toBe(false);
      expect(
        current
          .getByRole("button", { name: "users.refresh" })
          .classList.contains("ant-btn-loading"),
      ).toBe(false);
      expect(current.getByText(credential().login)).toBeTruthy();
    });
    for (const name of [
      "users.createCredential",
      "users.rotate",
      "users.disable",
    ]) {
      const button = within(currentDrawer!).getByRole("button", {
        name,
      });
      expect((button as HTMLButtonElement).disabled).toBe(true);
      fireEvent.click(button);
    }
    expect(screen.queryByText("users.secretTitle")).toBeNull();
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    expect(mutations()).toHaveLength(1);
  });

  it.each(["registration", "owner"])(
    "does not release an acknowledged attempt after its %s scope changes",
    async (change) => {
      onWrite = async () => {
        currentJob = ticket("saved");
        revision = "10";
        lastCommand = "8";
        return jsonResponse({ job: currentJob, response: null }, 202);
      };
      mount(true);
      await createUser();
      await screen.findByText("users.operationFinished");
      if (change === "registration") targetRevision = "4";
      else controllerEpoch = "3";
      await readLatest();
      await screen.findByText("users.operationScopeChanged");
      expect(
        screen.queryByRole("button", { name: "users.reviewNewOperation" }),
      ).toBeNull();
      expect(mutations()).toHaveLength(1);
    },
  );

  it("closes the credential drawer before focusing a remote task, without another request", async () => {
    onWrite = async () =>
      new Response("{", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    mount(true);
    const taskRegion = await screen.findByRole("region", {
      name: "control.command",
    });
    const drawer = await openCredentials();
    const confirmation = await openCredentialReview(
      drawer,
      "users.createCredential",
    );
    fireEvent.click(
      within(confirmation).getByRole("button", {
        name: "users.createCredential",
      }),
    );
    await within(drawer).findByText("users.operationUnknown");
    expect(
      within(drawer).getByText("users.operationSecretMissing"),
    ).toBeTruthy();
    const readTask = within(drawer).getByRole("button", {
      name: "users.readRecentTask",
    });
    await waitFor(() =>
      expect((readTask as HTMLButtonElement).disabled).toBe(false),
    );
    const before = requests.length;
    fireEvent.click(readTask);
    // Poll stable elements, not the whole portal's accessibility tree each time.
    await waitFor(() => expect(drawer.isConnected).toBe(false));
    await waitFor(() => expect(document.activeElement).toBe(taskRegion));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getAllByText("users.operationUnknown")).toHaveLength(1);
    expect(requests).toHaveLength(before);
    expect(mutations()).toHaveLength(1);
  });

  it.each(["node", "session", "unmount"])(
    "ignores a late mutation response after %s changes",
    async (change) => {
      const pending = deferred<Response>();
      onWrite = async () => pending.promise;
      const mounted = mount(true);
      await createUser();
      await waitFor(() => expect(mutations()).toHaveLength(1));
      const signal = mutations()[0].signal;
      if (change === "unmount") mounted.unmount();
      else
        fireEvent.click(
          screen.getByRole("button", {
            name: change === "node" ? "test.local" : "test.session",
          }),
        );
      await waitFor(() => expect(signal?.aborted).toBe(true));
      await act(async () => {
        pending.resolve(
          jsonResponse({ job: ticket("saved"), response: null }, 202),
        );
      });
      if (change !== "unmount")
        await waitFor(() => namedButton("users.create"));
      expect(screen.queryByText("users.operationFinished")).toBeNull();
      expect(screen.queryByText("users.operationUnknown")).toBeNull();
      expect(mutations()).toHaveLength(1);
    },
  );
});

describe("recover one remote create result without replaying a mutation", () => {
  const recoveredUser = () => ({
    ...user(),
    id: OTHER_USER,
    name: "Recovered user",
    revision: "10",
  });
  const resultPath = `/targets/${PEER}/command/user-result`;
  const resultRequests = () =>
    requests.filter((request) => request.path === resultPath);
  function prepareResult() {
    revision = "10";
    lastCommand = "8";
    currentJob = ticket("saved", JOB, true);
    onWrite = async (path) => {
      if (path !== resultPath) throw new Error("Unexpected fixture mutation");
      return jsonResponse({ job: currentJob, user_id: OTHER_USER });
    };
    onSearch = async (url) =>
      jsonResponse({
        revision,
        items:
          url.searchParams.get("mode") === "id" ? [recoveredUser()] : users,
        next_cursor: null,
      });
    onRead = (path) =>
      path.endsWith("/credentials")
        ? Promise.resolve(
            jsonResponse({ revision, items: [], next_cursor: null }),
          )
        : undefined;
  }
  async function readResult() {
    const panel = await screen.findByRole("region", {
      name: "control.command",
    });
    const button = await within(panel).findByRole("button", {
      name: "control.readCreatedUser",
    });
    await waitFor(() =>
      expect((button as HTMLButtonElement).disabled).toBe(false),
    );
    await act(async () => {
      fireEvent.click(button);
      fireEvent.click(button);
    });
  }

  it("gates competing user reads while recovery is pending without blocking its internal refresh", async () => {
    prepareResult();
    const response = deferred<Response>();
    const commandResponse = deferred<Response>();
    const credentials = deferred<Response>();
    onWrite = async (path) =>
      path === `/targets/${PEER}/command/refresh`
        ? commandResponse.promise
        : response.promise;
    onRead = (path) => {
      if (path === `/targets/${PEER}/users`)
        return Promise.resolve(
          jsonResponse({ revision, items: users, next_cursor: USER }),
        );
      if (path.endsWith("/credentials")) return credentials.promise;
      return undefined;
    };
    mount(true);
    const row = await userRow();
    const recover = await waitFor(() => namedButton("control.readCreatedUser"));
    const refresh = namedButton("users.refresh");
    const commandRefresh = namedButton("control.refresh");
    const next = namedButton("users.next");
    const deleted = screen.getByRole("checkbox", {
      name: "users.includeDeleted",
    });
    const form = screen.getByRole("form", { name: "users.searchTitle" });
    const rowReads = ["users.credentials", "users.moreActions"].map((name) =>
      within(row).getByRole("button", { name }),
    );
    const { item: permission } = await rowAction(row, "resources.permission");
    const preset = screen.getByRole("menuitem", { name: "presets.title" });
    const rowMenuReads = [permission, preset];
    fireEvent.change(within(form).getByLabelText("users.searchQuery"), {
      target: { value: "Existing" },
    });
    await waitFor(() => {
      expect((recover as HTMLButtonElement).disabled).toBe(false);
      expect((next as HTMLButtonElement).disabled).toBe(false);
    });
    const beforeCommand = requests.length;
    await act(async () => {
      fireEvent.click(commandRefresh);
      fireEvent.click(recover);
    });
    expect(requests).toHaveLength(beforeCommand + 1);
    expect(requests.at(-1)?.path).toBe(`/targets/${PEER}/command/refresh`);
    expect(resultRequests()).toHaveLength(0);
    await act(async () => commandResponse.resolve(jsonResponse(currentJob)));
    await waitFor(() => {
      expect((commandRefresh as HTMLButtonElement).disabled).toBe(false);
      expect((recover as HTMLButtonElement).disabled).toBe(false);
    });
    const before = requests.length;
    // Exercise handlers in the same batch, before disabled props can render.
    await act(async () => {
      fireEvent.click(recover);
      fireEvent.click(commandRefresh);
      fireEvent.click(refresh);
      fireEvent.click(next);
      fireEvent.click(deleted);
      rowMenuReads.forEach((item) => fireEvent.click(item));
      rowReads.forEach((button) => fireEvent.click(button));
      fireEvent.submit(form);
    });
    expect(resultRequests()).toHaveLength(1);
    expect(requests).toHaveLength(before + 1);
    for (const button of [recover, commandRefresh, refresh, next, ...rowReads])
      expect((button as HTMLButtonElement).disabled).toBe(true);
    expect((deleted as HTMLInputElement).disabled).toBe(true);
    expect(
      (
        within(form).getByRole("button", {
          name: "users.searchSubmit",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(
      (
        screen.getByRole("combobox", {
          name: "control.scope",
        }) as HTMLInputElement
      ).disabled,
    ).toBe(false);
    await act(async () =>
      response.resolve(jsonResponse({ job: currentJob, user_id: OTHER_USER })),
    );
    const drawer = await screen.findByRole("dialog", {
      name: "users.credentialsFor",
    });
    // The newly opened drawer is now the active reader. Another recovery must
    // wait for its credential metadata read rather than cancel it and contend.
    expect((recover as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(recover);
    expect(resultRequests()).toHaveLength(1);
    await act(async () =>
      credentials.resolve(
        jsonResponse({ revision, items: [], next_cursor: null }),
      ),
    );
    await waitFor(() =>
      expect((recover as HTMLButtonElement).disabled).toBe(false),
    );
    expect(within(drawer).getByText("users.deliveryCreated")).toBeTruthy();
    expect(searchRequests()).toHaveLength(1);
    expect(mutations()).toHaveLength(2);
  });

  it.each(["reload", "known202"])(
    "finds the exact off-page user after %s and keeps credential creation explicit",
    async (entry) => {
      prepareResult();
      if (entry === "known202") {
        currentJob = null;
        revision = "9";
        lastCommand = "7";
        const recover = onWrite;
        onWrite = async (path, init) => {
          if (path !== `/targets/${PEER}/commands`) return recover(path, init);
          currentJob = ticket("saved", JOB, true);
          revision = "10";
          lastCommand = "8";
          return jsonResponse({ job: currentJob, response: null }, 202);
        };
      }
      mount(true);
      if (entry === "known202") {
        await createUser();
        await screen.findByText("users.operationFinished");
      } else {
        await userRow();
        await searchFor("Existing");
      }
      await readResult();
      const drawer = await screen.findByRole("dialog");
      expect(within(drawer).getByText("users.deliveryCreated")).toBeTruthy();
      const lookup = searchRequests().find(
        (request) => new URLSearchParams(request.query).get("mode") === "id",
      )!;
      expect(lookup.path).toBe(`/targets/${PEER}/users/search`);
      expect(new URLSearchParams(lookup.query).get("q")).toBe(OTHER_USER);
      expect(new URLSearchParams(lookup.query).get("limit")).toBe("1");
      expect(resultRequests()).toHaveLength(1);
      expect(resultRequests()[0].body).toEqual({ job_id: JOB });
      if (entry === "known202") {
        const next = await within(drawer).findByRole("button", {
          name: "users.reviewNewOperation",
        });
        await waitFor(() =>
          expect((next as HTMLButtonElement).disabled).toBe(false),
        );
        fireEvent.click(next);
      }
      const review = await openCredentialReview(
        drawer,
        "users.createCredentialAndConnect",
      );
      expect(
        reviewField(review, "users.reviewUser").getByText(OTHER_USER),
      ).toBeTruthy();
      expect(
        (
          within(review).getByRole("button", {
            name: "users.createCredential",
          }) as HTMLButtonElement
        ).disabled,
      ).toBe(false);
      expect(
        requests.filter((request) => request.path.endsWith("/commands")),
      ).toHaveLength(entry === "known202" ? 1 : 0);
      expect(mutations()).toHaveLength(entry === "known202" ? 2 : 1);
      expect(screen.queryByText("users.secretTitle")).toBeNull();
    },
  );

  it("keeps a lost submission unknown while independently inspecting a selected later create ticket", async ({
    onTestFailed,
  }) => {
    const started = performance.now();
    type Phase =
      | "mount"
      | "createUser"
      | "unknown-visible"
      | "readLatest"
      | "readResult"
      | "drawer"
      | "assertions"
      | "complete";
    const phases: { phase: Phase; elapsed_ms: number }[] = [];
    const mark = (phase: Phase) => {
      if (phases.length < 8)
        phases.push({
          phase,
          elapsed_ms: Math.max(0, Math.floor(performance.now() - started)),
        });
    };
    onTestFailed(() => {
      console.error(
        "remote_create_recovery_test_trace",
        JSON.stringify({
          elapsed_ms: Math.max(0, Math.floor(performance.now() - started)),
          phases: phases.slice(0, 8),
        }),
      );
    });
    prepareResult();
    currentJob = null;
    revision = "9";
    lastCommand = "7";
    const recover = onWrite;
    onWrite = async (path, init) => {
      if (path !== `/targets/${PEER}/commands`) return recover(path, init);
      currentJob = ticket("saved", OTHER_JOB, true);
      revision = "10";
      lastCommand = "8";
      throw new TypeError("Lost first response");
    };
    mark("mount");
    mount(true);
    mark("createUser");
    await createUser();
    mark("unknown-visible");
    await screen.findByText("users.operationUnknown");
    mark("readLatest");
    await readLatest();
    mark("readResult");
    await readResult();
    mark("drawer");
    const drawer = await screen.findByRole("dialog", {
      name: "users.credentialsFor",
    });
    mark("assertions");
    expect(within(drawer).getByText("users.operationUnknown")).toBeTruthy();
    expect(screen.queryByText("users.reviewNewOperation")).toBeNull();
    expect(
      (
        within(drawer).getByRole("button", {
          name: "users.createCredentialAndConnect",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(resultRequests()[0].body).toEqual({ job_id: OTHER_JOB });
    expect(
      requests.filter((request) => request.path.endsWith("/commands")),
    ).toHaveLength(1);
    expect(mutations()).toHaveLength(2);
    mark("complete");
  });

  it("binds a successful first create reply to the same scope even outside the current filter", async () => {
    prepareResult();
    revision = "9";
    lastCommand = "7";
    currentJob = null;
    onWrite = async (path) => {
      if (path !== `/targets/${PEER}/commands`)
        throw new Error("Unexpected fixture mutation");
      revision = "10";
      lastCommand = "8";
      currentJob = ticket("saved", JOB, true);
      return jsonResponse({
        job: currentJob,
        response: {
          receipt: {
            controller_epoch: "2",
            command_id: "8",
            status: "saved",
            policy_revision: "10",
            rejection: null,
            user_id: OTHER_USER,
            credential_id: null,
          },
          replayed: false,
          user: recoveredUser(),
          credential: null,
          secret: null,
          secret_available: false,
        },
      });
    };
    mount(true);
    await userRow();
    await searchFor("Existing");
    await createUser();
    const drawer = await screen.findByRole("dialog", {
      name: "users.credentialsFor",
    });
    const next = await within(drawer).findByRole("button", {
      name: "users.reviewNewOperation",
    });
    await waitFor(() =>
      expect((next as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(next);
    const review = await openCredentialReview(
      drawer,
      "users.createCredentialAndConnect",
    );
    expect(
      reviewField(review, "users.reviewUser").getByText(OTHER_USER),
    ).toBeTruthy();
    expect(
      (
        within(review).getByRole("button", {
          name: "users.createCredential",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(false);
    expect(resultRequests()).toHaveLength(0);
    expect(mutations()).toHaveLength(1);
  });

  it("does not use an older exact-user observation as authority for a newer policy revision", async () => {
    prepareResult();
    mount(true);
    const button = await waitFor(() => namedButton("control.readCreatedUser"));
    await waitFor(() =>
      expect((button as HTMLButtonElement).disabled).toBe(false),
    );
    const read = onRead;
    onRead = (path) => {
      if (path === `/targets/${PEER}/policy`) {
        revision = "11";
        return Promise.resolve(jsonResponse(remotePolicy()));
      }
      return read(path);
    };
    await readResult();
    const drawer = await screen.findByRole("dialog");
    const review = await openCredentialReview(
      drawer,
      "users.createCredentialAndConnect",
    );
    expect(
      (
        within(review).getByRole("button", {
          name: "users.createCredential",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(resultRequests()).toHaveLength(1);
    expect(mutations()).toHaveLength(1);
  });

  it.each([
    "wrongTicket",
    "oldRevision",
    "deleted",
    "unsupported",
    "expired",
    "denied",
  ])("does not open a user or retry after %s", async (failure) => {
    prepareResult();
    if (failure === "wrongTicket")
      onWrite = async () =>
        jsonResponse({
          job: ticket("saved", OTHER_JOB, true),
          user_id: OTHER_USER,
        });
    if (failure === "expired")
      onWrite = async () =>
        jsonResponse({ error: { code: "receipt_expired" } }, 409);
    if (failure === "denied")
      onWrite = async () =>
        jsonResponse({ error: { code: "node_control_denied" } }, 403);
    if (failure === "oldRevision")
      onSearch = async () =>
        jsonResponse({
          revision: "9",
          items: [{ ...recoveredUser(), revision: "9" }],
          next_cursor: null,
        });
    if (failure === "deleted")
      onSearch = async () =>
        jsonResponse({ revision, items: [], next_cursor: null });
    if (failure === "unsupported")
      onSearch = async () =>
        jsonResponse({ error: { code: "user_search_unsupported" } }, 502);
    mount(true);
    await readResult();
    await screen.findByText(
      failure === "denied"
        ? "control.denied"
        : failure === "expired"
          ? "control.receiptExpired"
          : failure === "unsupported"
            ? "users.searchUnsupported"
            : failure === "deleted"
              ? "users.notFound"
              : "api.format",
    );
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(resultRequests()).toHaveLength(1);
    expect(searchRequests()).toHaveLength(
      ["wrongTicket", "expired", "denied"].includes(failure) ? 0 : 1,
    );
    expect(mutations()).toHaveLength(1);
  });

  it.each(["node", "session", "unmount"])(
    "ignores a late result after %s changes the read scope",
    async (change) => {
      prepareResult();
      const response = deferred<Response>();
      onWrite = async () => response.promise;
      const mounted = mount(true);
      await readResult();
      await waitFor(() => expect(resultRequests()).toHaveLength(1));
      const signal = resultRequests()[0].signal;
      if (change === "unmount") mounted.unmount();
      else
        fireEvent.click(
          screen.getByRole("button", {
            name: change === "node" ? "test.local" : "test.session",
          }),
        );
      await waitFor(() => expect(signal?.aborted).toBe(true));
      await act(async () =>
        response.resolve(
          jsonResponse({
            job: ticket("saved", JOB, true),
            user_id: OTHER_USER,
          }),
        ),
      );
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(searchRequests()).toHaveLength(0);
      expect(mutations()).toHaveLength(1);
    },
  );

  it.each(["destination", "owner", "job"])(
    "discards the recovered user when the refreshed %s changed",
    async (change) => {
      prepareResult();
      mount(true);
      const control = await waitFor(() =>
        namedButton("control.readCreatedUser"),
      );
      await waitFor(() => expect(control.disabled).toBe(false));
      const read = onRead;
      onRead = (path) => {
        if (path === `/targets/${PEER}` && change === "destination") {
          targetRevision = "4";
          return Promise.resolve(jsonResponse(target()));
        }
        if (path === `/targets/${PEER}/policy` && change === "owner") {
          controllerEpoch = "3";
          return Promise.resolve(jsonResponse(remotePolicy()));
        }
        if (path === `/targets/${PEER}/command` && change === "job") {
          currentJob = ticket("applied", OTHER_JOB, true);
          return Promise.resolve(jsonResponse(currentJob));
        }
        return read(path);
      };
      await readResult();
      await waitFor(() => {
        expect(resultRequests()).toHaveLength(1);
        expect(searchRequests()).toHaveLength(1);
        expect(namedButton("control.readCreatedUser").disabled).toBe(false);
      });
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(mutations()).toHaveLength(1);
    },
  );
});

describe("review the exact operation before dispatch", () => {
  it("identifies the local management origin and exact same-name user, and cancels without a write", async () => {
    users = [user(), { ...user(), id: OTHER_USER }];
    mount();
    const { source, item } = await rowAction(
      await userRow(OTHER_USER),
      "users.delete",
    );
    const before = requests.length;
    fireEvent.click(item);
    const dialog = await screen.findByRole("dialog");
    const node = reviewField(dialog, "users.reviewNode");
    expect(node.getByText("users.reviewLocalNode")).toBeTruthy();
    expect(
      reviewField(dialog, "users.reviewOrigin").getByText("https://localhost"),
    ).toBeTruthy();
    expect(node.queryByText(LOCAL)).toBeNull();
    const selected = reviewField(dialog, "users.reviewUser");
    expect(selected.getByText("Existing user")).toBeTruthy();
    expect(selected.getByText(OTHER_USER)).toBeTruthy();
    expect(selected.queryByText(USER)).toBeNull();
    expect(within(dialog).getByText("users.deleteHint")).toBeTruthy();
    const confirm = within(dialog).getByRole("button", {
      name: "users.delete",
    });
    expect(document.activeElement).not.toBe(confirm);
    const cancel = within(dialog).getByRole("button", { name: "users.cancel" });
    await waitFor(() => expect(document.activeElement).toBe(cancel));
    fireEvent.click(cancel);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await returnedFocus(
      source,
      screen.getByRole("region", { name: "users.title" }),
    );
    expect(document.activeElement).not.toBe(confirm);
    expect(requests).toHaveLength(before);
    expect(mutations()).toHaveLength(0);
  });

  it("reviews the remote node and credential identity, then dispatches a double click once with the captured CAS", async () => {
    const response = deferred<Response>();
    onWrite = async () => response.promise;
    mount(true);
    const drawer = await openCredentials();
    const dialog = await openCredentialReview(drawer, "users.rotate");
    const node = reviewField(dialog, "users.reviewNode");
    expect(node.getByText("Remote fixture")).toBeTruthy();
    expect(node.getByText(PEER)).toBeTruthy();
    const parent = reviewField(dialog, "users.reviewUser");
    expect(parent.getByText("Existing user")).toBeTruthy();
    expect(parent.getByText(USER)).toBeTruthy();
    const identity = reviewField(dialog, "users.reviewCredential");
    expect(identity.getByText(credential().login)).toBeTruthy();
    expect(identity.getByText(CREDENTIAL)).toBeTruthy();
    expect(within(dialog).getByText("users.rotateHint")).toBeTruthy();
    expect(within(dialog).queryByText("users.secretTitle")).toBeNull();
    expect(dialog.querySelector('input[type="password"]')).toBeNull();
    expect(dialog.querySelector("a[href]")).toBeNull();
    const confirm = within(dialog).getByRole("button", {
      name: "users.rotate",
    });
    await act(async () => {
      fireEvent.click(confirm);
      fireEvent.click(confirm);
    });
    await waitFor(() => expect(mutations()).toHaveLength(1));
    expect(mutations()[0].path).toBe(`/targets/${PEER}/commands`);
    expect(mutations()[0].body).toEqual({
      expected_target_revision: "3",
      controller_epoch: "2",
      command_id: "8",
      expected_policy_revision: "9",
      mutation: { action: "rotate_credential", id: CREDENTIAL },
    });
    await act(async () => {
      currentJob = ticket("saved");
      revision = "10";
      lastCommand = "8";
      response.resolve(jsonResponse({ job: currentJob, response: null }, 202));
    });
    await screen.findByText("users.operationFinished");
    expect(screen.getByText("users.operationSecretMissing")).toBeTruthy();
    expect(screen.queryByText("users.secretTitle")).toBeNull();
    expect(mutations()).toHaveLength(1);
  });

  it("shows permanent credential revocation impact and returns Escape focus within its drawer without a write", async () => {
    mount(true);
    const drawer = await openCredentials();
    const source = await within(drawer).findByRole("button", {
      name: "users.revoke",
    });
    await waitFor(() =>
      expect((source as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(source);
    const dialog = await waitFor(() => {
      const confirmation = screen
        .getAllByRole("dialog")
        .find((element) => element !== drawer);
      expect(confirmation).toBeTruthy();
      return confirmation!;
    });
    expect(
      reviewField(dialog, "users.reviewCredential").getByText(CREDENTIAL),
    ).toBeTruthy();
    expect(
      reviewField(dialog, "users.reviewUser").getByText(USER),
    ).toBeTruthy();
    expect(within(dialog).getByText("users.revokeHint")).toBeTruthy();
    const before = requests.length;
    const cancel = within(dialog).getByRole("button", { name: "users.cancel" });
    await waitFor(() => expect(document.activeElement).toBe(cancel));
    fireEvent.keyDown(cancel, {
      key: "Escape",
      code: "Escape",
      keyCode: 27,
      which: 27,
    });
    await waitFor(() => expect(screen.getAllByRole("dialog")).toHaveLength(1));
    await returnedFocus(
      source,
      screen.getByRole("region", { name: "users.credentialsFor" }),
    );
    expect(document.activeElement).not.toBe(cancel);
    expect(requests).toHaveLength(before);
    expect(mutations()).toHaveLength(0);
  });

  it.each(["revision", "registration", "owner"])(
    "disables an old remote confirmation during reads and after the observed %s changes, without replacing its CAS",
    async (change) => {
      mount(true);
      const dialog = await openUserReview("users.disable");
      const refresh = namedButton("users.refresh");
      const confirm = within(dialog).getByRole("button", {
        name: "users.disable",
      });
      const result = deferred<Response>();
      onRead = (path) =>
        path === `/targets/${PEER}/policy` ? result.promise : undefined;
      if (change === "revision") revision = "10";
      else if (change === "registration") targetRevision = "4";
      else controllerNodeId = OTHER_USER;
      const previous = requests.filter((request) =>
        request.path.endsWith("/policy"),
      ).length;
      // A controlled underlay event models an observation racing the modal;
      // this is not evidence that a person can click through its overlay.
      fireEvent.click(refresh);
      await waitFor(() =>
        expect(
          requests.filter((request) => request.path.endsWith("/policy")).length,
        ).toBeGreaterThan(previous),
      );
      await waitFor(() =>
        expect((confirm as HTMLButtonElement).disabled).toBe(true),
      );
      fireEvent.click(confirm);
      expect(mutations()).toHaveLength(0);
      await act(async () => result.resolve(jsonResponse(remotePolicy())));
      await within(dialog).findByText("users.reviewChanged");
      expect((confirm as HTMLButtonElement).disabled).toBe(true);
      fireEvent.click(confirm);
      expect(mutations()).toHaveLength(0);
      fireEvent.click(
        within(dialog).getByRole("button", { name: "users.cancel" }),
      );
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    },
  );

  it("invalidates a credential preview when its list is re-read even at the same revision", async () => {
    mount();
    const drawer = await openCredentials();
    const dialog = await openCredentialReview(drawer, "users.rotate");
    const currentDrawer = screen
      .getAllByRole("dialog")
      .find((element) => element !== dialog)!;
    const refresh = within(currentDrawer).getByRole("button", {
      name: "users.refresh",
    });
    const confirm = within(dialog).getByRole("button", {
      name: "users.rotate",
    });
    const result = deferred<Response>();
    onRead = (path) =>
      path === "/proxy/credentials" ? result.promise : undefined;
    const previous = requests.filter(
      (request) => request.path === "/proxy/credentials",
    ).length;
    // As above, dispatch through the current underlay DOM, not detached nodes.
    fireEvent.click(refresh);
    await waitFor(() =>
      expect(
        requests.filter((request) => request.path === "/proxy/credentials")
          .length,
      ).toBeGreaterThan(previous),
    );
    await waitFor(() =>
      expect((confirm as HTMLButtonElement).disabled).toBe(true),
    );
    fireEvent.click(confirm);
    expect(mutations()).toHaveLength(0);
    await act(async () =>
      result.resolve(
        jsonResponse({
          revision: "9",
          items: [credential()],
          next_cursor: null,
        }),
      ),
    );
    await within(dialog).findByText("users.reviewChanged");
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(confirm);
    expect(mutations()).toHaveLength(0);
  });

  it.each(["node", "session"])(
    "discards an unsubmitted confirmation and ignores its late read after the %s changes",
    async (change) => {
      mount(true);
      await openUserReview("users.delete");
      const oldRegion = screen.getByRole("region", { name: "users.title" });
      const oldSource = within(oldRegion).getByRole("button", {
        name: "users.moreActions",
      });
      const refresh = namedButton("users.refresh");
      const result = deferred<Response>();
      onRead = (path) =>
        path === `/targets/${PEER}/policy` ? result.promise : undefined;
      fireEvent.click(refresh);
      await waitFor(() =>
        expect(
          requests.filter(
            (request) => request.path === `/targets/${PEER}/policy`,
          ),
        ).toHaveLength(2),
      );
      const pending = requests
        .filter((request) => request.path === `/targets/${PEER}/policy`)
        .at(-1)!;
      onRead = () => undefined;
      fireEvent.click(
        screen.getByRole("button", {
          name: change === "node" ? "test.local" : "test.session",
        }),
      );
      await waitFor(() => expect(pending.signal?.aborted).toBe(true));
      await act(async () => result.resolve(jsonResponse(remotePolicy())));
      await waitFor(() => namedButton("users.create"));
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      expect(screen.queryByText("users.reviewChanged")).toBeNull();
      expect(document.activeElement).not.toBe(oldRegion);
      expect(document.activeElement).not.toBe(oldSource);
      expect(mutations()).toHaveLength(0);
    },
  );
});
