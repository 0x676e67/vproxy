// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://localhost/"}
import { createRequire } from "node:module";
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
import { useEffect, useId, useRef, useState } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import { ManagementProvider, useManagement } from "../../auth/context";
import CrossNodeSearch, { type UserLocation } from "./CrossNodeSearch";

const require = createRequire(import.meta.url);
const rcIdModule = require("@rc-component/util/lib/hooks/useId") as {
  default: (id?: string) => string;
};

// Keep the real Modal, forms, session generations and response decoders. Only
// captions, Umi Router exports and the in-memory HTTP boundary are substituted.
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

const targetId = (index: number) =>
  `T${String(index).padStart(2, "0")}${"A".repeat(19)}`;
const userId = (index: number) =>
  `U${String(index).padStart(2, "0")}${"A".repeat(19)}`;
const CURSOR_ONE = `us1_${"A".repeat(98)}`;
const CURSOR_TWO = `us1_${"B".repeat(97)}Q`;
const targets = Array.from({ length: 26 }, (_, index) => ({
  node_id: targetId(index + 1),
  name: `Node ${index + 1}`,
  origin: `https://node-${index + 1}.example:9443`,
  server_ip: null,
  active: true,
  retired: false,
  revision: "3",
  observed_epoch: "2",
  observed_command: "7",
  observed_policy_revision: "9",
  rollback_detected: false,
}));
const targetCaption = (index: number) =>
  `${targets[index - 1].name} · ${targetId(index)}`;
const user = (index = 1, name = "Shared account", deleted = false) => ({
  id: userId(index),
  name,
  active: !deleted,
  deleted,
  protocols: ["http"],
  concurrent_limit: 8,
  revision: "9",
});
const page = (
  items: ReturnType<typeof user>[] = [],
  next_cursor: string | null = null,
  revision = "9",
) => ({ revision, items, next_cursor });
const firstPage = (name: string, cursor: string, revision = "9") =>
  page(
    Array.from({ length: 25 }, (_, index) => user(index + 1, name)),
    cursor,
    revision,
  );

interface RequestRecord {
  path: string;
  query: URLSearchParams;
  method: string;
  signal: AbortSignal | null;
}
let requests: RequestRecord[];
let unexpected: string[];
let active: number;
let peak: number;
let onDirectory: (url: URL) => Promise<Response>;
let onSearch: (url: URL) => Promise<Response>;
let locate: ReturnType<typeof vi.fn<(location: UserLocation) => void>>;
let close: ReturnType<typeof vi.fn<() => void>>;

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
function Harness() {
  const { controller, state } = useManagement();
  const [open, setOpen] = useState(false);
  const opened = useRef(false);
  useEffect(() => {
    if (!opened.current && state.phase === "authenticated") {
      opened.current = true;
      setOpen(true);
    }
  }, [state.phase]);
  return (
    <>
      <output data-testid="session-phase">{state.phase}</output>
      <button onClick={() => void controller.check()}>test.session</button>
      {open && (
        <CrossNodeSearch
          onClose={() => {
            close();
            setOpen(false);
          }}
          onLocate={locate}
        />
      )}
    </>
  );
}
function mount() {
  return render(
    <ConfigProvider
      theme={{ token: { motion: false } }}
      wave={{ disabled: true }}
    >
      <MemoryRouter initialEntries={["/users"]}>
        <ManagementProvider>
          <Harness />
        </ManagementProvider>
      </MemoryRouter>
    </ConfigProvider>,
  );
}
const searchRequests = () =>
  requests.filter(({ path }) => path.endsWith("/users/search"));
const directoryRequests = () =>
  requests.filter(({ path }) => path === "/targets");
const scope = (path: string) =>
  path === "/proxy/users/search"
    ? null
    : /^\/targets\/([^/]+)\/users\/search$/.exec(path)?.[1];
const groupCaption = (target: string | null) =>
  target === null
    ? "control.localScope · control.localScope"
    : `${targets.find(({ node_id }) => node_id === target)!.name} · ${target}`;
function group(target: string | null) {
  const region = screen.getByLabelText(groupCaption(target), {
    selector: "section",
  });
  return {
    ...within(region),
    button: (label: string) => button(label, region),
  };
}
function button(label: string, root: HTMLElement = document.body) {
  // Captions select one real control without repeatedly calculating accessible
  // names and visibility for every checkbox and result row in the whole modal.
  const element = within(root)
    .getByText(label, { exact: true })
    .closest("button");
  if (!(element instanceof HTMLButtonElement))
    throw new Error("Expected a button for the fixture caption");
  return element;
}
function formElement() {
  return screen.getByLabelText("users.crossSearchForm", { selector: "form" });
}
async function openGroup(target: string | null) {
  const caption = groupCaption(target);
  const headers = screen
    .getAllByText(caption, { exact: true })
    .map((element) => element.closest('[role="button"]'))
    .filter(
      (element): element is HTMLElement => element instanceof HTMLElement,
    );
  expect(headers).toHaveLength(1);
  expect(headers[0].getAttribute("aria-expanded")).toBe("false");
  await act(async () => fireEvent.click(headers[0]));
  expect(headers[0].getAttribute("aria-expanded")).toBe("true");
  await screen.findByLabelText(caption, { selector: "section" });
  return group(target);
}
async function ready() {
  const submit = button("users.searchSubmit", formElement());
  await waitFor(() => expect(submit.disabled).toBe(false));
}
async function selectTarget(index: number) {
  const directory = await screen.findByLabelText("users.crossDirectory", {
    selector: "section",
  });
  const checkbox = await within(directory).findByLabelText(
    targetCaption(index),
  );
  await waitFor(() =>
    expect((checkbox as HTMLInputElement).disabled).toBe(false),
  );
  fireEvent.click(checkbox);
  expect((checkbox as HTMLInputElement).checked).toBe(true);
}
async function search(query = "Shared account") {
  const form = formElement();
  fireEvent.change(within(form).getByLabelText("users.searchQuery"), {
    target: { value: query },
  });
  await act(async () => {
    fireEvent.submit(form);
  });
}

beforeEach(() => {
  vi.spyOn(rcIdModule, "default").mockImplementation((id?: string) => {
    const generatedId = useId();
    return id || generatedId;
  });
  requests = [];
  unexpected = [];
  active = 0;
  peak = 0;
  locate = vi.fn<(location: UserLocation) => void>();
  close = vi.fn<() => void>();
  onDirectory = async (url) =>
    jsonResponse({
      items: url.searchParams.has("after")
        ? targets.slice(25)
        : targets.slice(0, 25),
      next_cursor: url.searchParams.has("after") ? null : targetId(25),
      controller_available: true,
    });
  onSearch = async () => jsonResponse(page());
  vi.stubGlobal("__VPROXY_DEMO__", false);
  // jsdom has no layout engine. These platform shims make no geometric claim.
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
      if (path === "/auth/session" && method === "GET")
        return jsonResponse({
          ...sessionFixture(),
          expires_at: Math.floor(Date.now() / 1000) + 3600,
        });
      requests.push({
        path,
        query: url.searchParams,
        method,
        signal: init?.signal ?? null,
      });
      if (
        method !== "GET" ||
        (path !== "/targets" && !path.endsWith("/users/search"))
      ) {
        unexpected.push(`${method} ${path}`);
        throw new Error("Unexpected cross-node fixture request");
      }
      active++;
      peak = Math.max(peak, active);
      try {
        return await (path === "/targets" ? onDirectory(url) : onSearch(url));
      } finally {
        active--;
      }
    }),
  );
});
afterEach(() => {
  cleanup();
  try {
    expect(unexpected).toEqual([]);
    expect(requests.every(({ method }) => method === "GET")).toBe(true);
  } finally {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  }
});

describe("cross-node user search", () => {
  it.each(["selection", "includeDeleted"] as const)(
    "requires another explicit submit after %s changes during Form validation",
    async (change) => {
      mount();
      await selectTarget(1);
      const form = formElement();
      fireEvent.change(within(form).getByLabelText("users.searchQuery"), {
        target: { value: "Shared account" },
      });
      await act(async () => {
        fireEvent.submit(form);
        fireEvent.click(
          screen.getByLabelText(
            change === "selection" ? targetCaption(2) : "users.includeDeleted",
          ),
        );
      });
      await ready();
      expect(searchRequests()).toHaveLength(0);

      await act(async () => fireEvent.submit(form));
      await waitFor(() =>
        expect(searchRequests()).toHaveLength(change === "selection" ? 2 : 1),
      );
      await ready();
      expect(searchRequests().map(({ path }) => scope(path))).toEqual(
        change === "selection" ? [targetId(1), targetId(2)] : [targetId(1)],
      );
      for (const request of searchRequests())
        expect(request.query.get("include_deleted")).toBe(
          change === "includeDeleted" ? "true" : "false",
        );
      expect(peak).toBe(1);
    },
  );

  it.each(["after does not advance", "cursor cycle", "more than 25"] as const)(
    "rejects a directory page whose %s without publishing it or fetching again",
    async (boundary) => {
      onDirectory = async (url) =>
        jsonResponse({
          items: !url.searchParams.has("after")
            ? targets.slice(0, 25)
            : boundary === "after does not advance"
              ? targets.slice(24, 25)
              : boundary === "cursor cycle"
                ? targets.slice(0, 25)
                : targets,
          next_cursor:
            !url.searchParams.has("after") || boundary === "cursor cycle"
              ? targetId(25)
              : boundary === "more than 25"
                ? targetId(26)
                : null,
          controller_available: true,
        });
      mount();
      await selectTarget(1);
      fireEvent.click(button("users.crossDirectoryNext"));
      const directory = screen.getByLabelText("users.crossDirectory", {
        selector: "section",
      });
      await within(directory).findByText("api.format");
      expect(directoryRequests()).toHaveLength(2);
      expect(directoryRequests()[1].query.get("after")).toBe(targetId(25));
      expect(within(directory).queryByLabelText(targetCaption(26))).toBeNull();
      expect(button("users.crossDirectoryNext", directory).disabled).toBe(true);
      expect(button("users.crossDirectoryRefresh", directory).disabled).toBe(
        false,
      );
      expect(searchRequests()).toHaveLength(0);
      expect(peak).toBe(1);
    },
  );

  it("keeps explicit selections across directory page 26 and locates same-name users only by node and ID", async () => {
    onSearch = async () =>
      jsonResponse(page([user(1, "Shared account", true)]));
    mount();
    await selectTarget(1);
    expect(directoryRequests()).toHaveLength(1);
    expect(searchRequests()).toHaveLength(0);
    expect(screen.queryByLabelText(targetCaption(26))).toBeNull();
    fireEvent.click(button("users.crossDirectoryNext"));
    await selectTarget(26);
    fireEvent.click(screen.getByLabelText("control.localScope"));
    fireEvent.click(screen.getByLabelText("users.includeDeleted"));
    await search();
    await waitFor(() => expect(searchRequests()).toHaveLength(3));
    await ready();
    expect(directoryRequests()).toHaveLength(2);
    expect(directoryRequests()[1].query.get("after")).toBe(targetId(25));
    expect(
      searchRequests()
        .map(({ path }) => scope(path))
        .sort(),
    ).toEqual([null, targetId(1), targetId(26)].sort());
    for (const request of searchRequests()) {
      expect(Object.fromEntries(request.query)).toEqual({
        mode: "name",
        q: "Shared account",
        limit: "25",
        include_deleted: "true",
      });
    }
    for (const selected of [null, targetId(1), targetId(26)]) {
      const result = await openGroup(selected);
      expect(result.getByText("Shared account")).toBeTruthy();
      fireEvent.click(result.button("users.crossLocate"));
      expect(locate).toHaveBeenLastCalledWith({
        targetId: selected,
        userId: userId(1),
        includeDeleted: true,
      });
    }
    expect(locate).toHaveBeenCalledTimes(3);
    expect(peak).toBe(1);
  });

  it("serializes deferred group reads and advances each opaque cursor independently", async () => {
    const first = deferred<Response>();
    const next = deferred<Response>();
    onSearch = async (url) => {
      if (url.searchParams.get("after") === CURSOR_ONE) return next.promise;
      if (url.searchParams.get("after") === CURSOR_TWO)
        return jsonResponse(page([user(50, "Second page two")], null, "21"));
      return scope(url.pathname.replace(/^\/api\/v1/, "")) === targetId(1)
        ? first.promise
        : jsonResponse(firstPage("Second first page", CURSOR_TWO, "21"));
    };
    mount();
    await selectTarget(1);
    await selectTarget(2);
    await search();
    await waitFor(() => expect(searchRequests()).toHaveLength(1));
    expect(scope(searchRequests()[0].path)).toBe(targetId(1));
    expect(active).toBe(1);
    await act(async () =>
      first.resolve(jsonResponse(firstPage("First first page", CURSOR_ONE))),
    );
    await waitFor(() => expect(searchRequests()).toHaveLength(2));
    await ready();
    await openGroup(targetId(1));
    await openGroup(targetId(2));
    fireEvent.click(group(targetId(1)).button("users.crossNext"));
    await waitFor(() => expect(searchRequests()).toHaveLength(3));
    expect(group(targetId(2)).button("users.crossNext").disabled).toBe(true);
    expect(button("users.crossDirectoryNext").disabled).toBe(true);
    await act(async () =>
      next.resolve(jsonResponse(page([user(49, "First page two")]))),
    );
    await ready();
    expect(group(targetId(1)).getByText("First page two")).toBeTruthy();
    expect(group(targetId(2)).getAllByText("Second first page")).toHaveLength(
      25,
    );
    fireEvent.click(group(targetId(2)).button("users.crossNext"));
    await waitFor(() => expect(searchRequests()).toHaveLength(4));
    await ready();
    expect(group(targetId(2)).getByText("Second page two")).toBeTruthy();
    expect(group(targetId(1)).getByText("First page two")).toBeTruthy();
    expect(
      searchRequests()
        .slice(2)
        .map(({ path, query }) => [scope(path), query.get("after")]),
    ).toEqual([
      [targetId(1), CURSOR_ONE],
      [targetId(2), CURSOR_TWO],
    ]);
    expect(peak).toBe(1);
  });

  it.each([
    "next revision",
    "previous first revision",
    "cursor cycle",
  ] as const)(
    "rejects a group's %s while preserving another node and requiring an explicit restart",
    async (boundary) => {
      const stableSecond = () =>
        page(
          Array.from({ length: 25 }, (_, index) =>
            user(index + 26, "Stable second page"),
          ),
          CURSOR_TWO,
        );
      const responses =
        boundary === "next revision"
          ? [
              firstPage("Original first page", CURSOR_ONE),
              page([user(50, "Unaccepted newer page")], null, "10"),
            ]
          : boundary === "previous first revision"
            ? [
                firstPage("Original first page", CURSOR_ONE),
                page([user(50, "Stable second page")]),
                firstPage("Unaccepted newer page", CURSOR_ONE, "10"),
              ]
            : [
                firstPage("Original first page", CURSOR_ONE),
                stableSecond(),
                page(
                  Array.from({ length: 25 }, (_, index) =>
                    user(index + 51, "Unaccepted cursor cycle"),
                  ),
                  CURSOR_ONE,
                ),
              ];
      responses.push(
        page([user(90, "Fresh user after explicit restart")], null, "10"),
      );
      onSearch = async (url) => {
        if (scope(url.pathname.replace(/^\/api\/v1/, "")) === targetId(2))
          return jsonResponse(
            page([user(80, "Other node stays independent")], null, "21"),
          );
        const response = responses.shift();
        if (!response) throw new Error("Unexpected pagination fixture request");
        return jsonResponse(response);
      };
      mount();
      await selectTarget(1);
      await selectTarget(2);
      await search();
      await waitFor(() => expect(searchRequests()).toHaveLength(2));
      await ready();
      await openGroup(targetId(1));
      await openGroup(targetId(2));
      let count = 2;
      const turn = async (key: "users.crossPrevious" | "users.crossNext") => {
        fireEvent.click(group(targetId(1)).button(key));
        ++count;
        await waitFor(() => expect(searchRequests()).toHaveLength(count));
        await ready();
      };
      await turn("users.crossNext");
      if (boundary === "previous first revision") {
        expect(group(targetId(1)).getByText("Stable second page")).toBeTruthy();
        await turn("users.crossPrevious");
        expect(searchRequests().at(-1)?.query.has("after")).toBe(false);
      } else if (boundary === "cursor cycle") {
        expect(
          group(targetId(1)).getAllByText("Stable second page"),
        ).toHaveLength(25);
        await turn("users.crossNext");
        // This repeats the older cursor, not the current request's cursor, so
        // the component must check the whole group's history after decoding.
        expect(searchRequests().at(-1)?.query.get("after")).toBe(CURSOR_TWO);
      }
      const failed = group(targetId(1));
      expect(
        failed.getAllByText(
          boundary === "cursor cycle" ? "api.format" : "users.searchChanged",
        ).length,
      ).toBeGreaterThan(0);
      expect(failed.queryByText("Unaccepted newer page")).toBeNull();
      expect(failed.queryByText("Unaccepted cursor cycle")).toBeNull();
      expect(failed.button("users.crossNext").disabled).toBe(true);
      expect(failed.button("users.crossPrevious").disabled).toBe(true);
      expect(
        group(targetId(2)).getByText("Other node stays independent"),
      ).toBeTruthy();
      expect(
        searchRequests().filter(({ path }) => scope(path) === targetId(2)),
      ).toHaveLength(1);
      expect(searchRequests()).toHaveLength(count);
      fireEvent.click(failed.button("users.crossReadAgain"));
      ++count;
      await waitFor(() => expect(searchRequests()).toHaveLength(count));
      await ready();
      expect(
        group(targetId(1)).getByText("Fresh user after explicit restart"),
      ).toBeTruthy();
      expect(searchRequests().at(-1)?.query.has("after")).toBe(false);
      expect(group(targetId(1)).queryByText("users.searchChanged")).toBeNull();
      expect(group(targetId(1)).queryByText("api.format")).toBeNull();
      fireEvent.click(group(targetId(2)).button("users.crossLocate"));
      expect(locate).toHaveBeenLastCalledWith({
        targetId: targetId(2),
        userId: userId(80),
        includeDeleted: false,
      });
      expect(responses).toHaveLength(0);
      expect(peak).toBe(1);
    },
  );

  it("keeps unsupported, busy, changed and malformed pages distinct from empty results without retrying", async () => {
    const attempts = new Map<string | null | undefined, number>();
    onSearch = async (url) => {
      const node = scope(url.pathname.replace(/^\/api\/v1/, ""));
      const attempt = (attempts.get(node) ?? 0) + 1;
      attempts.set(node, attempt);
      if (node === targetId(2) && attempt > 1) return jsonResponse(page());
      if (node === targetId(1))
        return jsonResponse(
          { error: { code: "user_search_unsupported" } },
          502,
        );
      if (node === targetId(2))
        return jsonResponse({ error: { code: "policy_busy" } }, 503);
      if (node === targetId(3))
        return jsonResponse({ error: { code: "user_search_changed" } }, 409);
      return jsonResponse({
        revision: "9",
        items: [],
        next_cursor: "not-a-search-cursor",
      });
    };
    mount();
    for (const index of [1, 2, 3, 4]) await selectTarget(index);
    await search();
    await waitFor(() => expect(searchRequests()).toHaveLength(4));
    await ready();
    for (const [index, error] of [
      [1, "users.searchUnsupported"],
      [2, "users.busy"],
      [3, "users.searchChanged"],
      [4, "api.format"],
    ] as const) {
      await openGroup(targetId(index));
      expect(group(targetId(index)).getAllByText(error).length).toBeGreaterThan(
        0,
      );
      expect(group(targetId(index)).queryByText("users.crossEmpty")).toBeNull();
      expect(group(targetId(index)).button("users.crossNext").disabled).toBe(
        true,
      );
    }
    expect([...attempts.values()]).toEqual([1, 1, 1, 1]);
    fireEvent.click(group(targetId(2)).button("users.crossReadAgain"));
    await waitFor(() => expect(searchRequests()).toHaveLength(5));
    await ready();
    expect(group(targetId(2)).getByText("users.crossEmpty")).toBeTruthy();
    expect(scope(searchRequests()[4].path)).toBe(targetId(2));
    expect(searchRequests()[4].query.has("after")).toBe(false);
    expect(
      group(targetId(1)).getAllByText("users.searchUnsupported").length,
    ).toBeGreaterThan(0);
    expect(peak).toBe(1);
  });

  it("invalidates changed conditions and explicit cancellation before an abort-ignoring result can start another node", async () => {
    const changed = deferred<Response>();
    const cancelled = deferred<Response>();
    onSearch = async (url) =>
      url.searchParams.get("q") === "old query"
        ? changed.promise
        : cancelled.promise;
    mount();
    await selectTarget(1);
    await selectTarget(2);
    await search("old query");
    await waitFor(() => expect(searchRequests()).toHaveLength(1));
    fireEvent.change(screen.getByLabelText("users.searchQuery"), {
      target: { value: "replacement query" },
    });
    expect(searchRequests()[0].signal?.aborted).toBe(true);
    expect(button("users.searchSubmit").disabled).toBe(true);
    await act(async () =>
      changed.resolve(jsonResponse(page([user(1, "Late old query")]))),
    );
    await ready();
    expect(screen.queryByText("Late old query")).toBeNull();
    expect(searchRequests()).toHaveLength(1);
    await search("replacement query");
    await waitFor(() => expect(searchRequests()).toHaveLength(2));
    fireEvent.click(button("users.crossCancel"));
    expect(searchRequests()[1].signal?.aborted).toBe(true);
    await act(async () =>
      cancelled.resolve(jsonResponse(page([user(2, "Late cancelled query")]))),
    );
    await ready();
    expect(screen.queryByText("Late cancelled query")).toBeNull();
    expect(searchRequests()).toHaveLength(2);
    expect(locate).not.toHaveBeenCalled();
    expect(peak).toBe(1);
  });

  it.each(["session", "close", "unmount"] as const)(
    "ignores a late group and stops the remaining nodes after %s",
    async (boundary) => {
      const late = deferred<Response>();
      onSearch = async () => late.promise;
      const view = mount();
      await selectTarget(1);
      await selectTarget(2);
      await search();
      await waitFor(() => expect(searchRequests()).toHaveLength(1));
      if (boundary === "session") {
        fireEvent.click(button("test.session"));
        await waitFor(() =>
          expect(screen.getByTestId("session-phase").textContent).toBe(
            "authenticated",
          ),
        );
      } else if (boundary === "close") {
        fireEvent.click(button("users.crossClose"));
        expect(close).toHaveBeenCalledTimes(1);
      } else view.unmount();
      expect(searchRequests()[0].signal?.aborted).toBe(true);
      await act(async () =>
        late.resolve(jsonResponse(page([user(1, "Late replaced session")]))),
      );
      expect(screen.queryByText("Late replaced session")).toBeNull();
      expect(searchRequests()).toHaveLength(1);
      expect(locate).not.toHaveBeenCalled();
    },
  );
});
