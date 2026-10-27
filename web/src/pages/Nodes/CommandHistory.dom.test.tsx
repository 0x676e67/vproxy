// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://manager.example/"}
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { ConfigProvider } from "antd";
import { StrictMode, useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import {
  historyEntry,
  historyPage,
  HISTORY_LOCAL,
  HISTORY_PEER,
  HISTORY_JOB,
  HISTORY_CREDENTIAL,
} from "../../api/commandHistory.fixtures";
import { ManagementProvider, useManagement } from "../../auth/context";
import ManagementGate from "../../components/ManagementGate";
import messages from "../../locales/en-US";
import CommandHistory from "./CommandHistory";

vi.mock("../../hooks/useMessages", async () => {
  const captions = (await import("../../locales/en-US")).default;
  return {
    useMessages: () => ({
      intl: { locale: "en-US" },
      t: (id: keyof typeof captions) => captions[id],
    }),
  };
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
let reads: { path: string; method: string; signal: AbortSignal | null }[];
let reply: (path: string) => Promise<Response>;
let checkSession: () => Promise<void>;
const base = `/api/v1/targets/${HISTORY_PEER}/commands/history`;
beforeEach(() => {
  reads = [];
  reply = async () => jsonResponse(historyPage());
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
      const path = String(input);
      if (path === "/api/v1/auth/session")
        return jsonResponse({
          ...sessionFixture(),
          expires_at: Math.floor(Date.now() / 1000) + 3600,
        });
      if (path.includes("/commands/history")) {
        reads.push({
          path,
          method: init?.method ?? "GET",
          signal: init?.signal ?? null,
        });
        return reply(path);
      }
      throw new Error("Unexpected fixture API request");
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function Host() {
  const { controller } = useManagement();
  const [target, setTarget] = useState(HISTORY_PEER);
  const [count, setCount] = useState(0);
  checkSession = () => controller.check();
  return (
    <>
      <button onClick={() => setTarget(HISTORY_CREDENTIAL)}>test.target</button>
      <button onClick={() => setCount((value) => value + 1)}>
        test.render
      </button>
      <output>{count}</output>
      <ManagementGate>
        <p>Local node remains visible</p>
        <CommandHistory
          localNodeId={HISTORY_LOCAL}
          targetId={target}
          disabled={false}
        />
      </ManagementGate>
    </>
  );
}
async function mount() {
  render(
    <StrictMode>
      <ConfigProvider theme={{ token: { motion: false } }}>
        <ManagementProvider>
          <Host />
        </ManagementProvider>
      </ConfigProvider>
    </StrictMode>,
  );
  await screen.findByRole("button", { name: messages["commandHistory.open"] });
}
const click = (key: keyof typeof messages) =>
  fireEvent.click(screen.getByRole("button", { name: messages[key] }));
const search = (id: string) => {
  fireEvent.change(
    screen.getByLabelText(messages["commandHistory.lookupLabel"]),
    { target: { value: id } },
  );
  click("commandHistory.lookup");
};
describe("remote controller-local command history drawer", () => {
  it("reads only on explicit open or pagination and follows the original descending cursor", async () => {
    const first = {
      items: Array.from({ length: 20 }, (_, index) => ({
        ...historyEntry(),
        sequence: String(21 - index),
        job: {
          ...historyEntry().job,
          job_id: `${String(index).padStart(21, "0")}A`,
        },
      })),
      next_cursor: "2",
      oldest_sequence: "1",
      trimmed: true,
    };
    const older = {
      ...historyEntry(),
      sequence: "1",
      job: {
        ...historyEntry().job,
        job_id: HISTORY_CREDENTIAL,
        state: "superseded",
        policy_revision: null,
      },
      user_id: null,
    };
    reply = async (path) =>
      jsonResponse(
        path.endsWith(`/${HISTORY_JOB}`)
          ? historyEntry()
          : path.includes("before=2")
            ? {
                items: [older],
                next_cursor: null,
                oldest_sequence: "1",
                trimmed: true,
              }
            : first,
      );
    await mount();
    expect(reads).toHaveLength(0);
    click("commandHistory.open");
    await screen.findByText(first.items[0].job.job_id);
    expect(reads).toHaveLength(1);
    expect(reads[0].path).toBe(`${base}?limit=20`);
    for (const key of [
      "commandHistory.scope",
      "commandHistory.limit",
      "commandHistory.secret",
      "commandHistory.historical",
      "commandHistory.trimmed",
    ] as const)
      expect(screen.getByText(messages[key])).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "test.render" }));
    expect(reads).toHaveLength(1);
    click("commandHistory.next");
    await screen.findByText(HISTORY_CREDENTIAL);
    expect(reads.at(-1)?.path).toBe(`${base}?before=2&limit=20`);
    expect(screen.getByText(messages["control.job.superseded"])).toBeTruthy();
    expect(
      screen.getByRole("button", { name: messages["commandHistory.next"] }),
    ).toHaveProperty("disabled", true);
    click("commandHistory.previous");
    await screen.findByText(first.items[0].job.job_id);
    expect(reads.every((request) => request.method === "GET")).toBe(true);
    expect(reads).toHaveLength(3);
  });
  it("looks up an exact historical result and refreshes only on request without offering control actions", async () => {
    reply = async (path) =>
      jsonResponse(
        path.endsWith(`/${HISTORY_JOB}`) ? historyEntry() : historyPage(),
      );
    await mount();
    click("commandHistory.open");
    await screen.findByText(HISTORY_JOB);
    search(HISTORY_JOB);
    await screen.findAllByText(HISTORY_JOB);
    expect(reads.at(-1)?.path).toBe(`${base}/${HISTORY_JOB}`);
    expect(
      screen
        .getByRole("button", { name: messages["commandHistory.refresh"] })
        .getAttribute("aria-busy"),
    ).toBe("false");
    expect(screen.getByText(messages["control.job.applied"])).toBeTruthy();
    expect(
      screen.queryByRole("button", { name: messages["control.retry"] }),
    ).toBeNull();
    expect(
      screen.queryByRole("button", { name: messages["control.supersede"] }),
    ).toBeNull();
    // Ant Design owns its loading-icon lifecycle separately from the result
    // render. Wait for the real button to accept another deliberate click.
    await waitFor(() => {
      const refresh = screen.getByRole("button", {
        name: messages["commandHistory.refresh"],
      });
      expect(refresh.querySelector(".ant-btn-loading-icon")).toBeNull();
      expect(refresh).toHaveProperty("disabled", false);
    });
    click("commandHistory.refresh");
    await waitFor(() => expect(reads).toHaveLength(3));
    await screen.findByText(HISTORY_JOB);
    expect(reads.at(-1)?.path).toBe(`${base}?limit=20`);
    expect(reads.every((request) => request.method === "GET")).toBe(true);
    expect(reads).toHaveLength(3);
  });
  it("keeps a missing original job unknown, rejects invalid input before GET and never falls back to latest", async () => {
    reply = async (path) =>
      path.endsWith(`/${HISTORY_JOB}`)
        ? jsonResponse({ error: { code: "resource_not_found" } }, 404)
        : jsonResponse(historyPage());
    await mount();
    click("commandHistory.open");
    await screen.findByText(HISTORY_JOB);
    search("invalid");
    expect(
      await screen.findByText(messages["commandHistory.invalidJob"]),
    ).toBeTruthy();
    expect(reads).toHaveLength(1);
    search(HISTORY_JOB);
    expect(
      await screen.findByText(messages["commandHistory.missing"]),
    ).toBeTruthy();
    expect(reads).toHaveLength(2);
    expect(reads[1].path).toBe(`${base}/${HISTORY_JOB}`);
    expect(screen.queryByText(messages["commandHistory.empty"])).toBeNull();
    reply = async () => jsonResponse({ error: { code: "policy_busy" } }, 503);
    click("commandHistory.refresh");
    expect(
      await screen.findByText(messages["commandHistory.unavailable"]),
    ).toBeTruthy();
    expect(screen.queryByText(messages["commandHistory.empty"])).toBeNull();
    expect(screen.getByText("Local node remains visible")).toBeTruthy();
  });
  it("aborts closing and target changes, fencing late transports without automatic re-reads", async () => {
    const first = deferred<Response>();
    reply = () => first.promise;
    await mount();
    click("commandHistory.open");
    await waitFor(() => expect(reads).toHaveLength(1));
    click("commandHistory.close");
    expect(reads[0].signal?.aborted).toBe(true);
    await act(async () => first.resolve(jsonResponse(historyPage())));
    expect(screen.queryByText(HISTORY_JOB)).toBeNull();
    const second = deferred<Response>();
    reply = () => second.promise;
    click("commandHistory.open");
    await waitFor(() => expect(reads).toHaveLength(2));
    fireEvent.click(screen.getByRole("button", { name: "test.target" }));
    await waitFor(() => expect(reads[1].signal?.aborted).toBe(true));
    await act(async () => second.resolve(jsonResponse(historyPage())));
    expect(screen.queryByText(HISTORY_JOB)).toBeNull();
    expect(reads).toHaveLength(2);
    reply = async () =>
      jsonResponse({
        ...historyPage(),
        items: [
          {
            ...historyEntry(),
            job: { ...historyEntry().job, node_id: HISTORY_CREDENTIAL },
          },
        ],
      });
    click("commandHistory.open");
    await screen.findByText(HISTORY_JOB);
    expect(reads.at(-1)?.path).toBe(
      `/api/v1/targets/${HISTORY_CREDENTIAL}/commands/history?limit=20`,
    );
  });
  it("drops a previous session's response and exposes imported unknown timestamps only on a new explicit read", async () => {
    const late = deferred<Response>();
    reply = () => late.promise;
    await mount();
    click("commandHistory.open");
    await waitFor(() => expect(reads).toHaveLength(1));
    await act(async () => checkSession());
    expect(reads[0].signal?.aborted).toBe(true);
    await act(async () => late.resolve(jsonResponse(historyPage())));
    expect(screen.queryByText(HISTORY_JOB)).toBeNull();
    expect(reads).toHaveLength(1);
    reply = async () =>
      jsonResponse({
        ...historyEntry(),
        imported: true,
        recorded_at_unix_s: null,
        updated_at_unix_s: null,
        user_id: null,
      });
    click("commandHistory.open");
    // The first list attempt rejects a detail-shaped body; only an explicit
    // exact lookup can display it, and it never borrows the previous response.
    await screen.findByText(messages["commandHistory.unavailable"]);
    search(HISTORY_JOB);
    expect(
      await screen.findByText(messages["commandHistory.imported"]),
    ).toBeTruthy();
    expect(
      screen.getAllByText(messages["commandHistory.unknownTime"]),
    ).toHaveLength(2);
    expect(
      screen.getAllByText(messages["commandHistory.resultUnknown"]).length,
    ).toBeGreaterThanOrEqual(2);
    expect(reads).toHaveLength(3);
  });
});
