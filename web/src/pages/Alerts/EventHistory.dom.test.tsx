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
import { useState } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  eventPageFixture,
  episodeFixture,
  summaryFixture,
  EVENT_NODE,
  EVENT_OTHER,
} from "../../api/alertEvents.fixtures";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import { ManagementProvider, useManagement } from "../../auth/context";
import ManagementGate from "../../components/ManagementGate";
import AlertInbox, { ALERT_SUMMARY_POLL_MS } from "../../components/AlertInbox";
import messages from "../../locales/en-US";
import EventHistory from "./EventHistory";

vi.mock("@umijs/max", async () => ({
  Link: (await import("react-router-dom")).Link,
}));
vi.mock("../../hooks/useMessages", async () => {
  const captions = (await import("../../locales/en-US")).default;
  return {
    useMessages: () => ({
      intl: { locale: "en-US" },
      t: (
        id: keyof typeof captions,
        values?: Record<string, string | number>,
      ) =>
        Object.entries(values ?? {}).reduce(
          (text, [key, value]) => text.replaceAll(`{${key}}`, String(value)),
          captions[id],
        ),
    }),
  };
});
let requests: {
  path: string;
  method: string;
  body: unknown;
  signal: AbortSignal | null;
}[];
let reply: (path: string, method: string) => Promise<Response>;
let check: () => Promise<void>;
let visibility: DocumentVisibilityState;
beforeEach(() => {
  requests = [];
  visibility = "visible";
  Object.defineProperty(document, "visibilityState", {
    configurable: true,
    get: () => visibility,
  });
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
  reply = async (path, method) =>
    path === "/alert-episodes/1/acknowledge"
      ? jsonResponse(episodeFixture(true))
      : path === "/alert-episodes/1"
        ? jsonResponse(episodeFixture())
        : path === "/alert-summary"
          ? jsonResponse(summaryFixture())
          : method === "GET" && path.startsWith("/alert-events")
            ? jsonResponse(eventPageFixture())
            : Promise.reject(new Error("Unexpected fixture request"));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input).replace(/^\/api\/v1/, ""),
        method = init?.method ?? "GET";
      requests.push({
        path,
        method,
        body: init?.body ? JSON.parse(String(init.body)) : null,
        signal: init?.signal ?? null,
      });
      if (path === "/auth/session")
        return jsonResponse({
          ...sessionFixture(),
          expires_at: Math.floor(Date.now() / 1000) + 3600,
        });
      if (path === "/node")
        return jsonResponse({
          node_id: EVENT_NODE,
          name: "Local",
          version: "test",
          os: "linux",
          arch: "x86_64",
          capabilities: [],
        });
      return reply(path, method);
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
function Host({ badge = false }: { badge?: boolean | "with-history" }) {
  const { controller } = useManagement(),
    [origin, setOrigin] = useState<string | null>(null);
  check = () => controller.check();
  return (
    <ManagementGate>
      <button onClick={() => setOrigin(EVENT_OTHER)}>test.origin</button>
      {badge && <AlertInbox />}
      {badge !== true && <EventHistory origin={origin} initialEvent={null} />}
    </ManagementGate>
  );
}
function mount(badge: boolean | "with-history" = false) {
  return render(
    <MemoryRouter>
      <ConfigProvider
        theme={{ token: { motion: false } }}
        wave={{ disabled: true }}
      >
        <ManagementProvider>
          <Host badge={badge} />
        </ManagementProvider>
      </ConfigProvider>
    </MemoryRouter>,
  );
}
const posts = () => requests.filter((row) => row.method === "POST");
const click = (key: keyof typeof messages) =>
  fireEvent.click(screen.getByRole("button", { name: messages[key] }));
async function openEpisode() {
  await screen.findByText(messages["alerts.code.policy_not_applied"]);
  click("alertEvents.openEpisode");
  await screen.findByText(messages["alertEvents.episodeHint"]);
}
async function acknowledge() {
  click("alertEvents.ack");
  const modal = await screen.findByRole("dialog", {
    name: messages["alertEvents.confirm"],
  });
  fireEvent.click(
    within(modal).getByRole("button", { name: messages["alertEvents.ack"] }),
  );
}
describe("durable event history and original acknowledgement outcomes", () => {
  it("reads preserved remote observations from local history and offers only an explicit source-node view", async () => {
    reply = async () =>
      jsonResponse({
        ...eventPageFixture(),
        items: [
          {
            ...eventPageFixture().items[0],
            origin_node_id: EVENT_OTHER,
            kind: "node_tls",
            code: "node_tls_identity_expired",
          },
        ],
      });
    mount();
    await screen.findByText(messages["alerts.code.node_tls_identity_expired"]);
    expect(
      screen.getByText(messages["alerts.foreignObservation"]),
    ).toBeTruthy();
    expect(
      screen
        .getByRole("link", { name: messages["alerts.sourceNode"] })
        .getAttribute("href"),
    ).toBe(`/alerts?target=${EVENT_OTHER}`);
    expect(posts()).toHaveLength(0);
    expect(requests.some((row) => row.path.startsWith("/targets/"))).toBe(
      false,
    );
    expect(screen.queryByText(messages["alerts.status.recovered"])).toBeNull();
  });
  it("reads local history only, acknowledges one exact state and keeps health status independent", async () => {
    mount();
    await openEpisode();
    await acknowledge();
    await screen.findByText(messages["alertEvents.acknowledged"]);
    expect(posts()).toHaveLength(1);
    expect(posts()[0]).toMatchObject({
      path: "/alert-episodes/1/acknowledge",
      body: { expected_node_id: EVENT_NODE, expected_transition_sequence: "1" },
    });
    expect(screen.getByText(messages["alerts.status.active"])).toBeTruthy();
    expect(screen.queryByText(messages["alerts.status.recovered"])).toBeNull();
    expect(requests.some((row) => row.path.startsWith("/targets/"))).toBe(
      false,
    );
  });
  it("restores an unknown POST after remount, reads only the original episode and ends review explicitly without replay", async () => {
    let acknowledged = false;
    reply = async (path, method) => {
      if (method === "POST")
        throw new TypeError("synthetic first response lost");
      if (path === "/alert-episodes/1")
        return jsonResponse(
          acknowledged
            ? { ...episodeFixture(true), acknowledged_by: EVENT_OTHER }
            : episodeFixture(),
        );
      return jsonResponse(eventPageFixture());
    };
    const first = mount();
    await openEpisode();
    await acknowledge();
    await screen.findAllByText(messages["alertEvents.unknown"]);
    expect(posts()).toHaveLength(1);
    first.unmount();
    acknowledged = true;
    mount();
    await screen.findAllByText(messages["alertEvents.unknown"]);
    fireEvent.click(
      screen.getByRole("button", {
        name: messages["alertEvents.readOriginal"],
      }),
    );
    await screen.findByText(messages["alertEvents.covered"]);
    expect(posts()).toHaveLength(1);
    expect(
      requests
        .filter(
          (row) =>
            row.path.startsWith("/alert-episodes/") && row.method === "GET",
        )
        .every((row) => row.path === "/alert-episodes/1"),
    ).toBe(true);
    expect(screen.getByText(EVENT_OTHER)).toBeTruthy();
    click("alertEvents.finish");
    const modal = await screen.findByRole("dialog", {
      name: messages["alertEvents.finish"],
    });
    fireEvent.click(
      within(modal).getByRole("button", {
        name: messages["alertEvents.finish"],
      }),
    );
    await waitFor(() =>
      expect(screen.queryByText(messages["alertEvents.covered"])).toBeNull(),
    );
    expect(posts()).toHaveLength(1);
  });
  it("allows explicit local review completion only after the original exact episode has a typed 404, not a busy or generic missing response", async () => {
    let outcome: "available" | "busy" | "generic" | "missing" = "available";
    reply = async (path, method) => {
      if (method === "POST")
        throw new TypeError("synthetic first response lost");
      if (path === "/alert-episodes/1")
        return outcome === "available"
          ? jsonResponse(episodeFixture())
          : outcome === "busy"
            ? jsonResponse({ error: { code: "policy_busy" } }, 503)
            : jsonResponse(
                {
                  error: {
                    code:
                      outcome === "missing"
                        ? "alert_history_not_queryable"
                        : "resource_not_found",
                  },
                },
                404,
              );
      return jsonResponse(eventPageFixture());
    };
    mount();
    await openEpisode();
    await acknowledge();
    await screen.findAllByText(messages["alertEvents.unknown"]);
    const readOriginal = () =>
      fireEvent.click(
        screen.getAllByRole("button", {
          name: messages["alertEvents.readOriginal"],
        })[0],
      );
    outcome = "busy";
    readOriginal();
    await screen.findByText(messages["users.busy"]);
    expect(
      screen.queryByText(messages["alertEvents.missingReview"]),
    ).toBeNull();
    expect(
      screen
        .getByRole("button", { name: messages["alertEvents.finish"] })
        .hasAttribute("disabled"),
    ).toBe(true);
    outcome = "generic";
    readOriginal();
    await screen.findByText(messages["users.notFound"]);
    expect(
      screen.queryByText(messages["alertEvents.missingReview"]),
    ).toBeNull();
    expect(
      screen
        .getByRole("button", { name: messages["alertEvents.finish"] })
        .hasAttribute("disabled"),
    ).toBe(true);
    outcome = "missing";
    readOriginal();
    await screen.findByText(messages["alertEvents.missingReview"]);
    expect(posts()).toHaveLength(1);
    click("alertEvents.finish");
    const modal = await screen.findByRole("dialog", {
      name: messages["alertEvents.finish"],
    });
    expect(
      within(modal).getByText(messages["alertEvents.missingReview"]),
    ).toBeTruthy();
    fireEvent.click(
      within(modal).getByRole("button", {
        name: messages["alertEvents.finish"],
      }),
    );
    await waitFor(() =>
      expect(screen.queryByText(messages["alertEvents.unknown"])).toBeNull(),
    );
    expect(posts()).toHaveLength(1);
  });
  it("does not allow a late exact-episode 404 from a previous origin view to clear an unknown acknowledgement", async () => {
    let resolve!: (response: Response) => void;
    const late = new Promise<Response>((accept) => {
      resolve = accept;
    });
    let delayed = false;
    reply = async (path, method) => {
      if (method === "POST")
        throw new TypeError("synthetic first response lost");
      if (path === "/alert-episodes/1")
        return delayed ? late : jsonResponse(episodeFixture());
      return jsonResponse({
        ...eventPageFixture(),
        items: path.includes("origin_node_id") ? [] : eventPageFixture().items,
      });
    };
    mount();
    await openEpisode();
    await acknowledge();
    await screen.findAllByText(messages["alertEvents.unknown"]);
    delayed = true;
    fireEvent.click(
      screen.getAllByRole("button", {
        name: messages["alertEvents.readOriginal"],
      })[0],
    );
    await waitFor(() =>
      expect(
        requests.filter((row) => row.path === "/alert-episodes/1"),
      ).toHaveLength(2),
    );
    const original = requests.filter(
      (row) => row.path === "/alert-episodes/1",
    )[1];
    fireEvent.click(screen.getByRole("button", { name: "test.origin" }));
    await screen.findByText(messages["alertEvents.empty"]);
    expect(original.signal?.aborted).toBe(true);
    await act(async () =>
      resolve(
        jsonResponse({ error: { code: "alert_history_not_queryable" } }, 404),
      ),
    );
    expect(
      screen.queryByText(messages["alertEvents.missingReview"]),
    ).toBeNull();
    expect(
      screen.queryByRole("button", { name: messages["alertEvents.finish"] }),
    ).toBeNull();
    expect(screen.getByText(messages["alertEvents.unknown"])).toBeTruthy();
    expect(posts()).toHaveLength(1);
  });
  it("fences an origin/session change and never turns a missing record into an empty successful history", async () => {
    let resolve!: (response: Response) => void;
    const late = new Promise<Response>((accept) => {
      resolve = accept;
    });
    reply = (path) =>
      path.includes("origin_node_id")
        ? Promise.resolve(jsonResponse({ ...eventPageFixture(), items: [] }))
        : late;
    mount();
    await waitFor(() =>
      expect(requests.some((row) => row.path.startsWith("/alert-events"))).toBe(
        true,
      ),
    );
    const original = requests.find((row) =>
      row.path.startsWith("/alert-events"),
    )!;
    fireEvent.click(screen.getByRole("button", { name: "test.origin" }));
    await screen.findByText(messages["alertEvents.empty"]);
    expect(original.signal?.aborted).toBe(true);
    await act(async () => resolve(jsonResponse(eventPageFixture())));
    expect(
      screen.queryByText(messages["alerts.code.policy_not_applied"]),
    ).toBeNull();
    reply = async () =>
      jsonResponse({ error: { code: "alert_history_not_queryable" } }, 404);
    fireEvent.change(screen.getByLabelText(messages["alertEvents.eventId"]), {
      target: { value: "1" },
    });
    click("alertEvents.lookup");
    await screen.findByText(messages["alertEvents.missing"]);
    await act(async () => check());
    expect(posts()).toHaveLength(0);
  });
  it("clears the badge after an exact acknowledgement without removing the bell or claiming recovery", async () => {
    let acknowledged = false;
    reply = async (path, method) => {
      if (path === "/alert-episodes/1/acknowledge" && method === "POST") {
        acknowledged = true;
        return jsonResponse(episodeFixture(true));
      }
      if (path === "/alert-episodes/1")
        return jsonResponse(episodeFixture(acknowledged));
      if (path === "/alert-summary")
        return jsonResponse({
          ...summaryFixture(),
          unacknowledged_count: acknowledged ? 0 : 1,
        });
      return jsonResponse(eventPageFixture());
    };
    mount("with-history");
    await screen.findByRole("link", {
      name: messages["alertEvents.badge"].replace("{count}", "1"),
    });
    await openEpisode();
    await acknowledge();
    await screen.findByText(messages["alertEvents.acknowledged"]);
    const bell = await screen.findByRole("link", {
      name: messages["alertEvents.badge"].replace("{count}", "0"),
    });
    expect(bell.querySelector(".ant-badge-count")).toBeNull();
    expect(bell.querySelector("svg")).not.toBeNull();
    expect(posts()).toHaveLength(1);
    expect(posts()[0].path).toBe("/alert-episodes/1/acknowledge");
    expect(screen.getByText(messages["alertEvents.warning"])).toBeTruthy();
  });
  it("polls only the visible local summary at thirty seconds and reports failures as unknown", async () => {
    vi.useFakeTimers();
    let summaries = 0;
    reply = async () =>
      ++summaries === 1
        ? jsonResponse(summaryFixture())
        : jsonResponse({ error: { code: "policy_busy" } }, 503);
    mount(true);
    await act(async () => vi.advanceTimersByTimeAsync(0));
    expect(screen.getByRole("link").getAttribute("aria-label")).toBe(
      messages["alertEvents.badge"].replace("{count}", "1"),
    );
    expect(screen.getByRole("link").getAttribute("href")).toBe(
      "/alerts?view=history",
    );
    await act(async () => {
      visibility = "hidden";
      document.dispatchEvent(new Event("visibilitychange"));
      await vi.advanceTimersByTimeAsync(ALERT_SUMMARY_POLL_MS);
    });
    expect(summaries).toBe(1);
    await act(async () => {
      visibility = "visible";
      document.dispatchEvent(new Event("visibilitychange"));
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(
      screen.getByRole("link", { name: messages["alertEvents.badgeUnknown"] }),
    ).toBeTruthy();
    expect(summaries).toBe(2);
    expect(posts()).toHaveLength(0);
  });
});
