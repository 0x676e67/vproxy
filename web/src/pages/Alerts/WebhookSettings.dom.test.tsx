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
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import type { WebhookChange, WebhookView } from "../../api/notifications";
import {
  WEBHOOK_NODE,
  WEBHOOK_OPERATION,
  deliveryFixture,
  webhookFixture,
} from "../../api/notifications.fixtures";
import { ManagementProvider, useManagement } from "../../auth/context";
import { JOURNAL_PREFIX } from "../../auth/review-journal";
import messages from "../../locales/en-US";
import WebhookSettings from "./WebhookSettings";

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
let server: WebhookView;
let posts: { path: string; input: unknown; csrf: unknown }[];
let loseAnswer: boolean;
let currentSession: ReturnType<typeof sessionFixture>;
let pausePost: Promise<void> | null;
let checkSession: () => Promise<void>;
beforeEach(() => {
  server = webhookFixture();
  posts = [];
  loseAnswer = false;
  currentSession = sessionFixture();
  pausePost = null;
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
  }));
  const computed = window.getComputedStyle.bind(window);
  vi.spyOn(window, "getComputedStyle").mockImplementation((element) =>
    computed(element),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      const path = String(url).replace(/^\/api\/v1/, ""),
        method = init?.method ?? "GET";
      if (path === "/auth/session")
        return jsonResponse({
          ...currentSession,
          expires_at: Math.floor(Date.now() / 1000) + 3600,
        });
      if (path === "/node")
        return jsonResponse({
          node_id: WEBHOOK_NODE,
          name: "Fixture",
          version: "test",
          os: "test",
          arch: "test",
          capabilities: [],
        });
      if (method === "GET" && path === "/notifications/webhook")
        return jsonResponse(server);
      if (method === "POST" && path.startsWith("/notifications/webhook")) {
        const input = JSON.parse(String(init?.body));
        posts.push({
          path,
          input,
          csrf: (init?.headers as Record<string, string>)["X-CSRF-Token"],
        });
        if (path.endsWith("/retry"))
          server = {
            ...server,
            pending: {
              ...server.pending!,
              outcome: "ready",
              http_status: null,
            },
          };
        else {
          const change = input as WebhookChange;
          server = {
            ...server,
            revision: String(BigInt(server.revision) + 1n),
            operation_id: change.operation_id,
            enabled: change.enabled,
            automatic_retry: change.automatic_retry,
            configured: !change.clear_destination,
            has_bearer:
              !change.clear_destination &&
              !change.clear_bearer &&
              (!!change.bearer || server.has_bearer),
            pending: null,
          };
        }
        const response = structuredClone(server);
        if (pausePost) await pausePost;
        if (loseAnswer) throw new TypeError("fixture lost response");
        return jsonResponse(response);
      }
      throw new Error("Unexpected test resource");
    }),
  );
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function mount() {
  return render(
    <ConfigProvider
      theme={{ token: { motion: false } }}
      wave={{ disabled: true }}
    >
      <ManagementProvider>
        <Probe />
        <WebhookSettings />
      </ManagementProvider>
    </ConfigProvider>,
  );
}
function Probe() {
  const { controller } = useManagement();
  checkSession = () => controller.check();
  return null;
}
async function ready(view: ReturnType<typeof mount>) {
  await waitFor(() =>
    expect(
      (
        within(view.container).getByRole("button", {
          name: messages["notifications.save"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(false),
  );
}
const click = (view: ReturnType<typeof mount>, key: keyof typeof messages) =>
  fireEvent.click(
    within(view.container).getByRole("button", { name: messages[key] }),
  );
async function confirm(title: keyof typeof messages) {
  const modal = await screen.findByRole("dialog", { name: messages[title] });
  fireEvent.click(
    within(modal).getByRole("button", {
      name: messages["notifications.confirm"],
    }),
  );
}
function fill(view: ReturnType<typeof mount>) {
  fireEvent.click(
    within(view.container).getByRole("switch", {
      name: messages["notifications.enable"],
    }),
  );
  fireEvent.change(
    within(view.container).getByLabelText(messages["notifications.url"]),
    { target: { value: "https://hooks.example/test-secret?token=fixture" } },
  );
  fireEvent.change(
    within(view.container).getByLabelText(messages["notifications.token"]),
    { target: { value: "fixture-bearer" } },
  );
}

describe("webhook settings and original unknown results", () => {
  it("starts disabled and sends one confirmed local write without storing capabilities", async () => {
    const view = mount();
    await ready(view);
    expect(posts).toHaveLength(0);
    expect(
      (
        within(view.container).getByRole("switch", {
          name: messages["notifications.enable"],
        }) as HTMLButtonElement
      ).getAttribute("aria-checked"),
    ).toBe("false");
    fill(view);
    click(view, "notifications.save");
    expect(posts).toHaveLength(0);
    await confirm("notifications.save");
    await waitFor(() => expect(posts).toHaveLength(1));
    await ready(view);
    expect(posts[0].path).toBe("/notifications/webhook");
    expect(posts[0].csrf).toBe(sessionFixture().csrf_token);
    expect((posts[0].input as WebhookChange).expected_node_id).toBe(
      WEBHOOK_NODE,
    );
    expect(
      (
        within(view.container).getByLabelText(
          messages["notifications.url"],
        ) as HTMLInputElement
      ).value,
    ).toBe("");
    expect(
      (
        within(view.container).getByLabelText(
          messages["notifications.token"],
        ) as HTMLInputElement
      ).value,
    ).toBe("");
    expect(
      Object.keys(localStorage).some((key) =>
        key.startsWith(JOURNAL_PREFIX + "notifications."),
      ),
    ).toBe(false);
  });
  it("keeps a local input error editable without creating a review note or request", async () => {
    const view = mount();
    await ready(view);
    fill(view);
    fireEvent.change(
      within(view.container).getByLabelText(messages["notifications.url"]),
      { target: { value: "http://hooks.example/" } },
    );
    click(view, "notifications.save");
    await confirm("notifications.save");
    await within(view.container).findByText(messages["notifications.invalid"]);
    await ready(view);
    expect(posts).toHaveLength(0);
    expect(
      Object.keys(localStorage).some((key) =>
        key.startsWith(JOURNAL_PREFIX + "notifications."),
      ),
    ).toBe(false);
  });
  it("restores only metadata after a lost answer and never replays the secret write", async () => {
    loseAnswer = true;
    let view = mount();
    await ready(view);
    fill(view);
    click(view, "notifications.save");
    await confirm("notifications.save");
    await within(view.container).findByText(
      messages["notifications.reviewRequired"],
    );
    const notes = Object.keys(localStorage).filter((key) =>
      key.startsWith(JOURNAL_PREFIX + "notifications."),
    );
    expect(notes).toHaveLength(1);
    const raw = localStorage.getItem(notes[0])!;
    expect(raw).toContain((posts[0].input as WebhookChange).operation_id);
    for (const secret of ["hooks.example", "test-secret", "fixture-bearer"])
      expect(raw).not.toContain(secret);
    view.unmount();
    loseAnswer = false;
    view = mount();
    await within(view.container).findByText(
      messages["notifications.result.saved"],
    );
    expect(posts).toHaveLength(1);
    expect(
      (
        within(view.container).getByRole("button", {
          name: messages["notifications.save"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    click(view, "notifications.finishReview");
    await confirm("notifications.finishReview");
    await ready(view);
    expect(localStorage.getItem(notes[0])).toBeNull();
    expect(posts).toHaveLength(1);
  });
  it("retains the original actor note and rejects a late answer after session replacement", async () => {
    let release = () => {};
    pausePost = new Promise<void>((resolve) => {
      release = resolve;
    });
    try {
      const view = mount();
      await ready(view);
      fill(view);
      click(view, "notifications.save");
      await confirm("notifications.save");
      await waitFor(() => expect(posts).toHaveLength(1));
      currentSession = {
        ...sessionFixture("another"),
        administrator: { id: "B".repeat(21) + "Q", username: "another" },
      };
      server = {
        ...webhookFixture(),
        revision: "2",
        operation_id: WEBHOOK_OPERATION,
        configured: true,
      };
      await act(() => checkSession());
      await ready(view);
      expect(
        (
          within(view.container).getByRole("switch", {
            name: messages["notifications.enable"],
          }) as HTMLElement
        ).getAttribute("aria-checked"),
      ).toBe("false");
      await act(async () => {
        release();
        await Promise.resolve();
      });
      expect(
        (
          within(view.container).getByRole("switch", {
            name: messages["notifications.enable"],
          }) as HTMLElement
        ).getAttribute("aria-checked"),
      ).toBe("false");
      const notes = Object.keys(localStorage).filter((key) =>
        key.startsWith(JOURNAL_PREFIX + "notifications."),
      );
      expect(notes).toHaveLength(1);
      expect(
        JSON.parse(localStorage.getItem(notes[0])!).value.administratorId,
      ).toBe(sessionFixture().administrator.id);
      expect(
        within(view.container).queryByText(
          messages["notifications.reviewRequired"],
        ),
      ).toBeNull();
      expect(posts).toHaveLength(1);
    } finally {
      release();
    }
  });
  it("keeps pending delivery protected until explicit discard, and retry carries only original assertions", async () => {
    server = {
      ...webhookFixture(),
      enabled: true,
      configured: true,
      revision: "1",
      operation_id: WEBHOOK_OPERATION,
      pending: deliveryFixture(),
    };
    const view = mount();
    await within(view.container).findByText(deliveryFixture().id);
    expect(
      (
        within(view.container).getByRole("button", {
          name: messages["notifications.save"],
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    fireEvent.click(
      within(view.container).getByLabelText(
        messages["notifications.discardHint"],
      ),
    );
    await ready(view);
    click(view, "notifications.retry");
    await confirm("notifications.retry");
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0].path).toBe("/notifications/webhook/retry");
    expect(posts[0].input).toEqual({
      expected_node_id: WEBHOOK_NODE,
      expected_revision: "1",
      delivery_id: deliveryFixture().id,
      expected_attempts: 1,
    });
    await within(view.container).findByText(
      messages["notifications.outcome.ready"],
    );
  });
});
