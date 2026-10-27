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
import type { CertificateStatus as Status } from "../../api/certificates";
import { jsonResponse, sessionFixture } from "../../api/client.fixtures";
import { ManagementProvider, useManagement } from "../../auth/context";
import ManagementGate from "../../components/ManagementGate";
import messages from "../../locales/en-US";
import CertificateStatus from "./CertificateStatus";

vi.mock("../../hooks/useMessages", async () => {
  const captions = (await import("../../locales/en-US")).default;
  return {
    useMessages: () => ({
      intl: { locale: "en-US" },
      t: (id: keyof typeof captions) => captions[id],
    }),
  };
});

const NODE_A = "AAECAwQFBgcICQoLDA0ODw";
const NODE_B = "EBESExQVFhcYGRobHB0eHw";
const ENDPOINT = "ICEiIyQlJicoKSorLC0uLw";
const OLD_SHA = "ab".repeat(32);
const NEW_SHA = "ef".repeat(32);
function status(nodeId = NODE_A, automatic = false, sha256 = OLD_SHA): Status {
  const leaf = {
    sha256,
    not_before_unix_s: "100",
    not_after_unix_s: "1000000",
  };
  return {
    node_id: nodeId,
    observed_at_unix_s: "150",
    entries: [
      {
        role: "management",
        source: automatic ? "acme" : "manual",
        id: null,
        protocol: null,
        state: "loaded",
        certificate: leaf,
        valid_now: true,
      },
      {
        role: "node",
        source: "manual",
        id: null,
        protocol: null,
        state: "disabled",
        certificate: null,
        valid_now: null,
      },
      {
        role: "proxy",
        source: "manual",
        id: ENDPOINT,
        protocol: "https",
        state: "loaded",
        certificate: { ...leaf, sha256: "cd".repeat(32) },
        valid_now: true,
      },
    ],
  };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}
let readStatus: () => Promise<Response>;
let checkSession: () => Promise<void>;
let requests: { path: string; method: string; signal: AbortSignal | null }[];
beforeEach(() => {
  requests = [];
  readStatus = async () => jsonResponse(status());
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
      const path = String(input),
        method = init?.method ?? "GET";
      requests.push({ path, method, signal: init?.signal ?? null });
      if (path === "/api/v1/auth/session")
        return jsonResponse({
          ...sessionFixture(),
          expires_at: Math.floor(Date.now() / 1000) + 3600,
        });
      if (path === "/api/v1/tls/status" && method === "GET")
        return readStatus();
      if (path === "/api/v1/tls/acme" && method === "GET")
        return jsonResponse({
          mode: "acme",
          environment: "staging",
          challenge: "http-01",
          certificate: {
            not_before_unix_s: "100",
            not_after_unix_s: "1000000",
            available: true,
          },
          activity: "waiting",
          next_attempt_at_unix_s: "1000",
          last_failure: null,
          observed_at_unix_s: "150",
        });
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
  const [nodeId, setNodeId] = useState(NODE_A);
  const [rendered, setRendered] = useState(0);
  checkSession = () => controller.check();
  return (
    <>
      <button onClick={() => setNodeId(NODE_B)}>test.node</button>
      <button onClick={() => setRendered((value) => value + 1)}>
        test.render
      </button>
      <output data-testid="render-count">{rendered}</output>
      <ManagementGate>
        <p>Local node remains visible</p>
        <CertificateStatus disabled={false} nodeId={nodeId} />
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
  await screen.findByRole("button", { name: messages["certificates.title"] });
}
const reads = () =>
  requests.filter((request) => request.path === "/api/v1/tls/status");
const acmeReads = () =>
  requests.filter((request) => request.path === "/api/v1/tls/acme");
const toggle = () =>
  fireEvent.click(
    screen.getByRole("button", { name: messages["certificates.title"] }),
  );

describe("local loaded certificate panel", () => {
  it("reads only on expansion or explicit refresh and labels loaded validity without claiming trust", async () => {
    await mount();
    expect(reads()).toHaveLength(0);
    toggle();
    await screen.findByText(OLD_SHA);
    expect(
      screen.getByText(messages["certificates.validityOnly"]),
    ).toBeTruthy();
    expect(screen.getByText(messages["certificates.role.proxy"])).toBeTruthy();
    expect(
      screen
        .getByText(`${ENDPOINT.slice(0, 8)}…`)
        .closest("[title]")
        ?.getAttribute("title"),
    ).toBe(ENDPOINT);
    expect(
      screen.getAllByText(messages["certificates.condition.within_validity"]),
    ).toHaveLength(2);
    expect(
      screen.queryByRole("button", { name: messages["acme.title"] }),
    ).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "test.render" }));
    expect(screen.getByTestId("render-count").textContent).toBe("1");
    expect(reads()).toHaveLength(1);
    readStatus = async () => {
      const value = status();
      value.entries[0] = {
        ...value.entries[0],
        certificate: {
          sha256: NEW_SHA,
          not_before_unix_s: "100",
          not_after_unix_s: "120",
        },
        valid_now: false,
      };
      return jsonResponse(value);
    };
    fireEvent.click(
      screen.getByRole("button", { name: messages["certificates.refresh"] }),
    );
    await screen.findByText(NEW_SHA);
    expect(
      screen.getByText(messages["certificates.condition.expired"]),
    ).toBeTruthy();
    expect(reads()).toHaveLength(2);
    expect(requests.every((request) => request.method === "GET")).toBe(true);
  });

  it("keeps 404 local and nests legacy ACME status only after an explicit ACME-source snapshot", async () => {
    readStatus = async () =>
      jsonResponse(
        { error: { code: "not_found", message: "private-certificate-marker" } },
        404,
      );
    await mount();
    toggle();
    await screen.findByText(messages["certificates.unsupported"]);
    expect(screen.getByText("Local node remains visible")).toBeTruthy();
    expect(screen.queryByText("private-certificate-marker")).toBeNull();
    expect(acmeReads()).toHaveLength(0);
    readStatus = async () => jsonResponse(status(NODE_A, true));
    fireEvent.click(
      screen.getByRole("button", { name: messages["certificates.refresh"] }),
    );
    await screen.findByRole("button", { name: messages["acme.title"] });
    expect(acmeReads()).toHaveLength(0);
    fireEvent.click(
      screen.getByRole("button", { name: messages["acme.title"] }),
    );
    await screen.findByText(messages["acme.stagingWarning"]);
    expect(acmeReads()).toHaveLength(1);
    expect(reads()).toHaveLength(2);
  });

  it("aborts closing and ignores the old response after reopening", async () => {
    const late = deferred<Response>();
    readStatus = () => late.promise;
    await mount();
    toggle();
    await waitFor(() => expect(reads()).toHaveLength(1));
    const signal = reads()[0].signal;
    toggle();
    await waitFor(() => expect(signal?.aborted).toBe(true));
    readStatus = async () => jsonResponse(status(NODE_A, false, NEW_SHA));
    toggle();
    await screen.findByText(NEW_SHA);
    await act(async () => {
      late.resolve(jsonResponse(status()));
    });
    expect(screen.queryByText(OLD_SHA)).toBeNull();
    expect(screen.getByText(NEW_SHA)).toBeTruthy();
    expect(reads()).toHaveLength(2);
  });

  it("requires a new expansion after session revalidation and rejects its abort-ignoring old response", async () => {
    const late = deferred<Response>();
    readStatus = () => late.promise;
    await mount();
    toggle();
    await waitFor(() => expect(reads()).toHaveLength(1));
    const signal = reads()[0].signal;
    await act(async () => {
      await checkSession();
    });
    expect(signal?.aborted).toBe(true);
    expect(
      screen
        .getByRole("button", { name: messages["certificates.title"] })
        .getAttribute("aria-expanded"),
    ).toBe("false");
    expect(reads()).toHaveLength(1);
    readStatus = async () => jsonResponse(status(NODE_A, false, NEW_SHA));
    toggle();
    await screen.findByText(NEW_SHA);
    await act(async () => {
      late.resolve(jsonResponse(status()));
    });
    expect(screen.queryByText(OLD_SHA)).toBeNull();
    expect(reads()).toHaveLength(2);
  });

  it("closes on local node identity changes and never installs another node's late snapshot", async () => {
    const late = deferred<Response>();
    readStatus = () => late.promise;
    await mount();
    toggle();
    await waitFor(() => expect(reads()).toHaveLength(1));
    const signal = reads()[0].signal;
    fireEvent.click(screen.getByRole("button", { name: "test.node" }));
    expect(signal?.aborted).toBe(true);
    expect(
      screen
        .getByRole("button", { name: messages["certificates.title"] })
        .getAttribute("aria-expanded"),
    ).toBe("false");
    expect(reads()).toHaveLength(1);
    readStatus = async () => jsonResponse(status(NODE_B, false, NEW_SHA));
    toggle();
    await screen.findByText(NEW_SHA);
    await act(async () => {
      late.resolve(jsonResponse(status()));
    });
    expect(screen.queryByText(OLD_SHA)).toBeNull();
    expect(screen.getByText(NEW_SHA)).toBeTruthy();
    expect(reads()).toHaveLength(2);
  });
});
