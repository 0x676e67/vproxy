// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { ConfigProvider } from "antd";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { TrafficMetadata } from "../../api/traffic";
import messages from "../../locales/en-US";
import { Completeness } from "./index";

vi.mock("@umijs/max", async () => {
  const router = await import("react-router-dom");
  return { Link: router.Link, useLocation: router.useLocation };
});
vi.mock("../../hooks/useMessages", async () => {
  const captions = (await import("../../locales/en-US")).default;
  return {
    useMessages: () => ({
      intl: { locale: "en-US" },
      t: (id: keyof typeof captions) => captions[id],
    }),
  };
});

afterEach(cleanup);
const value: TrafficMetadata = {
  definition: "accepted_effective_payload_v1",
  origin_node_id: "A".repeat(22),
  meter_epoch: "AQEBAQEBAQEBAQEBAQEBAQ",
  meter_started_at_unix_ms: null,
  checkpoint_cursor: "0",
  last_checkpoint_at_unix_ms: null,
  last_run_clean: false,
  loss_possible: false,
  history_gap: false,
  time_uncertain: false,
  observed_at_unix_ms: null,
  scope: { kind: "node", id: null },
};

describe("checkpoint warnings", () => {
  it("explains older source totals instead of claiming separate zero HTTP and HTTPS usage", () => {
    const { rerender } = render(
      <Completeness value={{ ...value, http_split: false }} />,
    );
    expect(screen.getByText(messages["traffic.httpUnsplit"])).toBeTruthy();
    rerender(<Completeness value={{ ...value, http_split: true }} />);
    expect(screen.queryByRole("alert")).toBeNull();
  });
  it("shows the local stage, retains older-server warnings and clears on recovery", () => {
    const view = (failed: boolean, stage?: "store") => (
      <ConfigProvider theme={{ token: { motion: false } }}>
        <Completeness
          value={value}
          checkpointError={failed}
          checkpointStage={stage}
        />
      </ConfigProvider>
    );
    const { rerender } = render(view(true, "store"));
    expect(
      screen.getByText(
        `${messages["traffic.checkpointError"]} ${messages["traffic.checkpointStage.store"]}`,
      ),
    ).toBeTruthy();
    rerender(view(true));
    expect(screen.getByText(messages["traffic.checkpointError"])).toBeTruthy();
    expect(screen.queryByText(/Failed during storage/)).toBeNull();
    rerender(view(false, "store"));
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("does not label a remote durable snapshot with local process health", () => {
    render(
      <ConfigProvider theme={{ token: { motion: false } }}>
        <Completeness
          value={value}
          checkpointError
          checkpointStage="store"
          remote
        />
      </ConfigProvider>,
    );
    expect(screen.getByText(messages["traffic.remoteOpenRun"])).toBeTruthy();
    expect(screen.queryByText(/Failed during storage/)).toBeNull();
    expect(screen.queryByText(messages["traffic.checkpointError"])).toBeNull();
  });
});
