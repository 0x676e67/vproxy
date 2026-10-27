// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://localhost/"}
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { ConfigProvider } from "antd";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import EndpointEditor, { type EditableEndpoint } from "./EndpointEditor";

vi.mock("../../hooks/useMessages", () => ({
  useMessages: () => ({ t: (key: string) => key }),
}));
beforeEach(() => {
  // Capability scaffolding, not a layout substitute. React and AntD Form/Radio
  // really mount, unregister/preserve fields, validate and dispatch submit.
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
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const entry: EditableEndpoint = {
  id: "A".repeat(22),
  protocol: "auto",
  bind: "0.0.0.0:1080",
  configured_public_address: "startup.example:1080",
  selection: { mode: "inherit" },
};
function mount(value = entry, busy = false, blocked = false) {
  const submit = vi.fn(async () => {}),
    cancel = vi.fn();
  const view = render(
    <ConfigProvider theme={{ token: { motion: false } }}>
      <EndpointEditor
        entry={value}
        busy={busy}
        blocked={blocked}
        notice={null}
        cancel={cancel}
        submit={submit}
      />
    </ConfigProvider>,
  );
  return { ...view, submit, cancel };
}

describe("endpoint declaration form", () => {
  it("preserves custom host/port through explicit mode changes and submits only metadata", async () => {
    const { submit } = mount();
    fireEvent.click(
      screen.getByRole("radio", { name: "connections.mode.custom" }),
    );
    const host = await screen.findByRole("textbox", {
      name: "connections.clientHost",
    });
    const port = screen.getByRole("textbox", {
      name: "connections.clientPort",
    });
    fireEvent.change(host, { target: { value: "PROXY.example" } });
    fireEvent.change(port, { target: { value: "8443" } });
    fireEvent.click(
      screen.getByRole("radio", { name: "connections.mode.hidden" }),
    );
    await waitFor(() => {
      expect(
        screen.queryByRole("textbox", { name: "connections.clientHost" }),
      ).toBeNull();
    });
    await screen.findByText("connections.hiddenHint");
    fireEvent.click(
      screen.getByRole("radio", { name: "connections.mode.custom" }),
    );
    expect(
      (
        (await screen.findByRole("textbox", {
          name: "connections.clientHost",
        })) as HTMLInputElement
      ).value,
    ).toBe("PROXY.example");
    expect(
      (
        screen.getByRole("textbox", {
          name: "connections.clientPort",
        }) as HTMLInputElement
      ).value,
    ).toBe("8443");
    fireEvent.click(
      screen.getByRole("button", { name: "connections.saveDeclaration" }),
    );
    await waitFor(() => expect(submit).toHaveBeenCalledOnce());
    expect(submit).toHaveBeenCalledWith({
      mode: "custom",
      public_address: "proxy.example:8443",
    });
    expect(screen.queryByRole("combobox")).toBeNull();
    expect(screen.getByText("AUTO")).toBeTruthy();
    expect(screen.queryByLabelText(/password/i)).toBeNull();
  });

  it("keeps inherit and hidden distinct without implicit address fields", async () => {
    const { submit } = mount();
    fireEvent.click(
      screen.getByRole("button", { name: "connections.saveDeclaration" }),
    );
    await waitFor(() =>
      expect(submit).toHaveBeenCalledWith({ mode: "inherit" }),
    );
    fireEvent.click(
      screen.getByRole("radio", { name: "connections.mode.hidden" }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "connections.saveDeclaration" }),
    );
    await waitFor(() =>
      expect(submit).toHaveBeenLastCalledWith({ mode: "hidden" }),
    );
    expect(submit).toHaveBeenCalledTimes(2);
  });

  it("does not submit invalid host/port or a blocked form", async () => {
    const { submit } = mount();
    fireEvent.click(
      screen.getByRole("radio", { name: "connections.mode.custom" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "connections.clientHost" }),
      { target: { value: "user:secret@proxy.example" } },
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "connections.clientPort" }),
      { target: { value: "00080" } },
    );
    await waitFor(() =>
      expect(
        (
          screen.getByRole("button", {
            name: "connections.saveDeclaration",
          }) as HTMLButtonElement
        ).disabled,
      ).toBe(true),
    );
    expect(submit).not.toHaveBeenCalled();
    cleanup();
    mount(entry, false, true);
    expect(
      (
        screen.getByRole("button", {
          name: "connections.saveDeclaration",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });
});
