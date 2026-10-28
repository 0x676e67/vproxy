// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, useNavigate } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { PageScrollReset, ScopeMenuLink } from "./ScopeNavigation";

vi.mock("@umijs/max", async () => {
  const router = await import("react-router-dom");
  return {
    Link: router.Link,
    useLocation: router.useLocation,
    useNavigate: router.useNavigate,
    useNavigationType: router.useNavigationType,
    useIntl: () => ({
      formatMessage: ({ defaultMessage }: { defaultMessage?: string }) =>
        defaultMessage,
    }),
  };
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
it("closes mobile navigation for an ordinary page visit, not a modified new-tab click", () => {
  const close = vi.fn();
  render(
    <MemoryRouter>
      <ScopeMenuLink
        path="/users"
        label="Proxy users"
        messageId="menu.users"
        onNavigate={close}
      >
        <span aria-hidden>team</span>
      </ScopeMenuLink>
    </MemoryRouter>,
  );
  const link = screen.getByRole("link", { name: "Proxy users" });
  fireEvent.click(link, { ctrlKey: true });
  expect(close).not.toHaveBeenCalled();
  fireEvent.click(link);
  expect(close).toHaveBeenCalledTimes(1);
});
it("starts a new page at the top without overriding query changes or Back navigation", () => {
  const scroll = vi.spyOn(window, "scrollTo").mockImplementation(() => {});
  function Host() {
    const navigate = useNavigate();
    return (
      <PageScrollReset>
        <button onClick={() => navigate("/users")}>Users</button>
        <button onClick={() => navigate("/users?target=one")}>Scope</button>
        <button onClick={() => navigate("/traffic")}>Traffic</button>
        <button onClick={() => navigate(-1)}>Back</button>
      </PageScrollReset>
    );
  }
  render(
    <MemoryRouter initialEntries={["/nodes"]}>
      <Host />
    </MemoryRouter>,
  );
  expect(scroll).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText("Users"));
  expect(scroll).toHaveBeenCalledTimes(1);
  expect(scroll).toHaveBeenLastCalledWith({
    top: 0,
    left: 0,
    behavior: "instant",
  });
  fireEvent.click(screen.getByText("Scope"));
  expect(scroll).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByText("Traffic"));
  expect(scroll).toHaveBeenCalledTimes(2);
  fireEvent.click(screen.getByText("Back"));
  expect(scroll).toHaveBeenCalledTimes(2);
});
