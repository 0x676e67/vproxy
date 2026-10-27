// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import ProjectLink from ".";

vi.mock("../../hooks/useMessages", () => ({
  useMessages: () => ({ t: () => "GitHub repository" }),
}));
afterEach(cleanup);

it("opens the public project without forwarding the management page or retaining an opener", () => {
  render(<ProjectLink />);
  const link = screen.getByRole("link", { name: "GitHub repository" });
  expect(link.getAttribute("href")).toBe("https://github.com/0x676e67/vproxy");
  expect(link.getAttribute("target")).toBe("_blank");
  expect(link.getAttribute("rel")).toBe("noopener noreferrer");
});
