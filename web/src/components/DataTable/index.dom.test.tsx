// @vitest-environment jsdom
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import DataTable from ".";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
it("reuses each row and its real controls, preserving header labels and existing cell props", () => {
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
  }));
  const click = vi.fn();
  render(
    <DataTable<{ id: string; name: string }>
      rowKey="id"
      pagination={false}
      dataSource={[{ id: "one", name: "Same record" }]}
      columns={[
        {
          title: "Name",
          dataIndex: "name",
          onCell: () => ({ id: "original-cell" }),
        },
        {
          title: "Actions",
          render: () => <button onClick={click}>Connect</button>,
        },
      ]}
    />,
  );
  const table = screen.getByRole("table");
  expect(within(table).getAllByText("Same record")).toHaveLength(1);
  expect(
    document.querySelector("#original-cell")?.getAttribute("data-label"),
  ).toBe("Name");
  expect(
    within(table).getByRole("columnheader", { name: "Actions" }),
  ).toBeTruthy();
  fireEvent.click(within(table).getByRole("button", { name: "Connect" }));
  expect(click).toHaveBeenCalledTimes(1);
});
