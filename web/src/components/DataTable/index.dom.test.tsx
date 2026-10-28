// @vitest-environment jsdom
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { ProColumns } from "@ant-design/pro-components";
import DataTable, { labelledColumns } from ".";

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

it("labels grouped ProTable leaves without changing renderers, cell handlers or the source schema", () => {
  type Row = { id: string };
  const click = vi.fn();
  const render = () => <button onClick={click}>Inspect</button>;
  const title = () => <span>Inspect</span>;
  const columns: ProColumns<Row>[] = [
    {
      title: "Group",
      children: [
        {
          title: "Identifier",
          dataIndex: "id",
          valueType: "text",
          onCell: () => ({ id: "preserved", colSpan: 2, onClick: click }),
        },
        { title, render },
      ],
    },
  ];
  Object.freeze(columns[0].children![0]);
  Object.freeze(columns[0].children);
  Object.freeze(columns[0]);
  Object.freeze(columns);
  const labelled = labelledColumns(columns);
  const leaves = labelled[0].children!;
  expect(labelled).not.toBe(columns);
  expect(leaves).not.toBe(columns[0].children);
  expect(leaves[0].valueType).toBe("text");
  expect(leaves[0].onCell?.({ id: "one" }, 0)).toEqual({
    id: "preserved",
    colSpan: 2,
    onClick: click,
    "data-label": "Identifier",
  });
  expect(leaves[1].title).toBe(title);
  expect(leaves[1].render).toBe(render);
  expect(leaves[1].onCell?.({ id: "one" }, 0)).toEqual({
    "data-label": undefined,
  });
});
