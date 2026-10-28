import { Table, type TableProps } from "antd";
import type { ColumnsType } from "antd/es/table";
import { useMemo } from "react";

/** Keep the same table, controls and focus order when records reflow on phones.
 * Field labels are derived from the existing headers, never a second schema. */
function labelledColumns<T extends object>(
  columns: ColumnsType<T>,
): ColumnsType<T> {
  return columns.map((column) => {
    if ("children" in column) {
      return { ...column, children: labelledColumns(column.children) };
    }
    return {
      ...column,
      onCell: (record, index) => ({
        ...column.onCell?.(record, index),
        "data-label":
          typeof column.title === "string" ? column.title : undefined,
      }),
    };
  });
}

export default function DataTable<T extends object>({
  columns,
  className,
  ...props
}: TableProps<T>) {
  const labelled = useMemo(
    () => columns && labelledColumns(columns),
    [columns],
  );
  return (
    <Table<T>
      {...props}
      columns={labelled}
      className={["management-data-table", className].filter(Boolean).join(" ")}
    />
  );
}
