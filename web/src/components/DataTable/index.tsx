import { Table, type TableProps } from "antd";
import type { ProColumns } from "@ant-design/pro-components";
import type { ColumnsType, ColumnType } from "antd/es/table";
import { useMemo } from "react";

interface LabelledColumn<T extends object> {
  title?: unknown;
  children?: LabelledColumn<T>[];
  onCell?: ColumnType<T>["onCell"];
}

/** Keep the same table, controls and focus order when records reflow on phones.
 * Field labels are derived from the existing headers, never a second schema. */
export function labelledColumns<T extends object>(
  columns: ColumnsType<T>,
): ColumnsType<T>;
export function labelledColumns<T extends object>(
  columns: ProColumns<T>[],
): ProColumns<T>[];
export function labelledColumns<T extends object>(
  columns: LabelledColumn<T>[],
): LabelledColumn<T>[] {
  return columns.map(function label(column): LabelledColumn<T> {
    if (column.children) {
      return { ...column, children: column.children.map(label) };
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
