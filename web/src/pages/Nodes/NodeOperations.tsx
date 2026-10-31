import { Collapse } from "antd";
import { useState, type ReactNode } from "react";
import { useMessages } from "../../hooks/useMessages";

/** Keep operation controllers mounted while hidden; a pending review stays open. */
export default function NodeOperations({
  identity,
  pending,
  children,
}: {
  identity: string;
  pending: boolean;
  children: ReactNode;
}) {
  const { t } = useMessages();
  const [expanded, setExpanded] = useState<string | null>(null);
  return (
    <Collapse
      ghost
      activeKey={pending || expanded === identity ? ["operations"] : []}
      onChange={(keys) => setExpanded(keys.length ? identity : null)}
      items={[
        {
          key: "operations",
          label: t("control.operations"),
          forceRender: true,
          children: <div className="management-node-tools">{children}</div>,
        },
      ]}
    />
  );
}
