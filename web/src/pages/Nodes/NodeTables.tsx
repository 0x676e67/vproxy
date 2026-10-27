import { ProTable, type ProColumns } from "@ant-design/pro-components";
import { Button, Space, Typography } from "antd";
import type { ManagedNode } from "../../data/nodes";
import type { DetailTab } from "./NodeCard";
import {
  ConfigStatus,
  ControlStatus,
  HealthStatus,
  useNodeLabels,
} from "./labels";

export default function NodeTables({
  nodes,
  mode,
  onOpen,
}: {
  nodes: ManagedNode[];
  mode: "health" | "configuration";
  onOpen: (node: ManagedNode, tab: DetailTab) => void;
}) {
  const { t, region, age } = useNodeLabels();
  const identity: ProColumns<ManagedNode>[] = [
    {
      title: t("node.name"),
      dataIndex: "name",
      width: 180,
      render: (_, node) => (
        <Space orientation="vertical" size={0}>
          <Button
            type="link"
            className="node-table-link"
            onClick={() => onOpen(node, mode)}
            aria-label={t("node.detailsLabel", { name: node.name })}
          >
            {node.name}
          </Button>
          <Typography.Text type="secondary">{region(node)}</Typography.Text>
        </Space>
      ),
    },
    {
      title: t(__VPROXY_DEMO__ ? "node.control" : "node.adminApi"),
      width: 160,
      render: (_, node) => <ControlStatus node={node} />,
    },
  ];
  const health: ProColumns<ManagedNode>[] = [
    {
      title: t("health.ipv4"),
      width: 200,
      render: (_, node) => (
        <Space orientation="vertical" size={4}>
          {node.ipv4 && (
            <span>
              {t("health.summary", {
                healthy: node.ipv4.healthy,
                total: node.ipv4.total,
              })}
            </span>
          )}
          <HealthStatus node={node} />
        </Space>
      ),
    },
    {
      title: t("health.ipv6"),
      width: 200,
      render: (_, node) =>
        node.ipv6 ? (
          <Space orientation="vertical" size={0}>
            <span>
              {t("health.prefixes", { count: node.ipv6.prefixCount })}
            </span>
            <Typography.Text type="secondary">
              {t("health.activeAddresses", {
                count: node.ipv6.activeAddresses,
              })}
            </Typography.Text>
          </Space>
        ) : (
          t("node.unknown")
        ),
    },
    {
      title: t("health.lastObservation"),
      width: 180,
      render: (_, node) =>
        node.healthAgeSeconds === null
          ? t("health.noObservation")
          : age(node.healthAgeSeconds),
    },
  ];
  const configuration: ProColumns<ManagedNode>[] = [
    {
      title: t("config.applied"),
      dataIndex: "appliedRevision",
      width: 160,
      render: (_, node) =>
        node.appliedRevision === null ? "—" : `r${node.appliedRevision}`,
    },
    {
      title: t("config.desired"),
      dataIndex: "desiredRevision",
      width: 160,
      render: (_, node) =>
        node.desiredRevision === null ? "—" : `r${node.desiredRevision}`,
    },
    {
      title: t("config.state"),
      width: 200,
      render: (_, node) => <ConfigStatus node={node} />,
    },
  ];

  return (
    <ProTable<ManagedNode>
      rowKey="id"
      columns={[...identity, ...(mode === "health" ? health : configuration)]}
      dataSource={nodes}
      headerTitle={t(
        mode === "health" ? "health.title" : "nodes.configuration",
      )}
      tooltip={t(
        mode === "health" ? "health.description" : "config.description",
      )}
      search={false}
      options={false}
      pagination={{ pageSize: 10, hideOnSinglePage: true }}
      scroll={{ x: 840 }}
      cardBordered
      locale={{ emptyText: t("nodes.empty") }}
    />
  );
}
