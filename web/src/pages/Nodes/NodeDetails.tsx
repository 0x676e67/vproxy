import {
  ProDescriptions,
  type ProDescriptionsItemProps,
} from "@ant-design/pro-components";
import { Alert, Drawer, Space, Tabs, Typography } from "antd";
import LanguageSwitch from "../../components/LanguageSwitch";
import type { ManagedNode } from "../../data/nodes";
import type { DetailTab } from "./NodeCard";
import {
  ConfigStatus,
  ControlStatus,
  HealthStatus,
  useNodeLabels,
} from "./labels";

export default function NodeDetails({
  node,
  parentName,
  tab,
  onTab,
  onClose,
}: {
  node: ManagedNode | undefined;
  parentName: string | null;
  tab: DetailTab;
  onTab: (tab: DetailTab) => void;
  onClose: () => void;
}) {
  const { t, region, age, number } = useNodeLabels();
  const columns: ProDescriptionsItemProps<ManagedNode>[] = [
    { title: t("node.id"), dataIndex: "id", copyable: true },
    { title: t("node.version"), dataIndex: "version" },
    {
      title: t("node.platform"),
      render: () => (node?.os ? `${node.os} / ${node.arch}` : "—"),
    },
    { title: t("node.region"), render: () => (node ? region(node) : "—") },
    {
      title: t(
        node?.control === "pending" ? "node.plannedParent" : "node.parent",
      ),
      render: () =>
        !node?.relationshipsKnown
          ? t("node.unknown")
          : (parentName ?? t("node.noParent")),
    },
    {
      title: t(__VPROXY_DEMO__ ? "node.control" : "node.adminApi"),
      render: () => node && <ControlStatus node={node} />,
    },
    { title: t("node.proxy"), render: () => node && t(`node.${node.proxy}`) },
    {
      title: t("node.connections"),
      render: () =>
        node?.metrics ? number(node.metrics.connections) : t("node.unknown"),
    },
    {
      title: t("node.lastObservation"),
      render: () => age(node?.observationAgeSeconds ?? null),
    },
  ];
  const health: ProDescriptionsItemProps<ManagedNode>[] = [
    { title: t("health.source"), dataIndex: "ipv4Address", copyable: true },
    { title: t("health.prefix"), dataIndex: "ipv6Prefix", copyable: true },
    {
      title: t("health.ipv4"),
      render: () => node && <HealthStatus node={node} />,
    },
    ...(
      [
        ["health.healthy", "healthy"],
        ["health.unhealthy", "unhealthy"],
        ["health.unconfirmed", "unknown"],
      ] as const
    ).map(([label, field]) => ({
      title: t(label),
      render: () => (node?.ipv4 ? number(node.ipv4[field]) : t("node.unknown")),
    })),
    {
      title: t("health.lastObservation"),
      render: () => age(node?.healthAgeSeconds ?? null),
    },
  ];
  const configuration: ProDescriptionsItemProps<ManagedNode>[] = [
    {
      title: t("config.applied"),
      render: () =>
        node?.appliedRevision == null ? "—" : `r${node.appliedRevision}`,
    },
    {
      title: t("config.desired"),
      render: () =>
        node?.desiredRevision == null ? "—" : `r${node.desiredRevision}`,
    },
    {
      title: t("config.state"),
      render: () => node && <ConfigStatus node={node} />,
    },
  ];

  return (
    <Drawer
      open={Boolean(node)}
      title={node?.name}
      onClose={onClose}
      size={660}
      destroyOnHidden
      extra={<LanguageSwitch />}
    >
      {node && (
        <Space orientation="vertical" size={20} className="full-width">
          <Typography.Text type="secondary">
            {t(__VPROXY_DEMO__ ? "app.sampleNotice" : "nodes.liveNotice")}
          </Typography.Text>
          <Tabs
            activeKey={tab}
            onChange={(key) => onTab(key as DetailTab)}
            items={[
              { key: "overview", label: t("node.details") },
              { key: "health", label: t("nodes.health") },
              { key: "configuration", label: t("nodes.configuration") },
            ]}
          />
          <ProDescriptions<ManagedNode>
            key={`${node.id}:${tab}`}
            column={1}
            dataSource={node}
            columns={
              tab === "overview"
                ? columns
                : tab === "health"
                  ? health
                  : configuration
            }
            emptyText="—"
          />
          {tab === "health" && (
            <Alert
              type="info"
              title={t(
                __VPROXY_DEMO__ ? "health.coverage" : "health.unavailable",
              )}
              description={t("health.description")}
              showIcon
            />
          )}
          {tab === "configuration" && (
            <Alert
              type="info"
              title={t(
                __VPROXY_DEMO__ ? "config.readOnly" : "config.unavailable",
              )}
              showIcon
            />
          )}
          {node.control === "disconnected" && (
            <Alert type="warning" title={t("node.staleNote")} showIcon />
          )}
          {node.control === "pending" && (
            <Alert type="info" title={t("node.pendingNote")} showIcon />
          )}
        </Space>
      )}
    </Drawer>
  );
}
