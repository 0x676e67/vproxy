import { ProCard } from "@ant-design/pro-components";
import {
  Alert,
  Button,
  Progress,
  Space,
  Statistic,
  Tag,
  Typography,
} from "antd";
import type { ManagedNode } from "../../data/nodes";
import { ControlStatus, HealthStatus, useNodeLabels } from "./labels";

export type DetailTab = "overview" | "health" | "configuration";

export default function NodeCard({
  node,
  parentName,
  onOpen,
}: {
  node: ManagedNode;
  parentName: string | null;
  onOpen: (node: ManagedNode, tab: DetailTab) => void;
}) {
  const { t, number, region, age } = useNodeLabels();
  const metrics = node.metrics;
  const health = node.ipv4;
  const note =
    node.control === "pending"
      ? t("node.pendingNote")
      : node.control === "disconnected"
        ? t("node.staleNote")
        : node.appliedRevision !== node.desiredRevision
          ? t("node.configNote", {
              applied: node.appliedRevision ?? "—",
              desired: node.desiredRevision ?? "—",
            })
          : null;

  return (
    <article aria-label={node.name} className="node-card">
      <ProCard variant="outlined">
        <div className="node-heading">
          <div className="node-identity">
            <Space wrap size={6}>
              <Typography.Title level={3} className="node-title">
                {node.name}
              </Typography.Title>
              {node.local && <Tag color="blue">{t("node.local")}</Tag>}
            </Space>
            <Typography.Text type="secondary" className="node-region">
              {region(node)}
              {node.zone ? ` · ${node.zone}` : ""}
            </Typography.Text>
          </div>
          <ControlStatus node={node} />
        </div>
        <Space wrap size={[4, 6]} className="node-roles">
          {node.relationshipsKnown && node.control !== "pending" && (
            <Tag>{t(node.parentId ? "node.managed" : "node.independent")}</Tag>
          )}
          {node.childCount !== null && node.childCount > 0 && (
            <Tag>{t("node.manages", { count: node.childCount })}</Tag>
          )}
          {__VPROXY_DEMO__ && <Tag>{t("node.proxyRole")}</Tag>}
        </Space>
        <div className="node-parent">
          <Typography.Text type="secondary">
            {!node.relationshipsKnown
              ? t("node.relationshipUnknown")
              : node.parentId
                ? `${t(node.control === "pending" ? "node.plannedParent" : "node.parent")}: ${parentName}`
                : t("node.noParent")}
          </Typography.Text>
          <Typography.Text type="secondary">
            {t("node.proxy")}: {t(`node.${node.proxy}`)}
          </Typography.Text>
        </div>
        <div className="node-metrics">
          {(
            [
              ["node.connections", metrics?.connections, null],
              ["node.upload", metrics?.uploadMbps, "Mbit/s"],
              ["node.download", metrics?.downloadMbps, "Mbit/s"],
            ] as const
          ).map(([key, value, unit]) => (
            <Statistic
              key={key}
              title={t(key)}
              value={value ?? "—"}
              formatter={(item) =>
                typeof item === "number" ? number(item) : item
              }
              suffix={
                unit && value !== undefined ? <small>{unit}</small> : null
              }
            />
          ))}
        </div>
        <section className="node-health" aria-label={t("health.ipv4")}>
          <div className="node-health-heading">
            <Typography.Text strong>
              {health
                ? t("health.summary", {
                    healthy: health.healthy,
                    total: health.total,
                  })
                : t("health.ipv4")}
            </Typography.Text>
            <HealthStatus node={node} />
          </div>
          {health ? (
            <div aria-hidden>
              <Progress
                percent={
                  health.total > 0
                    ? ((health.healthy + health.unhealthy) / health.total) * 100
                    : 0
                }
                success={{
                  percent:
                    health.total > 0
                      ? (health.healthy / health.total) * 100
                      : 0,
                }}
                strokeColor="#ff4d4f"
                showInfo={false}
              />
            </div>
          ) : (
            <div className="unknown-meter" aria-hidden />
          )}
          <Typography.Text type="secondary">
            {node.ipv6
              ? `${t("health.prefixes", { count: node.ipv6.prefixCount })} · ${t("health.activeAddresses", { count: node.ipv6.activeAddresses })}`
              : `${t("health.ipv6")}: ${t("node.unknown")}`}
          </Typography.Text>
        </section>
        <div className="node-resources">
          {(
            [
              ["node.cpu", metrics?.cpuPercent],
              ["node.memory", metrics?.memoryPercent],
            ] as const
          ).map(([key, value]) => (
            <div key={key}>
              <div className="node-resource-label">
                <span>{t(key)}</span>
                <span>
                  {value === undefined
                    ? t("node.unknown")
                    : `${number(value)}%`}
                </span>
              </div>
              {value === undefined ? (
                <div className="unknown-meter" aria-hidden />
              ) : (
                <Progress
                  percent={value}
                  showInfo={false}
                  size="small"
                  aria-label={t(key)}
                />
              )}
            </div>
          ))}
        </div>
        {note && <Alert type="info" title={note} className="node-note" />}
        <div className="node-observations">
          <span>
            {node.observationAgeSeconds === null
              ? t("node.noObservation")
              : t("node.observed", { age: age(node.observationAgeSeconds) })}
          </span>
          <span>
            {node.healthAgeSeconds === null
              ? t("health.noObservation")
              : t("health.observed", { age: age(node.healthAgeSeconds) })}
          </span>
        </div>
        <div className="node-actions">
          {(
            [
              ["overview", "node.details", "node.detailsLabel"],
              ["health", "nodes.health", "node.healthLabel"],
              ["configuration", "nodes.configuration", "node.configLabel"],
            ] as const
          ).map(([tab, label, accessible]) => (
            <Button
              type="link"
              key={tab}
              onClick={() => onOpen(node, tab)}
              aria-label={t(accessible, { name: node.name })}
            >
              {t(label)}
            </Button>
          ))}
        </div>
      </ProCard>
    </article>
  );
}
