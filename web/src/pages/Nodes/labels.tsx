import { Badge, Tag } from "antd";
import type { ManagedNode } from "../../data/nodes";
import { useMessages } from "../../hooks/useMessages";

export function useNodeLabels() {
  const { intl, t } = useMessages();
  const age = (seconds: number | null) => {
    if (seconds === null) return "—";
    const minutes = seconds >= 60;
    return intl.formatRelativeTime(
      -(minutes ? Math.round(seconds / 60) : seconds),
      minutes ? "minute" : "second",
      { numeric: "always" },
    );
  };
  const region = (node: ManagedNode) =>
    node.region ? t(`region.${node.region}`) : node.customRegion || "—";

  return { t, age, region, number: intl.formatNumber };
}

export function ControlStatus({ node }: { node: ManagedNode }) {
  const { t } = useNodeLabels();
  const status =
    node.control === "connected"
      ? "success"
      : node.control === "disconnected"
        ? "warning"
        : "default";
  return (
    <Badge
      status={status}
      text={t(
        !node.relationshipsKnown && node.local
          ? "node.apiReadSuccess"
          : `node.${node.control}`,
      )}
    />
  );
}

export function HealthStatus({ node }: { node: ManagedNode }) {
  const { t } = useNodeLabels();
  if (node.control === "pending") return <Tag>{t("health.notChecked")}</Tag>;
  if (node.ipv4 === null)
    return (
      <Tag>
        {t(
          node.healthAgeSeconds === null ? "health.notChecked" : "health.stale",
        )}
      </Tag>
    );
  if (node.ipv4.unhealthy > 0) {
    return (
      <Tag color="error">
        {t("health.failures", { count: node.ipv4.unhealthy })}
      </Tag>
    );
  }
  if (node.ipv4.unknown > 0) {
    return (
      <Tag color="warning">
        {t("health.unknownCount", { count: node.ipv4.unknown })}
      </Tag>
    );
  }
  return <Tag color="success">{t("health.healthy")}</Tag>;
}

export function ConfigStatus({ node }: { node: ManagedNode }) {
  const { t } = useNodeLabels();
  if (node.control === "pending") return <Tag>{t("config.notEnrolled")}</Tag>;
  if (node.appliedRevision === null || node.desiredRevision === null)
    return <Tag>{t("node.unknown")}</Tag>;
  if (node.control === "disconnected") {
    return <Tag color="warning">{t("config.unconfirmed")}</Tag>;
  }
  return node.appliedRevision === node.desiredRevision ? (
    <Tag color="success">{t("config.synced")}</Tag>
  ) : (
    <Tag color="processing">{t("config.awaiting")}</Tag>
  );
}
