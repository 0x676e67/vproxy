import { Descriptions } from "antd";
import type { AlertCoverage } from "../../api/alerts";
import type { NodeAlertCoverage } from "../../api/nodeAlerts";
import { useMessages } from "../../hooks/useMessages";

export default function ObservationCoverage({
  value,
}: {
  value: AlertCoverage | NodeAlertCoverage;
}) {
  const { t } = useMessages();
  const sources = [
    ["local_egress", "alerts.localEgress"],
    ["local_traffic", "alerts.localTraffic"],
    ["local_management_https", "alerts.localManagementHttps"],
    ["local_node_tls", "alerts.localNodeTls"],
    ["local_proxy_tls", "alerts.localProxyTls"],
  ] as const;
  return (
    <Descriptions
      size="small"
      column={{ xs: 1, sm: 2 }}
      items={[
        ...sources.map(([key, label]) => ({
          key,
          label: t(label),
          children: t(value[key] ? "alerts.enabled" : "alerts.disabled"),
        })),
        {
          key: "expected",
          label: t("alerts.localProxyExpected"),
          children: t(
            value.local_proxy_expected
              ? "alerts.expected"
              : "alerts.notExpected",
          ),
        },
        ...("remote_cached" in value
          ? [
              {
                key: "remote",
                label: t("alerts.remoteCached"),
                children: t(
                  value.remote_cached ? "alerts.enabled" : "alerts.disabled",
                ),
              },
              {
                key: "remote-observation",
                label: t("alerts.remoteObservation"),
                children: t(
                  value.remote_observation
                    ? "alerts.backgroundEnabled"
                    : "alerts.backgroundDisabled",
                ),
              },
            ]
          : []),
      ]}
    />
  );
}
