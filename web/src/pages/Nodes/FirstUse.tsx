import { Link } from "@umijs/max";
import { Collapse, Typography } from "antd";
import type { PolicyStatus } from "../../api/proxy";
import type { Owner } from "../../api/targets";
import { useMessages } from "../../hooks/useMessages";

/** Guidance uses the card's observation, not a separate readiness check. */
export default function FirstUse({
  policy,
  owner,
  unavailable,
}: {
  policy: PolicyStatus | null;
  owner: Owner | null;
  unavailable: boolean;
}) {
  const { t } = useMessages();
  const runtime =
    unavailable || !policy
      ? "setup.firstUse.unread"
      : !policy.proxy_running
        ? "users.apiOnly"
        : policy.applied_revision === null
          ? "users.degraded"
          : policy.applied_revision !== policy.saved_revision
            ? "users.pending"
            : "users.running";
  return (
    <section aria-label={t("setup.firstUse.title")}>
      <Collapse
        size="small"
        defaultActiveKey={policy?.proxy_running ? [] : ["first-use"]}
        items={[
          {
            key: "first-use",
            label: t("setup.firstUse.title"),
            children: (
              <ol className="management-first-use" role="list">
                <li>
                  <Typography.Text strong>
                    {t("setup.firstUse.users")}
                  </Typography.Text>
                  <Typography.Paragraph type="secondary">
                    {t(
                      unavailable || !owner
                        ? "setup.firstUse.ownerUnknown"
                        : owner.controller_node_id === null
                          ? "setup.firstUse.userHint"
                          : "setup.firstUse.delegated",
                    )}
                  </Typography.Paragraph>
                  <Link to="/users">{t("setup.firstUse.manageUsers")}</Link>
                </li>
                <li>
                  <Typography.Text strong>
                    {t("setup.firstUse.listener")}
                  </Typography.Text>
                  <Typography.Paragraph>{t(runtime)}</Typography.Paragraph>
                  <Typography.Paragraph type="secondary">
                    {t("setup.firstUse.notTested")}
                  </Typography.Paragraph>
                  <Link to="/service">{t("service.title")}</Link>
                </li>
                <li>
                  <Typography.Text strong>
                    {t("setup.firstUse.endpoints")}
                  </Typography.Text>
                  <Typography.Paragraph type="secondary">
                    {t(
                      unavailable
                        ? "setup.firstUse.endpointUnavailable"
                        : "setup.firstUse.endpointHint",
                    )}
                  </Typography.Paragraph>
                </li>
              </ol>
            ),
          },
        ]}
      />
    </section>
  );
}
