import { Link } from "@umijs/max";
import { Collapse, Descriptions, Space, Typography } from "antd";
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
        defaultActiveKey={["first-use"]}
        items={[
          {
            key: "first-use",
            label: t("setup.firstUse.title"),
            children: (
              <Descriptions
                column={1}
                layout="vertical"
                size="small"
                items={[
                  {
                    key: "users",
                    label: t("setup.firstUse.users"),
                    children: (
                      <Space
                        orientation="vertical"
                        size={8}
                        className="full-width"
                      >
                        <Typography.Text>
                          {t(
                            unavailable || !owner
                              ? "setup.firstUse.ownerUnknown"
                              : owner.controller_node_id === null
                                ? "setup.firstUse.userHint"
                                : "setup.firstUse.delegated",
                          )}
                        </Typography.Text>
                        <Link to="/users">
                          {t("setup.firstUse.manageUsers")}
                        </Link>
                      </Space>
                    ),
                  },
                  {
                    key: "listener",
                    label: t("setup.firstUse.listener"),
                    children: (
                      <Space
                        orientation="vertical"
                        size={8}
                        className="full-width"
                      >
                        <Typography.Text>{t(runtime)}</Typography.Text>
                        <Link to="/service">{t("service.title")}</Link>
                        <Typography.Text type="secondary">
                          {t("setup.firstUse.notTested")}
                        </Typography.Text>
                      </Space>
                    ),
                  },
                  {
                    key: "endpoints",
                    label: t("setup.firstUse.endpoints"),
                    children: t(
                      unavailable
                        ? "setup.firstUse.endpointUnavailable"
                        : "setup.firstUse.endpointHint",
                    ),
                  },
                ]}
              />
            ),
          },
        ]}
      />
    </section>
  );
}
