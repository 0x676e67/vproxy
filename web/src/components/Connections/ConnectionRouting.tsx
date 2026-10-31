import { Alert, Button, Form, Space, Typography } from "antd";
import { ProFormSelect, ProFormText } from "@ant-design/pro-components";
import { Link } from "@umijs/max";
import type { ApiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import type { RoutePermission } from "../../api/routing";
import { resourcesHref } from "../../api/targets";
import { useMessages } from "../../hooks/useMessages";
import type { ConnectionLabels } from "./connectionLabels";
import { connectionRoutes } from "./connectionState";
import RouteChoice from "../Presets/RouteChoice";

/** Form-only route choices. Optional resource labels never add grants or replace
 * the modal's fresh authorization check before generation. */
export default function ConnectionRouting({
  permission,
  peer,
  blocked,
  labels,
  labelError,
  readLabels,
}: {
  permission: RoutePermission | undefined;
  peer: string | null;
  blocked: boolean;
  labels: ConnectionLabels | null;
  labelError: ApiError | null;
  readLabels: () => void;
}) {
  const { t } = useMessages();
  const form = Form.useFormInstance();
  const routeKind = Form.useWatch("route_kind", form);
  const routes = permission ? connectionRoutes(permission) : [];
  return (
    <>
      <Form.Item
        name="route_kind"
        label={t("presets.route")}
        rules={[{ required: true }]}
      >
        <RouteChoice routes={routes} disabled={blocked} />
      </Form.Item>
      {routeKind === "exit" || routeKind === "pool" ? (
        <>
          <ProFormSelect
            name="route_value"
            label={t(
              routeKind === "exit"
                ? "connections.exitValue"
                : "connections.poolValue",
            )}
            disabled={blocked}
            fieldProps={{ showSearch: true, optionFilterProp: "label" }}
            options={(routeKind === "exit"
              ? permission?.exits
              : permission?.pools
            )?.map((value) => {
              const address =
                routeKind === "exit"
                  ? labels?.addresses.find((item) => item.id === value)
                  : null;
              const pool =
                routeKind === "pool"
                  ? labels?.pools.find((item) => item.id === value)
                  : null;
              return {
                value,
                label: address
                  ? `${address.name} · ${address.ip} · ${t(`resources.${address.state}`)} · ${value}`
                  : pool
                    ? `${pool.name} · ${pool.family === "v4" ? "IPv4" : "IPv6"} · ${t(`resources.${pool.state}`)} · ${value}`
                    : `${value} · ${t("connections.nameNotRead")}`,
              };
            })}
            rules={[{ required: true }]}
          />
          <Space
            orientation="vertical"
            className="full-width management-form-notice"
            size={8}
          >
            <Space wrap>
              <Button
                size="small"
                disabled={blocked}
                onClick={() => void readLabels()}
              >
                {t("connections.readNames")}
              </Button>
              <Link to={resourcesHref(peer)}>
                {t("connections.resourcesLink")}
              </Link>
            </Space>
            <Typography.Text type="secondary">
              {t("connections.namesHint")}
            </Typography.Text>
            {labelError && (
              <Alert
                type="warning"
                showIcon
                title={t(errorMessage(labelError))}
                description={t("connections.namesFailed")}
              />
            )}
          </Space>
        </>
      ) : (
        routeKind &&
        routeKind !== "default" && (
          <ProFormText
            name="route_value"
            label={t(
              routeKind === "ttl"
                ? "connections.ttlValue"
                : "connections.derivedValue",
            )}
            disabled={blocked}
            fieldProps={{ maxLength: 128, autoComplete: "off" }}
            rules={[{ required: true }]}
          />
        )
      )}
    </>
  );
}
