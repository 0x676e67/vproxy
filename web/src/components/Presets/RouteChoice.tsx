import { Collapse, Select, Space, Typography, type SelectProps } from "antd";
import { useState } from "react";
import type { ConnectionRoute } from "../../api/connection";
import { useMessages } from "../../hooks/useMessages";

type Kind = ConnectionRoute["kind"];
const advanced = (kind: Kind | undefined) =>
  kind === "session" || kind === "range" || kind === "ttl";

/** Entering advanced routing only opens choices; it must not silently choose
 * a derived route or fall back to a different authorized route. */
export default function RouteChoice({
  value,
  onChange,
  routes,
  disabled,
  ...accessibility
}: {
  value?: Kind;
  onChange?: (value: Kind | undefined) => void;
  routes: Kind[];
  disabled: boolean;
} & Pick<
  SelectProps,
  "id" | "aria-describedby" | "aria-invalid" | "aria-required"
>) {
  const { t } = useMessages();
  const [requested, setRequested] = useState(false);
  const derived = routes.filter(advanced);
  const showAdvanced = derived.length > 0 && (advanced(value) || requested);
  return (
    <Space orientation="vertical" className="full-width">
      <Select
        {...accessibility}
        aria-label={t("presets.route")}
        className="full-width"
        disabled={disabled}
        value={showAdvanced ? "advanced" : value}
        options={[
          ...routes
            .filter((kind) => !advanced(kind))
            .map((kind) => ({
              value: kind,
              label: t(`presets.route.${kind}`),
            })),
          ...(derived.length
            ? [{ value: "advanced", label: t("connections.advancedRouting") }]
            : []),
        ]}
        onChange={(kind) => {
          setRequested(kind === "advanced");
          onChange?.(kind === "advanced" ? undefined : (kind as Kind));
        }}
      />
      {showAdvanced && derived.length > 0 && (
        <Collapse
          defaultActiveKey={["routing"]}
          items={[
            {
              key: "routing",
              label: t("connections.advancedRouting"),
              children: (
                <Space orientation="vertical" className="full-width">
                  <Typography.Text type="secondary">
                    {t("connections.advancedRoutingHint")}
                  </Typography.Text>
                  <Select
                    aria-label={t("connections.derivedRoute")}
                    className="full-width"
                    disabled={disabled}
                    value={advanced(value) ? value : undefined}
                    options={derived.map((kind) => ({
                      value: kind,
                      label: t(`presets.route.${kind}`),
                    }))}
                    onChange={(kind) => onChange?.(kind)}
                  />
                </Space>
              ),
            },
          ]}
        />
      )}
    </Space>
  );
}
