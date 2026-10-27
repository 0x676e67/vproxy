import {
  Alert,
  Button,
  Descriptions,
  Drawer,
  Space,
  Tag,
  Typography,
} from "antd";
import { useEffect, useRef, useState } from "react";
import { apiError, type ApiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import type { PresetCapability } from "../../api/presets";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";

export function CapabilityView({ value }: { value: PresetCapability }) {
  const { t, intl } = useMessages();
  return (
    <Space orientation="vertical" className="full-width">
      <Alert
        type={value.backend_state === "ready" ? "info" : "warning"}
        showIcon
        title={t(`presets.backend.${value.backend_state}`)}
        description={t("presets.scopeHint")}
      />
      {value.reason_code && (
        <Typography.Text>
          {t(`presets.reason.${value.reason_code}`)}
        </Typography.Text>
      )}
      <Descriptions
        column={1}
        size="small"
        items={[
          {
            key: "revision",
            label: t("presets.catalogRevision"),
            children: value.preset_revision,
          },
          {
            key: "abi",
            label: t("presets.abi"),
            children: value.abi_version ?? "—",
          },
          {
            key: "at",
            label: t("presets.observed"),
            children:
              value.observed_at_unix_ms === null
                ? "—"
                : new Date(value.observed_at_unix_ms).toLocaleString(
                    intl.locale,
                  ),
          },
          {
            key: "names",
            label: t("presets.available"),
            children: value.available_presets.length ? (
              <Space wrap>
                {value.available_presets.map((name) => (
                  <Tag key={name}>{name}</Tag>
                ))}
              </Space>
            ) : (
              "—"
            ),
          },
        ]}
      />
    </Space>
  );
}

/** Explicit per-node read, never a poll spawned for every node card. */
export default function CapabilityButton({
  peer,
  disabled,
}: {
  peer: string | null;
  disabled: boolean;
}) {
  const { t } = useMessages();
  const { controller, state } = useManagement();
  const epoch = controller.generation();
  const [open, setOpen] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [view, setView] = useState<{
    value: PresetCapability | null;
    loading: boolean;
    error: ApiError | null;
  }>({ value: null, loading: false, error: null });
  const serial = useRef(0);
  useEffect(() => {
    if (!open || !state.session || state.busy) return;
    const request = new AbortController(),
      id = ++serial.current;
    setView({ value: null, loading: true, error: null });
    void controller
      .resource(
        state.session,
        (client, _csrf, signal) =>
          peer === null
            ? client.presets(signal)
            : client.targetPresets(peer, signal),
        request.signal,
      )
      .then((value) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          epoch === controller.generation()
        )
          setView({ value, loading: false, error: null });
      })
      .catch((error) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          epoch === controller.generation()
        )
          setView({ value: null, loading: false, error: apiError(error) });
      });
    return () => {
      serial.current++;
      request.abort();
    };
  }, [open, refresh, peer, controller, state.session, state.busy, epoch]);
  const canClose = peer === null || !view.loading;
  return (
    <>
      <Button size="small" disabled={disabled} onClick={() => setOpen(true)}>
        {t("presets.capability")}
      </Button>
      {open && (
        <Drawer
          open
          title={t("presets.capability")}
          closable={canClose}
          maskClosable={canClose}
          onClose={() => canClose && setOpen(false)}
          destroyOnHidden
        >
          <Space orientation="vertical" className="full-width" size={16}>
            <Typography.Text type="secondary">
              {t("presets.snapshot")}
            </Typography.Text>
            <Button
              loading={view.loading}
              disabled={view.loading || state.busy}
              onClick={() => setRefresh((value) => value + 1)}
            >
              {t("users.refresh")}
            </Button>
            {view.error && (
              <Alert
                type="error"
                showIcon
                title={t(errorMessage(view.error))}
              />
            )}
            {view.value && <CapabilityView value={view.value} />}
          </Space>
        </Drawer>
      )}
    </>
  );
}
