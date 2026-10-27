import { ProForm, ProFormSelect } from "@ant-design/pro-components";
import { Alert, Button, Drawer, Form, Modal, Space, Typography } from "antd";
import { useCallback, useEffect, useRef, useState } from "react";
import { apiError, type ApiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import {
  presetNames,
  poolPreset,
  userPreset,
  type Preset,
  type PresetCapability,
  type UserPresetView,
  type PoolPresetView,
} from "../../api/presets";
import {
  readPresetView,
  setPresets,
  type PresetMutation,
  type PresetScopeChange,
} from "../../api/remotePresets";
import { routingWritable, type RoutingContext } from "../../api/remoteRouting";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";
import { CapabilityView } from "./Capability";

type Fields = { default_preset: Preset | "none"; allowed_presets: Preset[] };
export default function PresetEditor({
  entity,
  peer,
  writeBlocked,
  close,
  onBusy,
  saved,
  mutate,
  invalidateReview,
}: {
  entity: { kind: "user" | "pool"; id: string; name: string };
  peer: string | null;
  writeBlocked: boolean;
  close: () => void;
  onBusy: (busy: boolean) => void;
  saved: (value: PresetScopeChange) => void;
  mutate?: (
    context: RoutingContext,
    mutation: PresetMutation,
    revision: string,
    signal: AbortSignal,
  ) => Promise<PresetScopeChange | null>;
  invalidateReview?: () => void;
}) {
  const { t } = useMessages();
  const { controller, state } = useManagement();
  const epoch = controller.generation();
  const [form] = Form.useForm<Fields>();
  const [view, setView] = useState<{
    data: UserPresetView | PoolPresetView;
    capability: PresetCapability;
    context: RoutingContext;
  } | null>(null);
  const [loading, setLoading] = useState(true),
    [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null),
    [uncertain, setUncertain] = useState(false);
  const [confirmation, setConfirmation] = useState<{
    mutation: PresetMutation;
    revision: string;
    epoch: number;
  } | null>(null);
  const read = useRef<AbortController | null>(null),
    write = useRef<AbortController | null>(null),
    serial = useRef(0);
  const load = useCallback(() => {
    invalidateReview?.();
    if (!state.session || state.busy) return;
    read.current?.abort();
    const request = new AbortController(),
      id = ++serial.current;
    read.current = request;
    setLoading(true);
    setError(null);
    setView(null);
    setConfirmation(null);
    setUncertain(false);
    void controller
      .resource(
        state.session,
        (client, _csrf, signal) =>
          readPresetView<UserPresetView | PoolPresetView>(
            client,
            peer,
            (api, signal) =>
              entity.kind === "user"
                ? api.userPresets(entity.id, signal)
                : api.poolPreset(entity.id, signal),
            (value) => value.revision,
            signal,
          ),
        request.signal,
      )
      .then((value) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          epoch === controller.generation()
        ) {
          const current =
            "presets" in value.data ? value.data.presets : value.data.preset;
          form.setFieldsValue({
            default_preset: current.default_preset ?? "none",
            allowed_presets:
              "allowed_presets" in current ? current.allowed_presets : [],
          });
          setView(value);
          setLoading(false);
        }
      })
      .catch((failure) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          epoch === controller.generation()
        ) {
          setError(apiError(failure));
          setLoading(false);
        }
      });
  }, [
    controller,
    state.session,
    state.busy,
    peer,
    entity.id,
    entity.kind,
    epoch,
    form,
    invalidateReview,
  ]);
  useEffect(() => {
    load();
    return () => {
      serial.current++;
      read.current?.abort();
    };
  }, [load]);
  useEffect(() => {
    onBusy(busy || (peer !== null && loading));
  }, [busy, peer, loading, onBusy]);
  useEffect(
    () => () => {
      write.current?.abort();
      onBusy(false);
    },
    [onBusy],
  );
  const disabled =
    writeBlocked ||
    busy ||
    loading ||
    state.busy ||
    !view ||
    !routingWritable(view.context) ||
    !!error ||
    uncertain;
  const submit = async () => {
    if (
      !state.session ||
      !confirmation ||
      confirmation.epoch !== epoch ||
      disabled ||
      write.current ||
      !view
    )
      return;
    const request = new AbortController();
    write.current = request;
    serial.current++;
    read.current?.abort();
    setBusy(true);
    onBusy(true);
    setError(null);
    try {
      // A pool's parent owns its admitted write and unknown-result fence. Do
      // not dispatch a second resource request or treat null as saved.
      const result = mutate
        ? await mutate(
            view.context,
            confirmation.mutation,
            confirmation.revision,
            request.signal,
          )
        : await controller.resource(
            state.session,
            (client, csrf, signal) =>
              setPresets(
                client,
                view.context,
                confirmation.mutation,
                confirmation.revision,
                csrf,
                signal,
              ),
            request.signal,
          );
      if (!request.signal.aborted && controller.generation() === epoch) {
        setConfirmation(null);
        if (result !== null) saved(result);
      }
    } catch (failure) {
      if (!request.signal.aborted && controller.generation() === epoch) {
        setError(apiError(failure));
        setUncertain(true);
        setConfirmation(null);
      }
    } finally {
      if (write.current === request) {
        write.current = null;
        setBusy(false);
        onBusy(false);
      }
    }
  };
  const current =
    view && ("presets" in view.data ? view.data.presets : view.data.preset);
  const canClose = !busy && !(peer !== null && loading);
  return (
    <Drawer
      open
      size="large"
      title={t("presets.editorTitle", { name: entity.name })}
      closable={canClose}
      maskClosable={canClose}
      onClose={() => canClose && close()}
      destroyOnHidden
    >
      <Space orientation="vertical" size={16} className="full-width">
        <Alert
          type="info"
          showIcon
          title={t("presets.newFlows")}
          description={t("presets.precedence")}
        />
        {error && (
          <Alert
            type="error"
            showIcon
            title={t(errorMessage(error))}
            description={t(
              uncertain ? "users.mutationUncertain" : "presets.unknown",
            )}
          />
        )}
        <Button
          loading={loading}
          disabled={loading || busy || state.busy}
          onClick={() =>
            error?.code === "invalid_csrf" ? void controller.check() : load()
          }
        >
          {t("users.refresh")}
        </Button>
        {view && current && (
          <>
            <CapabilityView value={view.capability} />
            {!routingWritable(view.context) && (
              <Alert
                type="warning"
                showIcon
                title={t(
                  peer === null
                    ? "control.locallyManaged"
                    : "resources.remoteWriteHint",
                )}
              />
            )}
            <Typography.Text>
              {t("resources.globalRevision")}: {view.data.revision}
            </Typography.Text>
            <ProForm<Fields>
              form={form}
              key={`${view.data.revision}:${epoch}`}
              initialValues={{
                default_preset: current.default_preset ?? "none",
                allowed_presets:
                  "allowed_presets" in current ? current.allowed_presets : [],
              }}
              submitter={{
                searchConfig: {
                  submitText: t("users.save"),
                  resetText: t("users.cancel"),
                },
                submitButtonProps: { disabled, loading: busy },
                resetButtonProps: { disabled: busy, onClick: close },
              }}
              onFinish={async (fields) => {
                if (disabled) return false;
                try {
                  const mutation: PresetMutation =
                    entity.kind === "user"
                      ? {
                          action: "set_user_presets",
                          presets: userPreset({
                            user_id: entity.id,
                            default_preset:
                              fields.default_preset === "none"
                                ? null
                                : fields.default_preset,
                            allowed_presets: fields.allowed_presets,
                          }),
                        }
                      : {
                          action: "set_pool_preset",
                          preset: poolPreset({
                            pool_id: entity.id,
                            default_preset:
                              fields.default_preset === "none"
                                ? null
                                : fields.default_preset,
                          }),
                        };
                  setConfirmation({
                    mutation,
                    revision: view.data.revision,
                    epoch,
                  });
                  return false;
                } catch {
                  form.setFields([
                    {
                      name: "default_preset",
                      errors: [t("presets.defaultRule")],
                    },
                  ]);
                  return false;
                }
              }}
            >
              {entity.kind === "user" && (
                <ProFormSelect
                  name="allowed_presets"
                  label={t("presets.allowed")}
                  mode="multiple"
                  options={presetNames.map((value) => ({
                    value,
                    label: value,
                  }))}
                  disabled={disabled}
                  fieldProps={{ allowClear: true }}
                />
              )}
              <ProFormSelect
                name="default_preset"
                label={t("presets.default")}
                disabled={disabled}
                options={[
                  {
                    value: "none",
                    label: t(
                      entity.kind === "user"
                        ? "presets.native"
                        : "presets.inherit",
                    ),
                  },
                  ...presetNames.map((value) => ({ value, label: value })),
                ]}
                rules={[{ required: true }]}
              />
            </ProForm>
          </>
        )}
      </Space>
      {confirmation && confirmation.epoch === epoch && (
        <Modal
          open
          title={t("presets.confirm")}
          onOk={() => void submit()}
          onCancel={() => !busy && setConfirmation(null)}
          confirmLoading={busy}
          maskClosable={false}
          closable={!busy}
          okButtonProps={{ disabled }}
          cancelButtonProps={{ disabled: busy }}
          okText={t("users.confirm")}
          cancelText={t("users.cancel")}
        >
          <Typography.Paragraph>{t("presets.newFlows")}</Typography.Paragraph>
          <Typography.Paragraph>{t("presets.precedence")}</Typography.Paragraph>
        </Modal>
      )}
    </Drawer>
  );
}
