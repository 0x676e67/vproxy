import {
  ProForm,
  ProFormCheckbox,
  ProFormSelect,
} from "@ant-design/pro-components";
import { Alert, Button, Drawer, Modal, Space, Typography } from "antd";
import { useCallback, useEffect, useRef, useState } from "react";
import { apiError, type ApiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import type { ProxyUser } from "../../api/proxy";
import {
  grantIds,
  type PermissionView,
  type RoutePermission,
} from "../../api/routing";
import {
  readRoutingView,
  routingReadDisabled,
  routingOperations,
  routingWritable,
  type RoutingContext,
  type RoutingScopeChange,
} from "../../api/remoteRouting";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";

export default function RoutingPermission({
  user,
  peer,
  writeBlocked,
  close,
  onBusy,
  saved,
}: {
  user: ProxyUser;
  peer: string | null;
  writeBlocked: boolean;
  close: () => void;
  onBusy: (busy: boolean) => void;
  saved: (result: RoutingScopeChange) => void;
}) {
  const { controller, state } = useManagement();
  const { t } = useMessages();
  const epoch = controller.generation();
  const [view, setView] = useState<{
    permission: PermissionView;
    context: RoutingContext;
  } | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const [confirmation, setConfirmation] = useState<{
    value: RoutePermission;
    revision: string;
    epoch: number;
  } | null>(null);
  const read = useRef<AbortController | null>(null);
  const write = useRef<AbortController | null>(null);
  const serial = useRef(0);
  const load = useCallback(() => {
    const session = state.session;
    if (!session || state.busy) return;
    read.current?.abort();
    const request = new AbortController();
    read.current = request;
    const id = ++serial.current;
    setLoading(true);
    setError(null);
    setView(null);
    setConfirmation(null);
    setUncertain(false);
    void controller
      .resource(
        session,
        async (client, _csrf, signal) => {
          const { data: permission, context } = await readRoutingView(
            client,
            peer,
            (read, signal) => read.routePermission(user.id, signal),
            (permission) => permission.revision,
            signal,
          );
          return { permission, context };
        },
        request.signal,
      )
      .then((value) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          controller.generation() === epoch
        ) {
          setView(value);
          setLoading(false);
        }
      })
      .catch((failure) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          controller.generation() === epoch
        ) {
          setError(apiError(failure));
          setLoading(false);
        }
      });
  }, [controller, state.session, state.busy, user.id, epoch, peer]);
  useEffect(() => {
    load();
    return () => {
      serial.current++;
      read.current?.abort();
    };
  }, [load]);
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
    user.deleted ||
    !view ||
    !routingWritable(view.context) ||
    !!error;
  const refresh = () => {
    if (error?.code === "invalid_csrf") void controller.check();
    else load();
  };
  const submit = async () => {
    const session = state.session;
    if (
      !session ||
      !confirmation ||
      confirmation.epoch !== epoch ||
      disabled ||
      write.current
    )
      return;
    const request = new AbortController();
    write.current = request;
    read.current?.abort();
    serial.current++;
    setBusy(true);
    onBusy(true);
    setError(null);
    try {
      const context = view!.context;
      const result = await controller.resource(
        session,
        (client, csrf, signal) =>
          routingOperations(client, context).setRoutePermission(
            confirmation.value,
            confirmation.revision,
            csrf,
            signal,
          ),
        request.signal,
      );
      if (!request.signal.aborted && controller.generation() === epoch) {
        setConfirmation(null);
        saved(result);
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
  return (
    <Drawer
      open
      size="large"
      title={t("resources.permissionTitle", { name: user.name })}
      onClose={() => !busy && close()}
      closable={!busy}
      maskClosable={!busy}
      destroyOnHidden
    >
      <Space orientation="vertical" size={16} className="full-width">
        <Alert
          type="info"
          showIcon
          title={t(
            peer === null ? "resources.localOnly" : "resources.remoteScope",
          )}
          description={t("resources.permissionHint")}
        />
        {peer === null && view?.context.owner?.controller_node_id && (
          <Alert type="warning" showIcon title={t("control.locallyManaged")} />
        )}
        {peer !== null && view && !routingWritable(view.context) && (
          <Alert
            type="warning"
            showIcon
            title={t("resources.remoteWriteHint")}
          />
        )}
        {error && (
          <Alert
            type="error"
            showIcon
            title={t(errorMessage(error))}
            description={t(
              uncertain
                ? "users.mutationUncertain"
                : "resources.permissionUnknown",
            )}
          />
        )}
        <Button
          loading={loading}
          disabled={routingReadDisabled(peer, loading, busy || state.busy)}
          onClick={refresh}
        >
          {t("users.refresh")}
        </Button>
        {view && (
          <ProForm<Omit<RoutePermission, "user_id">>
            key={`${user.id}:${view.permission.revision}:${epoch}`}
            initialValues={view.permission.permission}
            submitter={{
              searchConfig: {
                submitText: t("users.save"),
                resetText: t("users.cancel"),
              },
              submitButtonProps: { loading: busy, disabled },
              resetButtonProps: { disabled: busy, onClick: close },
            }}
            onFinish={async (values) => {
              if (disabled) return false;
              setConfirmation({
                value: {
                  user_id: user.id,
                  legacy_allowed: values.legacy_allowed,
                  exits: [...values.exits],
                  pools: [...values.pools],
                },
                revision: view.permission.revision,
                epoch,
              });
              return false;
            }}
          >
            <Typography.Paragraph>
              {t("resources.globalRevision")}: {view.permission.revision}
            </Typography.Paragraph>
            <ProFormCheckbox name="legacy_allowed" disabled={disabled}>
              {t("resources.legacyAllowed")}
            </ProFormCheckbox>
            <Typography.Paragraph type="secondary">
              {t("resources.legacyHint")}
            </Typography.Paragraph>
            <Alert type="info" showIcon title={t("resources.grantsHint")} />
            {(["exits", "pools"] as const).map((field) => (
              <ProFormSelect
                key={field}
                name={field}
                label={t(
                  field === "exits"
                    ? "resources.exitsGrant"
                    : "resources.poolsGrant",
                )}
                fieldProps={{
                  mode: "tags",
                  disabled,
                  maxTagCount: "responsive",
                  tokenSeparators: [",", " ", "\n"],
                }}
                options={view.permission.permission[field].map((value) => ({
                  value,
                  label: value,
                }))}
                rules={[
                  {
                    validator: async (_, value: unknown) => {
                      if (!grantIds(value))
                        throw new Error(t("resources.grantRule"));
                    },
                  },
                ]}
              />
            ))}
            <Typography.Paragraph type="secondary">
              {t("resources.selectorHint")}
            </Typography.Paragraph>
          </ProForm>
        )}
      </Space>
      {confirmation && confirmation.epoch === epoch && (
        <Modal
          open
          title={t("resources.permission")}
          onCancel={() => !busy && setConfirmation(null)}
          onOk={() => void submit()}
          okText={t("users.confirm")}
          cancelText={t("users.cancel")}
          confirmLoading={busy}
          okButtonProps={{ danger: true, disabled }}
          cancelButtonProps={{ disabled: busy }}
          closable={!busy}
          maskClosable={false}
        >
          <Typography.Paragraph>
            {t(
              !confirmation.value.legacy_allowed &&
                !confirmation.value.exits.length &&
                !confirmation.value.pools.length
                ? "resources.denyAllHint"
                : "resources.permissionHint",
            )}
          </Typography.Paragraph>
        </Modal>
      )}
    </Drawer>
  );
}
