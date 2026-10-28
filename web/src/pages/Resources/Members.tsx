import {
  ModalForm,
  ProFormText,
  ProTable,
  type ProColumns,
} from "@ant-design/pro-components";
import { Alert, Button, Drawer, Modal, Space, Typography } from "antd";
import { useCallback, useEffect, useRef, useState } from "react";
import { apiError, type ApiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import { canonicalId } from "../../api/proxy";
import type { Pool, RoutingPage } from "../../api/routing";
import {
  readRoutingView,
  routingReadDisabled,
  type RoutingContext,
  type RoutingOperations,
  type RoutingScopeChange,
  type RoutingSubmission,
} from "../../api/remoteRouting";
import { useManagement } from "../../auth/context";
import type { Intent } from "../../auth/routing-changes";
import { useMessages } from "../../hooks/useMessages";
import { labelledColumns } from "../../components/DataTable";

export type RoutingWork = (
  client: RoutingOperations,
  csrf: string,
  signal: AbortSignal,
) => Promise<RoutingScopeChange>;

export default function Members({
  pool,
  peer,
  onContext,
  submission,
  busy,
  writeDisabled,
  mutationError,
  refreshPolicy,
  mutate,
  invalidateReview,
  close,
}: {
  pool: Pool;
  peer: string | null;
  onContext: (context: RoutingContext) => void;
  submission: RoutingSubmission | null;
  busy: boolean;
  writeDisabled: boolean;
  mutationError: ApiError | null;
  refreshPolicy: () => void;
  mutate: (
    intent: Pick<
      Intent,
      "action" | "kind" | "resourceId" | "memberId" | "expectedRevision"
    >,
    work: RoutingWork,
  ) => Promise<RoutingScopeChange | null>;
  invalidateReview?: () => void;
  close: () => void;
}) {
  const { controller, state } = useManagement();
  const { t } = useMessages();
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [view, setView] = useState<{
    page: RoutingPage<string> | null;
    loading: boolean;
    error: ApiError | null;
  }>({ page: null, loading: true, error: null });
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const pending = useRef<AbortController | null>(null);
  const serial = useRef(0);
  const epoch = controller.generation();
  const cursor = cursors.at(-1);
  const load = useCallback(() => {
    invalidateReview?.();
    const session = state.session;
    if (!session || state.busy) return;
    pending.current?.abort();
    const request = new AbortController();
    pending.current = request;
    const id = ++serial.current;
    setView((value) => ({ ...value, loading: true, error: null }));
    void controller
      .resource(
        session,
        (client, _csrf, signal) =>
          readRoutingView(
            client,
            peer,
            (read, signal) =>
              read.poolMembers(pool.id, { after: cursor, limit: 25 }, signal),
            (page) => page.revision,
            signal,
          ),
        request.signal,
      )
      .then(({ data: page, context }) => {
        if (
          !request.signal.aborted &&
          serial.current === id &&
          controller.generation() === epoch
        ) {
          onContext(context);
          setView({ page, loading: false, error: null });
        }
      })
      .catch((error) => {
        if (
          !request.signal.aborted &&
          serial.current === id &&
          controller.generation() === epoch
        )
          setView({ page: null, loading: false, error: apiError(error) });
      });
  }, [
    controller,
    state.session,
    state.busy,
    pool.id,
    cursor,
    epoch,
    peer,
    onContext,
    invalidateReview,
  ]);
  useEffect(() => {
    load();
    return () => {
      serial.current++;
      pending.current?.abort();
    };
  }, [load]);
  const disabled =
    writeDisabled ||
    busy ||
    view.loading ||
    !!view.error ||
    !view.page ||
    pool.state === "retired";
  const change = async (addressId: string, remove: boolean) => {
    if (disabled || !view.page) return false;
    pending.current?.abort();
    const id = ++serial.current;
    const revision = view.page.revision;
    const result = await mutate(
      {
        action: remove ? "remove_member" : "add_member",
        kind: "pools",
        resourceId: pool.id,
        memberId: addressId,
        expectedRevision: revision,
      },
      (client, csrf, signal) =>
        client.poolMembership(
          pool.id,
          addressId,
          remove,
          revision,
          csrf,
          signal,
        ),
    );
    if (controller.generation() !== epoch || serial.current !== id)
      return false;
    if (result) {
      setAdding(false);
      setRemoving(null);
    }
    // Keep remote batch editing in this active view. The parent defers its
    // catalog refresh until close; a 202/error does not start another peer read.
    if (peer === null || result?.submission?.response) load();
    return result !== null;
  };
  const columns: ProColumns<{ id: string }>[] = [
    {
      title: t("resources.id"),
      dataIndex: "id",
      render: (_, row) => (
        <Typography.Text code copyable className="managed-identifier">
          {row.id}
        </Typography.Text>
      ),
    },
    {
      title: t("users.actions"),
      render: (_, row) => (
        <Button
          danger
          size="small"
          disabled={disabled}
          onClick={() => setRemoving(row.id)}
        >
          {t("resources.removeMember")}
        </Button>
      ),
    },
  ];
  return (
    <Drawer
      open
      size="large"
      title={`${t("resources.members")} — ${pool.name}`}
      onClose={() => !busy && !(peer !== null && view.loading) && close()}
      closable={!busy && !(peer !== null && view.loading)}
      maskClosable={!busy && !(peer !== null && view.loading)}
      destroyOnHidden
    >
      <Space orientation="vertical" size={16} className="full-width">
        {peer !== null && submission && (
          <Alert
            showIcon
            type={
              submission.response?.receipt.status === "rejected"
                ? "error"
                : "info"
            }
            title={t(
              submission.response?.receipt.status === "rejected"
                ? "control.rejected"
                : "control.receiptReceived",
            )}
            description={t("resources.remoteIntentHint")}
          />
        )}
        <Alert
          type="info"
          showIcon
          title={t("resources.memberHint")}
          description={t("resources.poolHint")}
        />
        {view.error && (
          <Alert type="error" showIcon title={t(errorMessage(view.error))} />
        )}
        {mutationError && (
          <Alert
            type="error"
            showIcon
            title={t(errorMessage(mutationError))}
            description={t("users.mutationUncertain")}
            action={
              <Button
                disabled={busy}
                onClick={() => {
                  setAdding(false);
                  setRemoving(null);
                  refreshPolicy();
                  if (peer === null) load();
                }}
              >
                {t("users.refresh")}
              </Button>
            }
          />
        )}
        <ProTable<{ id: string }>
          className="management-data-table"
          rowKey="id"
          columns={labelledColumns(columns)}
          dataSource={view.page?.items.map((id) => ({ id })) ?? []}
          loading={view.loading}
          search={false}
          options={false}
          pagination={false}
          scroll={{ x: 600 }}
          toolBarRender={() => [
            <Button
              key="refresh"
              onClick={load}
              disabled={routingReadDisabled(
                peer,
                view.loading,
                busy || state.busy,
              )}
            >
              {t("users.refresh")}
            </Button>,
            <Button
              key="add"
              type="primary"
              disabled={disabled}
              onClick={() => setAdding(true)}
            >
              {t("resources.addMember")}
            </Button>,
          ]}
        />
        <Space wrap>
          <Button
            disabled={view.loading || busy || cursors.length <= 1}
            onClick={() => setCursors((value) => value.slice(0, -1))}
          >
            {t("users.previous")}
          </Button>
          <Typography.Text>
            {t("users.page", { page: cursors.length })}
          </Typography.Text>
          <Button
            disabled={view.loading || busy || !view.page?.next_cursor}
            onClick={() =>
              setCursors((value) => [...value, view.page!.next_cursor!])
            }
          >
            {t("users.next")}
          </Button>
        </Space>
      </Space>
      {adding && (
        <ModalForm<{ address_id: string }>
          open
          title={t("resources.addMember")}
          modalProps={{
            onCancel: () => !busy && setAdding(false),
            destroyOnHidden: true,
            maskClosable: false,
            closable: !busy,
          }}
          submitter={{
            searchConfig: {
              submitText: t("users.save"),
              resetText: t("users.cancel"),
            },
            submitButtonProps: { loading: busy, disabled },
            resetButtonProps: {
              disabled: busy,
              onClick: () => setAdding(false),
            },
          }}
          onFinish={({ address_id }) => change(address_id, false)}
        >
          <ProFormText
            name="address_id"
            label={t("resources.id")}
            fieldProps={{ disabled: busy, maxLength: 22, autoComplete: "off" }}
            rules={[
              { required: true, message: t("resources.idRule") },
              {
                validator: async (_, value) => {
                  if (value && !canonicalId(value))
                    throw new Error(t("resources.idRule"));
                },
              },
            ]}
          />
        </ModalForm>
      )}
      {removing && (
        <Modal
          open
          title={t("resources.removeMember")}
          onCancel={() => !busy && setRemoving(null)}
          onOk={() => void change(removing, true)}
          okText={t("users.confirm")}
          cancelText={t("users.cancel")}
          confirmLoading={busy}
          okButtonProps={{ danger: true, disabled }}
          cancelButtonProps={{ disabled: busy }}
          closable={!busy}
          maskClosable={false}
        >
          <Typography.Paragraph>
            {t("resources.removeHint")}
          </Typography.Paragraph>
          <Typography.Text code>{removing}</Typography.Text>
        </Modal>
      )}
    </Drawer>
  );
}
