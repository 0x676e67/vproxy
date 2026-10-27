import {
  Alert,
  Button,
  Descriptions,
  Drawer,
  Input,
  Space,
  Table,
  Tag,
  Typography,
} from "antd";
import { useEffect, useRef, useState } from "react";
import { ApiError, apiError, type ManagementClient } from "../../api/client";
import { errorMessage } from "../../api/messages";
import { canonicalId } from "../../api/proxy";
import type {
  UserOperation,
  UserOperationPage,
} from "../../api/userOperations";
import { useManagement } from "../../auth/context";
import { useMessages, type MessageKey } from "../../hooks/useMessages";

const actionLabels = {
  create_user: "users.create",
  update_user: "users.edit",
  set_user_active: "users.historySetActive",
  delete_user: "users.delete",
} as const satisfies Record<UserOperation["action"], MessageKey>;

const stateLabels = {
  reserved: "users.historyReserved",
  saved: "users.historySaved",
  rejected: "users.historyRejected",
} as const satisfies Record<UserOperation["state"], MessageKey>;

/** Read-only recovery: only an explicit exact-ID read may reconcile a live
 * attempt. A list row, matching name or new session cannot identify its input. */
export default function LocalOperations({
  open,
  onClose,
  onClosed,
  onInspect,
  disabled,
}: {
  open: boolean;
  onClose: () => void;
  onClosed: (region: HTMLElement | null) => void;
  onInspect: (operation: UserOperation) => void;
  disabled: boolean;
}) {
  const { t } = useMessages();
  const { controller, state } = useManagement();
  const epoch = controller.generation();
  const [page, setPage] = useState<UserOperationPage | null>(null);
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [detail, setDetail] = useState<UserOperation | null>(null);
  const [id, setId] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const request = useRef<AbortController | null>(null);
  const panel = useRef<HTMLDivElement | null>(null);
  const serial = useRef(0);
  const inspect = useRef(onInspect);
  inspect.current = onInspect;
  const visible = open && state.phase === "authenticated" && !state.busy;

  const read = async <T,>(
    work: (client: ManagementClient, signal: AbortSignal) => Promise<T>,
    apply: (result: T) => void,
  ) => {
    if (!visible || disabled || !state.session || request.current) return;
    const active = new AbortController();
    const number = ++serial.current;
    const generation = controller.generation();
    request.current = active;
    setPending(true);
    setError(null);
    try {
      const result = await controller.resource(
        state.session,
        (client, _csrf, signal) => work(client, signal),
        active.signal,
      );
      if (
        !active.signal.aborted &&
        number === serial.current &&
        generation === controller.generation()
      )
        apply(result);
    } catch (failure) {
      if (
        !active.signal.aborted &&
        number === serial.current &&
        generation === controller.generation()
      )
        setError(apiError(failure));
    } finally {
      if (request.current === active) {
        request.current = null;
        setPending(false);
      }
    }
  };

  const list = (next: (string | undefined)[]) => {
    if (!visible || disabled || request.current) return;
    setPage(null);
    setDetail(null);
    void read(
      (client, signal) =>
        client.userOperations({ before: next.at(-1), limit: 25 }, signal),
      (result) => {
        setPage(result);
        setCursors(next);
      },
    );
  };
  const exact = (operationId: string) => {
    if (!visible || disabled || request.current || !canonicalId(operationId))
      return;
    setDetail(null);
    setId(operationId);
    void read(
      (client, signal) => client.userOperation(operationId, signal),
      (result) => {
        setDetail(result);
        inspect.current(result);
      },
    );
  };

  useEffect(() => {
    setPage(null);
    setDetail(null);
    setId("");
    setError(null);
    setCursors([undefined]);
    if (visible) list([undefined]);
    // Closing or replacing the session invalidates even an abort-ignoring read.
    return () => {
      ++serial.current;
      request.current?.abort();
      request.current = null;
      setPending(false);
    };
  }, [open, epoch, state.session, state.phase, state.busy, controller]);

  const blocked = disabled || pending || !visible;
  const status = (operation: UserOperation) => (
    <Tag
      color={
        operation.state === "saved"
          ? "green"
          : operation.state === "rejected"
            ? "warning"
            : "default"
      }
    >
      {t(stateLabels[operation.state])}
    </Tag>
  );
  return (
    <Drawer
      open={visible}
      size="large"
      title={t("users.localOperations")}
      onClose={onClose}
      panelRef={panel}
      focusable={{ focusTriggerAfterClose: false }}
      afterOpenChange={(nextOpen) => {
        if (!nextOpen) onClosed(panel.current);
      }}
      destroyOnHidden
    >
      <Space orientation="vertical" size="middle" className="full-width">
        <Typography.Paragraph type="secondary">
          {t("users.historyHint")}
        </Typography.Paragraph>
        <Space.Compact className="full-width">
          <Input
            value={id}
            maxLength={22}
            aria-label={t("users.operationId")}
            placeholder={t("users.operationId")}
            disabled={blocked}
            onChange={(event) => setId(event.target.value)}
            onPressEnter={() => exact(id)}
          />
          <Button
            disabled={blocked || !canonicalId(id)}
            onClick={() => exact(id)}
          >
            {t("users.checkOperation")}
          </Button>
        </Space.Compact>
        {error && (
          <Alert type="error" title={t(errorMessage(error))} showIcon />
        )}
        {detail && (
          <>
            <Descriptions
              title={t("users.historyDetail")}
              column={1}
              items={[
                {
                  key: "state",
                  label: t("users.state"),
                  children: status(detail),
                },
                {
                  key: "id",
                  label: t("users.operationId"),
                  children: (
                    <Typography.Text className="managed-identifier">
                      {detail.id}
                    </Typography.Text>
                  ),
                },
                {
                  key: "node",
                  label: t("users.historyNode"),
                  children: (
                    <Typography.Text className="managed-identifier">
                      {detail.node_id}
                    </Typography.Text>
                  ),
                },
                {
                  key: "action",
                  label: t("users.actions"),
                  children: t(actionLabels[detail.action]),
                },
                {
                  key: "user",
                  label: t("users.historyUser"),
                  children: (
                    <Typography.Text className="managed-identifier">
                      {detail.user_id ?? "—"}
                    </Typography.Text>
                  ),
                },
                {
                  key: "sequence",
                  label: t("control.sequence"),
                  children: detail.sequence,
                },
                {
                  key: "expected",
                  label: t("users.historyExpected"),
                  children: detail.expected_revision,
                },
                {
                  key: "epoch",
                  label: t("control.epoch"),
                  children: detail.expected_epoch,
                },
                {
                  key: "saved",
                  label: t("users.savedRevision"),
                  children: detail.saved_revision ?? "—",
                },
              ]}
            />
            <Alert
              type={detail.state === "rejected" ? "warning" : "info"}
              title={t(
                detail.rejection
                  ? errorMessage(new ApiError("server", detail.rejection))
                  : detail.state === "saved"
                    ? "users.historySavedHint"
                    : "users.historyReservedHint",
              )}
            />
          </>
        )}
        <Button
          disabled={blocked}
          loading={pending}
          onClick={() => list([undefined])}
        >
          {t("users.historyRefresh")}
        </Button>
        <Table<UserOperation>
          rowKey="id"
          size="small"
          loading={pending}
          dataSource={page?.items ?? []}
          pagination={false}
          columns={[
            {
              title: t("users.actions"),
              render: (_value, operation) => (
                <Space orientation="vertical" size={0}>
                  <Typography.Text>
                    {t(actionLabels[operation.action])}
                  </Typography.Text>
                  <Typography.Text
                    type="secondary"
                    className="managed-identifier"
                  >
                    {operation.id}
                  </Typography.Text>
                </Space>
              ),
            },
            {
              title: t("users.state"),
              render: (_value, operation) => status(operation),
            },
            {
              title: t("users.historyDetail"),
              render: (_value, operation) => (
                <Button disabled={blocked} onClick={() => exact(operation.id)}>
                  {t("users.historyInspect")}
                </Button>
              ),
            },
          ]}
          locale={{
            emptyText: t(page ? "users.historyEmpty" : "users.historyUnread"),
          }}
        />
        <Space wrap>
          <Button
            disabled={blocked || cursors.length <= 1}
            onClick={() => list(cursors.slice(0, -1))}
          >
            {t("users.historyPrevious")}
          </Button>
          <Button
            disabled={blocked || !page?.next_cursor}
            onClick={() =>
              page?.next_cursor && list([...cursors, page.next_cursor])
            }
          >
            {t("users.historyNext")}
          </Button>
        </Space>
      </Space>
    </Drawer>
  );
}
