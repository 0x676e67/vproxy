import { ProTable, type ProColumns } from "@ant-design/pro-components";
import { Link } from "@umijs/max";
import {
  Alert,
  Button,
  Collapse,
  Descriptions,
  Select,
  Space,
  Tag,
  Typography,
} from "antd";
import { useCallback, useEffect, useRef, useState } from "react";
import { apiError, type ApiError } from "../../api/client";
import type {
  HealthCheck,
  HealthEntry,
  HealthSnapshot,
} from "../../api/health";
import { errorMessage } from "../../api/messages";
import { useManagement } from "../../auth/context";
import { useMessages, type MessageKey } from "../../hooks/useMessages";
import { readRoutingView, routingReadDisabled } from "../../api/remoteRouting";
import { resourcesHref, type Target } from "../../api/targets";

interface CheckRow {
  id: string;
  entry: HealthEntry;
  check: HealthCheck;
}

function healthAdvice(check: HealthCheck): MessageKey {
  if (check.outcome === "success")
    return check.kind === "bind"
      ? "resources.guidance.bindSuccess"
      : "resources.guidance.tcpSuccess";
  return `resources.guidance.${check.outcome}`;
}

export default function Health({
  peer,
  onTarget,
  onBusy,
}: {
  peer: string | null;
  onTarget: (target: Target | null) => void;
  onBusy: (busy: boolean) => void;
}) {
  const { controller, state } = useManagement();
  const { t, intl } = useMessages();
  const epoch = controller.generation();
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [limit, setLimit] = useState(10);
  const cursor = cursors.at(-1);
  const [view, setView] = useState<{
    snapshot: HealthSnapshot | null;
    loading: boolean;
    error: ApiError | null;
    received: number | null;
    restarted: boolean;
  }>({
    snapshot: null,
    loading: true,
    error: null,
    received: null,
    restarted: false,
  });
  const pending = useRef<AbortController | null>(null);
  const serial = useRef(0);
  const load = useCallback(() => {
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
            (read, signal) => read.health({ after: cursor, limit }, signal),
            null,
            signal,
          ),
        request.signal,
      )
      .then(({ data: snapshot, context }) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          controller.generation() === epoch
        ) {
          onTarget(
            context.scope.kind === "target" ? context.scope.target : null,
          );
          setView((current) => ({
            snapshot,
            loading: false,
            error: null,
            received: Date.now(),
            restarted:
              !!current.snapshot &&
              current.snapshot.boot_id !== snapshot.boot_id,
          }));
        }
      })
      .catch((failure) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          controller.generation() === epoch
        )
          setView({
            snapshot: null,
            loading: false,
            error: apiError(failure),
            received: null,
            restarted: false,
          });
      });
  }, [
    controller,
    state.session,
    state.busy,
    epoch,
    cursor,
    limit,
    peer,
    onTarget,
  ]);
  useEffect(() => {
    onBusy(peer !== null && view.loading);
    return () => onBusy(false);
  }, [view.loading, peer, onBusy]);
  useEffect(() => {
    load();
    return () => {
      serial.current++;
      pending.current?.abort();
    };
  }, [load]);
  const time = (value: number | null) =>
    value === null || Number.isNaN(new Date(value).getTime())
      ? "—"
      : new Date(value).toLocaleString(intl.locale);
  const columns: ProColumns<CheckRow>[] = [
    {
      title: t("resources.ip"),
      render: (_, { entry }) => (
        <Space orientation="vertical" size={0}>
          <Typography.Text code>{entry.ip}</Typography.Text>
          <Link
            to={resourcesHref(peer, entry.address_id)}
            className="managed-identifier"
          >
            {entry.address_id}
          </Link>
        </Space>
      ),
    },
    {
      title: t("resources.revision"),
      render: (_, { entry }) => entry.address_revision,
    },
    {
      title: t("resources.check"),
      render: (_, { check }) =>
        t(check.kind === "bind" ? "resources.bind" : "resources.tcp"),
    },
    {
      title: t("resources.target"),
      render: (_, { check }) => check.target ?? "—",
    },
    {
      title: t("users.state"),
      render: (_, { check }) => (
        <Space
          orientation="vertical"
          size={4}
          style={{ width: "100%", maxWidth: 240 }}
        >
          <Tag
            color={
              check.outcome === "unknown"
                ? "default"
                : check.outcome === "success"
                  ? "blue"
                  : "orange"
            }
          >
            {t(`resources.${check.outcome}`)}
          </Tag>
          {!view.loading && !state.busy && !view.error && (
            <Collapse
              size="small"
              ghost
              style={{ width: "100%" }}
              items={[
                {
                  key: "guidance",
                  label: t("resources.guidanceTitle"),
                  children: (
                    <Typography.Text>{t(healthAdvice(check))}</Typography.Text>
                  ),
                },
              ]}
            />
          )}
        </Space>
      ),
    },
    {
      title: t("resources.observed"),
      render: (_, { check }) => time(check.observed_at_unix_ms),
    },
    {
      title: t("resources.age"),
      render: (_, { check }) => check.age_millis ?? "—",
    },
    {
      title: t("resources.latency"),
      render: (_, { check }) => check.latency_millis ?? "—",
    },
  ];
  const snapshot = view.snapshot;
  const rows =
    snapshot?.entries.flatMap((entry) =>
      entry.checks.map((check) => ({
        id: `${entry.address_id}:${check.kind}:${check.target ?? ""}`,
        entry,
        check,
      })),
    ) ?? [];
  return (
    <Space orientation="vertical" size={16} className="full-width">
      <Alert
        type="info"
        showIcon
        title={t("resources.observationHint")}
        description={t("resources.snapshotHint")}
      />
      {view.error && (
        <Alert
          type="error"
          showIcon
          title={t(errorMessage(view.error))}
          action={
            <Button onClick={load}>{t("resources.readLatestSnapshot")}</Button>
          }
        />
      )}
      {snapshot?.catalog_error && (
        <Alert type="warning" showIcon title={t("resources.catalogError")} />
      )}
      {snapshot && !snapshot.catalog_loaded && (
        <Alert type="info" showIcon title={t("resources.catalogNotLoaded")} />
      )}
      {view.restarted && (
        <Alert type="info" showIcon title={t("resources.restartHint")} />
      )}
      {snapshot && (
        <Descriptions
          column={{ xs: 1, sm: 2 }}
          items={[
            {
              key: "boot",
              label: t("resources.bootId"),
              children: (
                <Typography.Text code>{snapshot.boot_id}</Typography.Text>
              ),
            },
            {
              key: "sequence",
              label: t("resources.sequence"),
              children: snapshot.sequence,
            },
            {
              key: "revision",
              label: t("resources.globalRevision"),
              children: snapshot.catalog_revision ?? "—",
            },
            {
              key: "observed",
              label: t("resources.catalogObserved"),
              children: time(snapshot.catalog_observed_at_unix_ms),
            },
            {
              key: "age",
              label: t("resources.catalogAge"),
              children: snapshot.catalog_age_millis ?? "—",
            },
            {
              key: "flight",
              label: t("resources.inFlight"),
              children: snapshot.in_flight,
            },
            {
              key: "retrieved",
              label: t("resources.retrieved"),
              children: time(view.received),
            },
          ]}
        />
      )}
      <ProTable<CheckRow>
        headerTitle={t("resources.snapshotTitle", {
          time: time(view.received),
        })}
        rowKey="id"
        columns={columns}
        dataSource={rows}
        loading={view.loading || state.busy}
        options={false}
        search={false}
        pagination={false}
        scroll={{ x: 1300 }}
        toolBarRender={() => [
          <Button
            key="refresh"
            disabled={routingReadDisabled(peer, view.loading, state.busy)}
            loading={view.loading}
            onClick={load}
          >
            {t("resources.readLatestSnapshot")}
          </Button>,
        ]}
      />
      <Space wrap>
        <Typography.Text>{t("resources.pageSize")}</Typography.Text>
        <Select<number>
          aria-label={t("resources.pageSize")}
          value={limit}
          disabled={view.loading || state.busy}
          options={[5, 10, 16].map((value) => ({ value, label: value }))}
          onChange={(value) => {
            setLimit(value);
            setCursors([undefined]);
          }}
        />
        <Button
          disabled={view.loading || state.busy || cursors.length <= 1}
          onClick={() => setCursors((value) => value.slice(0, -1))}
        >
          {t("users.previous")}
        </Button>
        <Typography.Text>
          {t("users.page", { page: cursors.length })}
        </Typography.Text>
        <Button
          disabled={view.loading || state.busy || !snapshot?.next_cursor}
          onClick={() =>
            setCursors((value) => [...value, snapshot!.next_cursor!])
          }
        >
          {t("users.next")}
        </Button>
      </Space>
    </Space>
  );
}
