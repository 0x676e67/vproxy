import { PageContainer, ProCard } from "@ant-design/pro-components";
import { Link, useLocation } from "@umijs/max";
import {
  Alert,
  Button,
  Descriptions,
  Empty,
  Result,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  alertCodes,
  type AlertCode,
  type AlertState,
  type OperationAlert,
} from "../../api/alerts";
import { errorMessage } from "../../api/messages";
import { resourcesHref, usersHref } from "../../api/targets";
import { trafficHref } from "../../api/traffic";
import { useManagement } from "../../auth/context";
import ManagementGate from "../../components/ManagementGate";
import ScopeError from "../../components/ScopeError";
import { useMessages, type MessageKey } from "../../hooks/useMessages";
import { useScopeNavigation } from "../../routing/ScopeNavigation";
import {
  scopeHref,
  scopeLocation,
  alertLocation,
  alertHistoryHref,
} from "../../routing/scope";
import ScopePicker from "../Users/ScopePicker";
import { useAlerts } from "./useAlerts";
import EventHistory from "./EventHistory";
import FleetAlerts from "./FleetAlerts";
import ObservationCoverage from "./ObservationCoverage";
import WebhookSettings from "./WebhookSettings";
import { NODE_ALERT_STALE_MS } from "./fleet";
import {
  observationDeadline,
  useObservationExpiry,
} from "./useObservationExpiry";

function Destination({
  row,
  peer,
}: {
  row: OperationAlert;
  peer: string | null;
}) {
  const { t } = useMessages();
  if (
    [
      "management_https",
      "node_tls",
      "proxy_tls",
      "remote_observation",
    ].includes(row.kind) ||
    (row.kind === "policy" &&
      [
        "proxy_not_running",
        "proxy_drain_failed",
        "proxy_drain_interrupted",
      ].includes(row.code))
  )
    return (
      <Space orientation="vertical" size={4}>
        <Link to="/nodes">{t("alerts.openNode")}</Link>
        {peer && <Typography.Text code>{peer}</Typography.Text>}
        {peer && (
          <Typography.Text type="secondary">
            {t("fleet.nodeLocationHint")}
          </Typography.Text>
        )}
      </Space>
    );
  if (row.kind === "egress_check" && row.resource_id)
    return (
      <Link to={resourcesHref(peer, row.resource_id)}>
        {t("resources.lookupOpen")}
      </Link>
    );
  if (row.kind === "health_catalog")
    return (
      <Link to={resourcesHref(peer)}>
        {t(peer === null ? "alerts.openResources" : "alerts.openNodeResources")}
      </Link>
    );
  if (row.kind === "policy")
    return peer ? (
      <Link to={usersHref(peer)}>{t("alerts.openPolicy")}</Link>
    ) : (
      <Link to="/users">{t("alerts.openPolicy")}</Link>
    );
  if (row.kind === "remote_job")
    return (
      <Link to={usersHref(row.origin_node_id)}>{t("alerts.openJob")}</Link>
    );
  return (
    <Link
      to={trafficHref(
        { kind: "node", id: null },
        row.kind === "remote_traffic" ? row.origin_node_id : peer,
      )}
    >
      {t("alerts.openTraffic")}
    </Link>
  );
}

function AlertList({
  listState,
  peer,
}: {
  listState: AlertState;
  peer: string | null;
}) {
  const { t, intl } = useMessages();
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [limit, setLimit] = useState(10);
  const after = cursors.at(-1);
  const options = useMemo(
    () => ({ state: listState, after, limit }),
    [listState, after, limit],
  );
  const view = useAlerts(options, peer);
  const page = view.page;
  const remote = peer !== null;
  const remotePage = page && "node_id" in page ? page : null;
  const deadline = remotePage
    ? observationDeadline(
        remotePage.age_millis,
        view.receivedMonotonic,
        NODE_ALERT_STALE_MS,
      )
    : null;
  useObservationExpiry(
    deadline,
    remote && !view.paused && !view.blocked && !view.loading && !view.error,
  );
  const unconfirmed = remote
    ? !!view.error ||
      view.loading ||
      view.interrupted ||
      view.paused ||
      !remotePage ||
      remotePage.collection_error ||
      deadline === null ||
      performance.now() > deadline
    : !!view.error ||
      view.loading ||
      view.paused ||
      !page ||
      page.collection_error ||
      page.age_millis === null;
  const previousRecord = (row: OperationAlert) =>
    remote && (unconfirmed || !row.evidence_fresh);
  const sourcePeer = (row: OperationAlert) =>
    peer ??
    (view.observerNode !== null && row.origin_node_id !== view.observerNode
      ? row.origin_node_id
      : null);
  const previousBoot = useRef<string | null>(null);
  const [restarted, setRestarted] = useState(false);
  // Remember a changed boot without treating its empty history as recovery.
  useEffect(() => {
    if (!page || previousBoot.current === page.boot_id) return;
    if (previousBoot.current !== null) setRestarted(true);
    previousBoot.current = page.boot_id;
  }, [page]);
  const decimal = (value: string) => BigInt(value).toLocaleString(intl.locale);
  const time = (value: string | number | null) => {
    if (value === null || BigInt(value) > 8640000000000000n) return "—";
    return new Date(Number(value)).toLocaleString(intl.locale);
  };
  const disabled = view.loading || view.blocked;
  const changed =
    view.error?.status === 409 && view.error.code === "alerts_changed";
  const reload = () => {
    setCursors([undefined]);
    view.reload();
  };
  const columns: ColumnsType<OperationAlert> = [
    {
      title: t("alerts.kind"),
      render: (_, row) => (
        <Space orientation="vertical" size={4}>
          <Typography.Text>{t(`alerts.kind.${row.kind}`)}</Typography.Text>
          {row.check && (
            <Tag>{t(row.check === "bind" ? "alerts.bind" : "alerts.tcp")}</Tag>
          )}
          {row.target && <Typography.Text code>{row.target}</Typography.Text>}
        </Space>
      ),
    },
    {
      title: t("alerts.subject"),
      render: (_, row) => (
        <Space orientation="vertical" size={4}>
          <Typography.Text code className="managed-identifier">
            {row.origin_node_id}
          </Typography.Text>
          {peer === null && sourcePeer(row) !== null && (
            <Tag>{t("alerts.foreignObservation")}</Tag>
          )}
          {row.resource_id && (
            <Typography.Text code className="managed-identifier">
              {row.resource_id}
            </Typography.Text>
          )}
        </Space>
      ),
    },
    {
      title: t("alerts.status"),
      render: (_, row) => (
        <Space orientation="vertical" size={4}>
          <Tag
            color={
              previousRecord(row)
                ? "default"
                : row.status === "active"
                  ? "orange"
                  : row.status === "recovered"
                    ? "blue"
                    : "default"
            }
          >
            {t(
              previousRecord(row)
                ? "alerts.previousRecord"
                : remote && row.status === "recovered"
                  ? "alerts.remoteRecovered"
                  : `alerts.status.${row.status}`,
            )}
          </Tag>
          {((row.status === "active" && !row.evidence_fresh) ||
            previousRecord(row)) && <Tag>{t("alerts.stale")}</Tag>}
        </Space>
      ),
    },
    {
      title: t("alerts.reason"),
      render: (_, row) => {
        const reason = t(
          alertCodes.includes(row.code as AlertCode)
            ? (`alerts.code.${row.code}` as MessageKey)
            : "alerts.code.unknown",
        );
        return (["management_https", "node_tls", "proxy_tls"].includes(
          row.kind,
        ) &&
          (row.status !== "active" || !row.evidence_fresh)) ||
          (remote && (previousRecord(row) || row.status !== "active"))
          ? t("alerts.previousObservation", { reason })
          : reason;
      },
    },
    {
      title: t("alerts.observed"),
      render: (_, row) => time(row.last_observed_at_unix_ms),
    },
    { title: t("alerts.age"), render: (_, row) => decimal(row.age_millis) },
    ...(listState === "recent"
      ? [
          {
            title: t("alerts.ended"),
            render: (_: unknown, row: OperationAlert) =>
              time(row.ended_at_unix_ms),
          },
        ]
      : []),
    {
      title: t("alerts.action"),
      render: (_, row) => <Destination row={row} peer={sourcePeer(row)} />,
    },
  ];
  return (
    <Space orientation="vertical" size={16} className="full-width">
      <ProCard variant="outlined">
        <Descriptions
          column={{ xs: 1, sm: 2, lg: 3 }}
          items={[
            {
              key: "active",
              label: t("alerts.activeCount"),
              children:
                page && !view.error && !page.collection_error && !unconfirmed
                  ? intl.formatNumber(page.active_count)
                  : "—",
            },
            {
              key: "recent",
              label: t("alerts.recentCount"),
              children:
                page && !view.error && !unconfirmed
                  ? intl.formatNumber(page.recent_count)
                  : "—",
            },
            {
              key: "received",
              label: t("resources.retrieved"),
              children: time(view.received),
            },
            {
              key: "observed",
              label: t("alerts.collectionObserved"),
              children: time(page?.observed_at_unix_ms ?? null),
            },
            {
              key: "age",
              label: t("alerts.collectionAge"),
              children:
                page?.age_millis === null || page?.age_millis === undefined
                  ? "—"
                  : decimal(page.age_millis),
            },
          ]}
        />
      </ProCard>
      <Space wrap>
        <Button
          aria-label={t("alerts.refresh")}
          aria-busy={view.loading}
          onClick={reload}
          loading={view.loading}
          disabled={disabled}
        >
          {t("alerts.refresh")}
        </Button>
        <Typography.Text type="secondary">
          {t(
            remote
              ? "alerts.remoteManual"
              : view.paused
                ? "alerts.paused"
                : "alerts.polling",
          )}
        </Typography.Text>
        <Typography.Text type="secondary">
          {view.received === null
            ? t(
                remote && view.loading
                  ? "alerts.remoteReading"
                  : "alerts.waiting",
              )
            : t("alerts.received", { time: time(view.received) })}
        </Typography.Text>
      </Space>
      {remote && (
        <Alert
          type={unconfirmed && page ? "warning" : "info"}
          showIcon
          title={t(page ? "alerts.remoteSnapshot" : "alerts.remoteUnread")}
          description={t("alerts.remoteLifecycle")}
        />
      )}
      {page && "remote_observation" in page.coverage && (
        <Alert
          type="info"
          showIcon
          title={t(
            page.coverage.remote_observation
              ? "alerts.backgroundEnabled"
              : "alerts.backgroundDisabled",
          )}
          description={t(
            page.coverage.remote_observation
              ? "alerts.backgroundHint"
              : "alerts.backgroundDisabledHint",
          )}
        />
      )}
      {view.error && (
        <Alert
          type="error"
          showIcon
          title={t(
            remote &&
              view.error.code !== "operations_alerts_unsupported" &&
              !changed
              ? "alerts.remoteFailed"
              : errorMessage(view.error),
          )}
          description={page ? t("alerts.retained") : undefined}
        />
      )}
      {remotePage && unconfirmed && (
        <Alert type="warning" showIcon title={t("alerts.remoteUnknown")} />
      )}
      {page?.collection_error && (
        <Alert type="warning" showIcon title={t("alerts.collectionError")} />
      )}
      {page && page.dropped !== "0" && (
        <Alert
          type="warning"
          showIcon
          title={t("alerts.dropped", { count: decimal(page.dropped) })}
        />
      )}
      {restarted && (
        <Alert type="info" showIcon title={t("alerts.restarted")} />
      )}
      <Table<OperationAlert>
        rowKey="id"
        columns={columns}
        dataSource={page?.items ?? []}
        loading={view.loading}
        pagination={false}
        scroll={{ x: 1150 }}
        locale={{
          emptyText: (
            <Empty
              description={t(
                !page || unconfirmed
                  ? "alerts.noData"
                  : listState === "active"
                    ? "alerts.emptyActive"
                    : "alerts.emptyRecent",
              )}
            />
          ),
        }}
      />
      <Space wrap>
        <Button
          disabled={disabled || changed || cursors.length <= 1}
          onClick={() => {
            setCursors((current) => current.slice(0, -1));
            if (remote) view.reload();
          }}
        >
          {t("users.previous")}
        </Button>
        <Typography.Text>
          {t("users.page", { page: cursors.length })}
        </Typography.Text>
        <Button
          disabled={disabled || !!view.error || !page?.next_cursor}
          onClick={() => {
            const cursor = page?.next_cursor;
            if (cursor) {
              setCursors((current) => [...current, cursor]);
              if (remote) view.reload();
            }
          }}
        >
          {t("users.next")}
        </Button>
        <Typography.Text>{t("alerts.pageSize")}</Typography.Text>
        <Select
          aria-label={t("alerts.pageSize")}
          value={limit}
          disabled={disabled}
          options={[5, 10, 16].map((value) => ({ value, label: value }))}
          onChange={(value) => {
            setLimit(value);
            setCursors([undefined]);
            if (remote) view.reload();
          }}
        />
      </Space>
      {page && "coverage" in page && (
        <ProCard title={t("alerts.coverage")} variant="outlined">
          <Space orientation="vertical" size={12} className="full-width">
            <ObservationCoverage value={page.coverage} />
            <Typography.Text type="secondary">
              {t(remote ? "fleet.ownHint" : "alerts.remoteHint")}
            </Typography.Text>
            <Typography.Text type="secondary">
              {t("alerts.managementHttpsHint")}
            </Typography.Text>
          </Space>
        </ProCard>
      )}
    </Space>
  );
}

function Workspace({
  peer,
  select,
  history,
  eventId,
  selectHistory,
}: {
  peer: string | null;
  select: (peer: string | null) => void;
  history: boolean;
  eventId: string | null;
  selectHistory: (value: boolean) => void;
}) {
  const { t } = useMessages();
  const { state } = useManagement();
  const [listState, setListState] = useState<AlertState>("active");
  const [fleet, setFleet] = useState(false);
  const [notification, setNotification] = useState(false);
  useEffect(() => {
    setFleet(false);
    setNotification(false);
  }, [peer, history, eventId]);
  return (
    <PageContainer
      className="management-page"
      title={t("alerts.title")}
      content={t("alerts.description")}
    >
      <Space orientation="vertical" size={16} className="full-width">
        {!fleet && (
          <ScopePicker
            value={peer}
            onChange={select}
            disabled={state.busy}
            selected={null}
          />
        )}
        {!history && !fleet && !notification && (
          <Alert
            type="info"
            showIcon
            title={t("alerts.observationHint")}
            description={t("alerts.lifecycleHint")}
          />
        )}
        <Tabs
          activeKey={
            notification && peer === null
              ? "notifications"
              : fleet
                ? "fleet"
                : history
                  ? "history"
                  : listState
          }
          onChange={(value) => {
            setNotification(value === "notifications");
            if (value === "notifications") {
              setFleet(false);
              return;
            }
            setFleet(value === "fleet");
            if (value === "fleet") return;
            if (value === "history") selectHistory(true);
            else {
              setListState(value as AlertState);
              selectHistory(false);
            }
          }}
          items={[
            { key: "active", label: t("alerts.active") },
            { key: "recent", label: t("alerts.recent") },
            { key: "history", label: t("alertEvents.title") },
            { key: "fleet", label: t("fleet.title") },
            ...(peer === null
              ? [{ key: "notifications", label: t("notifications.title") }]
              : []),
          ]}
        />
        {notification && peer === null ? (
          <WebhookSettings />
        ) : fleet ? (
          <FleetAlerts key={`${peer ?? "local"}:${history}:${eventId ?? ""}`} />
        ) : history ? (
          <EventHistory origin={peer} initialEvent={eventId} />
        ) : (
          <AlertList
            key={`${peer ?? "local"}:${listState}`}
            listState={listState}
            peer={peer}
          />
        )}
      </Space>
    </PageContainer>
  );
}

export default function AlertsPage() {
  const { t } = useMessages();
  const location = useLocation();
  const select = useScopeNavigation();
  const route = (() => {
    try {
      return alertLocation(location.search);
    } catch {
      return null;
    }
  })();
  let peer: string | null;
  try {
    peer = scopeLocation(location);
  } catch {
    return <ScopeError />;
  }
  return __VPROXY_DEMO__ ? (
    <Result
      status="info"
      title={t("users.demoTitle")}
      subTitle={t("users.demoDescription")}
    />
  ) : (
    <ManagementGate>
      <Workspace
        peer={peer}
        history={route?.history ?? false}
        eventId={route?.eventId ?? null}
        select={(value) =>
          select(
            route?.history
              ? alertHistoryHref(value)
              : scopeHref("/alerts", value),
          )
        }
        selectHistory={(value) =>
          select(value ? alertHistoryHref(peer) : scopeHref("/alerts", peer))
        }
      />
    </ManagementGate>
  );
}
