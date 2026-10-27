import { PageContainer, ProCard } from "@ant-design/pro-components";
import { useLocation } from "@umijs/max";
import {
  Alert,
  Button,
  Collapse,
  Descriptions,
  Empty,
  Input,
  Result,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { useCallback, useEffect, useRef, useState } from "react";
import { apiError, type ApiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import { canonicalId, type ProxyProtocol } from "../../api/proxy";
import {
  compactBytes,
  exactBytes,
  readTrafficView,
  trafficHref,
  trafficLocation,
  trafficProtocols,
  type CheckpointStage,
  type BucketTotal,
  type Resolution,
  type TrafficMetadata,
  type TrafficScope,
  type TrafficTotal,
  type TrafficSource,
  type TrafficView,
} from "../../api/traffic";
import { useManagement } from "../../auth/context";
import ManagementGate from "../../components/ManagementGate";
import { useMessages } from "../../hooks/useMessages";
import ScopePicker from "../Users/ScopePicker";
import ScopeError from "../../components/ScopeError";
import { useScopeNavigation } from "../../routing/ScopeNavigation";

function useTrafficTime() {
  const { intl } = useMessages();
  return (value: number | null) => {
    if (value === null) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? `${value} ms`
      : date.toLocaleString(intl.locale);
  };
}

function BytesView({
  value,
  saturated = false,
}: {
  value: string | null;
  saturated?: boolean;
}) {
  const { intl } = useMessages();
  return (
    <Tooltip title={exactBytes(value, intl.locale)}>
      <Typography.Text
        className="managed-identifier"
        style={{ whiteSpace: "nowrap" }}
      >
        {value !== null && saturated ? "≥ " : ""}
        {compactBytes(value, intl.locale)}
      </Typography.Text>
    </Tooltip>
  );
}
const protocolLabel = (value: ProxyProtocol) =>
  value === "http" ? "HTTP / HTTPS" : value.toUpperCase();

function SourceNotice({ source }: { source: TrafficSource }) {
  const { t, intl } = useMessages();
  const time = useTrafficTime();
  return (
    <Alert
      type={
        source.state === "ready" || source.state === "pending"
          ? "info"
          : "warning"
      }
      showIcon
      title={t(`traffic.source.${source.state}`)}
      description={
        <Space orientation="vertical" className="full-width">
          <Typography.Text>
            {t(source.cached ? "traffic.cacheHint" : "traffic.onDemandHint")}
          </Typography.Text>
          {!source.collector_available && (
            <Typography.Text>
              {t("traffic.collectorUnavailable")}
            </Typography.Text>
          )}
          <Descriptions
            size="small"
            column={{ xs: 1, md: 2 }}
            items={[
              {
                key: "success",
                label: t("traffic.sourceSuccess"),
                children: time(source.last_success_at_unix_ms),
              },
              {
                key: "age",
                label: t("traffic.sourceAge"),
                children:
                  source.age_millis === null
                    ? "—"
                    : `${intl.formatNumber(source.age_millis)} ms`,
              },
              {
                key: "revision",
                label: t("traffic.targetRevision"),
                children: source.target_revision,
              },
            ]}
          />
        </Space>
      }
    />
  );
}

function Provenance({ value }: { value: TrafficMetadata }) {
  const { t } = useMessages();
  const time = useTrafficTime();
  return (
    <Collapse
      items={[
        {
          key: "source",
          label: t("traffic.metadata"),
          children: (
            <Descriptions
              column={{ xs: 1, md: 2 }}
              items={[
                {
                  key: "node",
                  label: t("traffic.origin"),
                  children: (
                    <Typography.Text copyable className="managed-identifier">
                      {value.origin_node_id}
                    </Typography.Text>
                  ),
                },
                {
                  key: "epoch",
                  label: t("traffic.epoch"),
                  children: (
                    <Typography.Text copyable className="managed-identifier">
                      {value.meter_epoch}
                    </Typography.Text>
                  ),
                },
                {
                  key: "started",
                  label: t("traffic.started"),
                  children: time(value.meter_started_at_unix_ms),
                },
                {
                  key: "checkpoint",
                  label: t("traffic.checkpoint"),
                  children: value.checkpoint_cursor,
                },
                {
                  key: "checkpointAt",
                  label: t("traffic.checkpointAt"),
                  children: time(value.last_checkpoint_at_unix_ms),
                },
                {
                  key: "observed",
                  label: t("traffic.observedAt"),
                  children: time(value.observed_at_unix_ms),
                },
                {
                  key: "clean",
                  label: t("traffic.clean"),
                  children: t(
                    value.last_run_clean
                      ? "traffic.cleanYes"
                      : "traffic.cleanNo",
                  ),
                },
              ]}
            />
          ),
        },
      ]}
    />
  );
}

export function Completeness({
  value,
  checkpointError = false,
  checkpointStage,
  remote = false,
}: {
  value: TrafficMetadata;
  checkpointError?: boolean;
  checkpointStage?: CheckpointStage | null;
  remote?: boolean;
}) {
  const { t } = useMessages();
  const warnings = [
    ...(remote && !value.last_run_clean ? [t("traffic.remoteOpenRun")] : []),
    ...(value.loss_possible ? [t("traffic.loss")] : []),
    ...(value.history_gap ? [t("traffic.gap")] : []),
    ...(value.time_uncertain ? [t("traffic.clock")] : []),
    ...(!remote && checkpointError
      ? [
          t("traffic.checkpointError") +
            (checkpointStage
              ? ` ${t(`traffic.checkpointStage.${checkpointStage}`)}`
              : ""),
        ]
      : []),
  ];
  return warnings.length ? (
    <Alert
      type="warning"
      showIcon
      title={t("traffic.warning")}
      description={
        <ul>
          {warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      }
    />
  ) : null;
}

interface HistoryRow {
  key: string;
  window_id: string;
  protocol: ProxyProtocol;
  sample: BucketTotal | null;
}

function Snapshot({
  peer,
  scope,
  protocol,
  resolution,
  onBusy,
}: {
  peer: string | null;
  scope: TrafficScope;
  protocol?: ProxyProtocol;
  resolution: Resolution;
  onBusy: (busy: boolean) => void;
}) {
  const { t, intl } = useMessages();
  const time = useTrafficTime();
  const { controller, state } = useManagement();
  const session = state.session;
  const epoch = controller.generation();
  const [view, setView] = useState<
    TrafficView & {
      loading: boolean;
      at: number | null;
      error: ApiError | null;
    }
  >({
    totals: null,
    history: null,
    totalsSource: null,
    historySource: null,
    historyError: null,
    loading: true,
    at: null,
    error: null,
  });
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [limit, setLimit] = useState(25);
  const cursor = cursors.at(-1);
  const serial = useRef(0);
  const pending = useRef<AbortController | null>(null);
  const load = useCallback(() => {
    if (!session || state.busy) return;
    pending.current?.abort();
    const request = new AbortController();
    pending.current = request;
    const id = ++serial.current;
    onBusy(true);
    setView((current) => ({ ...current, loading: true, error: null }));
    void controller
      .resource(
        session,
        (client, _csrf, signal) =>
          readTrafficView(
            client,
            peer,
            scope,
            { protocol, resolution, after: cursor, limit },
            signal,
          ),
        request.signal,
      )
      .then((result) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          epoch === controller.generation()
        ) {
          setView({ ...result, loading: false, at: Date.now(), error: null });
          onBusy(false);
        }
      })
      .catch((error) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          epoch === controller.generation()
        ) {
          setView((current) => ({
            ...current,
            loading: false,
            error: apiError(error),
          }));
          onBusy(false);
        }
      });
  }, [
    controller,
    session,
    state.busy,
    peer,
    scope,
    protocol,
    resolution,
    cursor,
    limit,
    epoch,
    onBusy,
  ]);
  useEffect(() => {
    load();
    return () => {
      serial.current++;
      pending.current?.abort();
      onBusy(false);
    };
  }, [load]);
  const disabled = view.loading || state.busy;
  const totals = view.totals;
  const history = view.history;
  const columns: ColumnsType<TrafficTotal> = [
    {
      title: t("traffic.protocol"),
      dataIndex: "protocol",
      render: protocolLabel,
    },
    {
      title: t("traffic.durableUpload"),
      render: (_, row) => (
        <BytesView
          value={row.durable_upload_bytes}
          saturated={row.durable_saturated}
        />
      ),
    },
    {
      title: t("traffic.durableDownload"),
      render: (_, row) => (
        <BytesView
          value={row.durable_download_bytes}
          saturated={row.durable_saturated}
        />
      ),
    },
    {
      title: t("traffic.liveUpload"),
      render: (_, row) => (
        <BytesView
          value={row.live_upload_bytes}
          saturated={row.live_saturated ?? false}
        />
      ),
    },
    {
      title: t("traffic.liveDownload"),
      render: (_, row) => (
        <BytesView
          value={row.live_download_bytes}
          saturated={row.live_saturated ?? false}
        />
      ),
    },
    {
      title: t("traffic.state"),
      render: (_, row) => (
        <Tag
          color={
            row.durable_saturated || row.live_saturated ? "warning" : "default"
          }
        >
          {t(
            row.durable_saturated || row.live_saturated
              ? "traffic.saturated"
              : "traffic.normal",
          )}
        </Tag>
      ),
    },
  ];
  const rows: HistoryRow[] =
    history?.items.flatMap((bucket) =>
      (protocol ? [protocol] : trafficProtocols).map((protocol) => ({
        key: `${bucket.window_id}:${protocol}`,
        window_id: bucket.window_id,
        protocol,
        sample:
          bucket.items.find((sample) => sample.protocol === protocol) ?? null,
      })),
    ) ?? [];
  const historyColumns: ColumnsType<HistoryRow> = [
    // window_id is a validated safe timestamp, never a byte counter.
    {
      title: t("traffic.window"),
      dataIndex: "window_id",
      render: (value) => time(Number(value)),
    },
    {
      title: t("traffic.protocol"),
      dataIndex: "protocol",
      render: protocolLabel,
    },
    {
      title: t("traffic.upload"),
      render: (_, row) => (
        <BytesView
          value={row.sample?.upload_bytes ?? null}
          saturated={row.sample?.saturated}
        />
      ),
    },
    {
      title: t("traffic.download"),
      render: (_, row) => (
        <BytesView
          value={row.sample?.download_bytes ?? null}
          saturated={row.sample?.saturated}
        />
      ),
    },
    {
      title: t("traffic.state"),
      render: (_, row) => (
        <Tag color={row.sample?.saturated ? "warning" : "default"}>
          {t(
            !row.sample
              ? "traffic.unknown"
              : row.sample.saturated
                ? "traffic.saturated"
                : "traffic.normal",
          )}
        </Tag>
      ),
    },
  ];
  return (
    <Space orientation="vertical" size={16} className="full-width">
      <Space wrap>
        <Button
          aria-label={t("traffic.refresh")}
          aria-busy={view.loading}
          loading={view.loading}
          disabled={disabled}
          onClick={load}
        >
          {t("traffic.refresh")}
        </Button>
        <Typography.Text type="secondary">
          {view.at === null
            ? t("traffic.waiting")
            : t("traffic.snapshot", { time: time(view.at) })}
        </Typography.Text>
      </Space>
      {view.error && (
        <Alert type="error" showIcon title={t(errorMessage(view.error))} />
      )}
      <ProCard
        title={t("traffic.totals")}
        variant="outlined"
        loading={view.loading && !totals}
      >
        <Space orientation="vertical" size={16} className="full-width">
          <Typography.Paragraph type="secondary">
            {t("traffic.cumulativeHint")}
          </Typography.Paragraph>
          {view.totalsSource && <SourceNotice source={view.totalsSource} />}
          {!totals && !view.loading && (
            <Empty description={t("traffic.noData")} />
          )}
          {totals && (
            <>
              {view.totalsSource ? (
                <Alert
                  type="info"
                  showIcon
                  title={t("traffic.remoteDurableOnly")}
                />
              ) : (
                totals.active_run_id === null && (
                  <Alert type="info" showIcon title={t("traffic.apiOnly")} />
                )
              )}
              <Completeness
                value={totals}
                checkpointError={totals.checkpoint_error}
                checkpointStage={totals.checkpoint_failure_stage}
                remote={view.totalsSource !== null}
              />
              <Descriptions
                column={{ xs: 1, md: 2 }}
                items={[
                  {
                    key: "run",
                    label: t("traffic.run"),
                    children: totals.active_run_id ?? "—",
                  },
                  {
                    key: "cycle",
                    label: t("traffic.completedAt"),
                    children: time(totals.last_completed_cycle_at_unix_ms),
                  },
                  {
                    key: "age",
                    label: t("traffic.cycleAge"),
                    children:
                      totals.last_completed_cycle_age_millis === null
                        ? "—"
                        : `${intl.formatNumber(totals.last_completed_cycle_age_millis)} ms`,
                  },
                ]}
              />
              <Table<TrafficTotal>
                rowKey="protocol"
                columns={columns}
                dataSource={totals.items}
                pagination={false}
                scroll={{ x: 720 }}
              />
              <Provenance value={totals} />
            </>
          )}
        </Space>
      </ProCard>
      {scope.kind === "credential" ? (
        <Alert type="info" showIcon title={t("traffic.noCredentialHistory")} />
      ) : (
        <ProCard
          title={t("traffic.history")}
          variant="outlined"
          loading={view.loading && !history}
        >
          <Space orientation="vertical" size={16} className="full-width">
            <Typography.Paragraph type="secondary">
              {t("traffic.historyHint")}
            </Typography.Paragraph>
            {view.historySource && <SourceNotice source={view.historySource} />}
            {view.historyError && (
              <Alert
                type="error"
                showIcon
                title={t(errorMessage(view.historyError))}
              />
            )}
            {!history && !view.loading && (
              <Empty description={t("traffic.noHistory")} />
            )}
            {history && (
              <>
                <Completeness
                  value={history}
                  remote={view.historySource !== null}
                />
                {history.retention_gap && (
                  <Alert
                    type="warning"
                    showIcon
                    title={t("traffic.retentionGap")}
                  />
                )}
                <Typography.Text type="secondary">
                  {t("traffic.retentionFloor", {
                    time:
                      history.retention_floor === null
                        ? "—"
                        : time(Number(history.retention_floor)),
                  })}
                </Typography.Text>
                <Table<HistoryRow>
                  rowKey="key"
                  columns={historyColumns}
                  dataSource={rows}
                  pagination={false}
                  locale={{
                    emptyText: <Empty description={t("traffic.noHistory")} />,
                  }}
                  scroll={{ x: 720 }}
                />
                <Space wrap>
                  <Button
                    disabled={disabled || cursors.length <= 1}
                    onClick={() =>
                      setCursors((current) => current.slice(0, -1))
                    }
                  >
                    {t("users.previous")}
                  </Button>
                  <Button
                    disabled={disabled || history.next_cursor === null}
                    onClick={() =>
                      setCursors((current) => [
                        ...current,
                        history.next_cursor!,
                      ])
                    }
                  >
                    {t("users.next")}
                  </Button>
                  <Typography.Text>{t("traffic.pageSize")}</Typography.Text>
                  <Select
                    aria-label={t("traffic.pageSize")}
                    value={limit}
                    disabled={disabled}
                    options={[10, 25, 50].map((value) => ({
                      value,
                      label: String(value),
                    }))}
                    onChange={(value) => {
                      setCursors([undefined]);
                      setLimit(value);
                    }}
                  />
                </Space>
                <Provenance value={history} />
              </>
            )}
          </Space>
        </ProCard>
      )}
    </Space>
  );
}

function Workspace({
  initial,
}: {
  initial: ReturnType<typeof trafficLocation>;
}) {
  const { t } = useMessages();
  const { state } = useManagement();
  const selectScope = useScopeNavigation();
  const { peer, scope, protocol, resolution } = initial;
  const [kind, setKind] = useState<TrafficScope["kind"]>(initial.scope.kind);
  const [id, setId] = useState(initial.scope.id ?? "");
  const [invalid, setInvalid] = useState(false);
  const [reading, setReading] = useState(false);
  const disabled = reading || state.busy;
  const apply = () => {
    if (kind !== "node" && !canonicalId(id)) {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    selectScope(
      trafficHref(
        kind === "node"
          ? { kind: "node", id: null }
          : ({ kind, id } as TrafficScope),
        peer,
        { protocol, resolution },
      ),
    );
  };
  return (
    <PageContainer
      className="management-page"
      title={t("traffic.title")}
      content={t("traffic.description")}
    >
      <Space orientation="vertical" size={16} className="full-width">
        <ScopePicker
          value={peer}
          selected={null}
          disabled={disabled}
          onChange={(peer) => {
            // Entity IDs belong to one node. Never carry them to another one.
            selectScope(
              trafficHref({ kind: "node", id: null }, peer, {
                protocol,
                resolution,
              }),
            );
          }}
        />
        <Alert type="info" showIcon title={t("traffic.definition")} />
        <>
          <Typography.Text type="secondary">
            {t(peer === null ? "traffic.local" : "traffic.remoteHint")}
          </Typography.Text>
          <div className="management-filter-bar">
            <div className="management-filter-field">
              <Typography.Text id="traffic-dimension-label">
                {t("traffic.dimension")}
              </Typography.Text>
              <Select
                aria-labelledby="traffic-dimension-label"
                aria-label={t("traffic.dimension")}
                value={kind}
                disabled={disabled}
                options={(["node", "user", "credential", "pool"] as const).map(
                  (value) => ({ value, label: t(`traffic.${value}`) }),
                )}
                onChange={(value) => {
                  setKind(value);
                  setId("");
                  setInvalid(false);
                }}
              />
            </div>
            {kind !== "node" && (
              <div className="management-filter-field management-filter-identifier">
                <Typography.Text id="traffic-id-label">
                  {t("traffic.id")}
                </Typography.Text>
                <Input
                  aria-labelledby="traffic-id-label"
                  aria-label={t("traffic.id")}
                  placeholder={t("traffic.idHint")}
                  disabled={disabled}
                  value={id}
                  maxLength={22}
                  status={invalid ? "error" : undefined}
                  onChange={(event) => setId(event.target.value)}
                  onPressEnter={apply}
                />
                {invalid && (
                  <Typography.Text type="danger">
                    {t("traffic.invalidId")}
                  </Typography.Text>
                )}
              </div>
            )}
            <Button type="primary" disabled={disabled} onClick={apply}>
              {t("traffic.apply")}
            </Button>
            <div className="management-filter-field">
              <Typography.Text id="traffic-protocol-label">
                {t("traffic.protocol")}
              </Typography.Text>
              <Select
                aria-labelledby="traffic-protocol-label"
                aria-label={t("traffic.protocol")}
                value={protocol ?? "all"}
                disabled={disabled}
                options={[
                  { value: "all", label: t("traffic.allProtocols") },
                  ...trafficProtocols.map((value) => ({
                    value,
                    label: protocolLabel(value),
                  })),
                ]}
                onChange={(value) =>
                  selectScope(
                    trafficHref(scope, peer, {
                      protocol:
                        value === "all" ? undefined : (value as ProxyProtocol),
                      resolution,
                    }),
                  )
                }
              />
            </div>
            <div className="management-filter-field">
              <Typography.Text id="traffic-resolution-label">
                {t("traffic.resolution")}
              </Typography.Text>
              <Select
                aria-labelledby="traffic-resolution-label"
                aria-label={t("traffic.resolution")}
                value={resolution}
                disabled={disabled || scope.kind === "credential"}
                options={(["minute", "hour", "day"] as const).map((value) => ({
                  value,
                  label: t(`traffic.${value}`),
                }))}
                onChange={(resolution) =>
                  selectScope(
                    trafficHref(scope, peer, { protocol, resolution }),
                  )
                }
              />
            </div>
          </div>
          <Space wrap>
            <Tag>{t(`traffic.${scope.kind}`)}</Tag>
            {scope.id !== null && (
              <Typography.Text copyable className="managed-identifier">
                {scope.id}
              </Typography.Text>
            )}
          </Space>
          <Snapshot
            key={`${peer ?? "local"}:${scope.kind}:${scope.id}:${protocol ?? "all"}:${resolution}`}
            peer={peer}
            scope={scope}
            protocol={protocol}
            resolution={resolution}
            onBusy={setReading}
          />
        </>
      </Space>
    </PageContainer>
  );
}

export default function TrafficPage() {
  const { t } = useMessages();
  const location = useLocation();
  let initial: ReturnType<typeof trafficLocation>;
  try {
    initial = trafficLocation(location.search);
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
      <Workspace key={location.search} initial={initial} />
    </ManagementGate>
  );
}
