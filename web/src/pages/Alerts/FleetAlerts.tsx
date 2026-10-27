import {
  Alert,
  Button,
  Card,
  Collapse,
  Descriptions,
  Empty,
  Space,
  Tag,
  Typography,
} from "antd";
import { Link } from "@umijs/max";
import { useEffect, useRef, useState } from "react";
import { apiError, type ApiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";
import { scopeHref } from "../../routing/scope";
import ObservationCoverage from "./ObservationCoverage";
import {
  FLEET_POLL_MS,
  NODE_ALERT_STALE_MS,
  freshRow,
  readFleet,
  type FleetRow,
} from "./fleet";
import {
  observationDeadline,
  useObservationExpiry,
} from "./useObservationExpiry";

export default function FleetAlerts() {
  const { controller, state } = useManagement(),
    { t, intl } = useMessages();
  const epoch = controller.generation(),
    session = state.session;
  const [run, setRun] = useState<{
      epoch: number;
      session: NonNullable<typeof session>;
    } | null>(null),
    [view, setView] = useState<{
      epoch: number;
      session: typeof session;
      rows: FleetRow[];
      loading: boolean;
      error: ApiError | null;
      completed: number | null;
    } | null>(null);
  const currentRun = useRef(run);
  currentRun.current = run;
  const [visible, setVisible] = useState(
    () => document.visibilityState !== "hidden",
  );
  useEffect(() => {
    const change = () => {
      setVisible(document.visibilityState !== "hidden");
      if (document.visibilityState === "hidden") {
        currentRun.current = null;
        setRun(null);
      }
    };
    document.addEventListener("visibilitychange", change);
    return () => document.removeEventListener("visibilitychange", change);
  }, []);
  useEffect(() => {
    if (!session || state.phase !== "authenticated" || state.busy || !visible) {
      currentRun.current = null;
      setRun(null);
      return;
    }
    if (!run) return;
    if (run.epoch !== epoch || run.session !== session) {
      currentRun.current = null;
      setRun(null);
      return;
    }
    let disposed = false,
      pending: AbortController | null = null,
      timer: ReturnType<typeof setTimeout> | undefined;
    const belongs = () =>
      !disposed &&
      currentRun.current === run &&
      controller.generation() === epoch &&
      controller.snapshot().session === session &&
      !controller.snapshot().busy &&
      document.visibilityState !== "hidden";
    const round = async () => {
      if (!belongs() || pending) return;
      const request = new AbortController();
      pending = request;
      const current = () => belongs() && !request.signal.aborted;
      setView((previous) => ({
        epoch,
        session,
        rows:
          previous?.epoch === epoch && previous.session === session
            ? previous.rows
            : [],
        loading: true,
        error: null,
        completed:
          previous?.epoch === epoch && previous.session === session
            ? previous.completed
            : null,
      }));
      try {
        const rows = await controller.resource(
          session,
          (client, _csrf, signal) =>
            readFleet(client, signal, current, (rows) => {
              if (current())
                setView({
                  epoch,
                  session,
                  rows: rows.map((row) => ({ ...row })),
                  loading: true,
                  error: null,
                  completed: null,
                });
            }),
          request.signal,
        );
        if (current())
          setView({
            epoch,
            session,
            rows,
            loading: false,
            error: null,
            completed: Date.now(),
          });
      } catch (failure) {
        if (current()) {
          setView((previous) => ({
            epoch,
            session,
            rows: previous?.rows ?? [],
            loading: false,
            error: apiError(failure),
            completed: null,
          }));
          currentRun.current = null;
          setRun(null);
        }
      } finally {
        if (pending === request) pending = null;
        if (current()) timer = setTimeout(() => void round(), FLEET_POLL_MS);
      }
    };
    void round();
    return () => {
      disposed = true;
      pending?.abort();
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [controller, epoch, session, state.phase, state.busy, visible, run]);
  const current =
    view?.epoch === epoch && view.session === session ? view : null;
  const started =
      run !== null && run.epoch === epoch && run.session === session,
    reading = started && !!current?.loading;
  const now = performance.now();
  const expiry =
    current?.rows.reduce<number | null>((earliest, row) => {
      if (!freshRow(row, now) || !row.page) return earliest;
      const deadline = observationDeadline(
        row.page.age_millis,
        row.received,
        NODE_ALERT_STALE_MS,
      );
      return deadline === null
        ? earliest
        : earliest === null
          ? deadline
          : Math.min(earliest, deadline);
    }, null) ?? null;
  useObservationExpiry(
    expiry,
    started && !reading && !current?.error && visible && !state.busy,
  );
  const known =
    started && !current?.error && !reading
      ? (current?.rows.filter((row) => freshRow(row, now)).length ?? 0)
      : 0;
  const status = (row: FleetRow) =>
    !started
      ? "stopped"
      : current?.error || reading
        ? "waiting"
        : row.outcome === "read"
          ? freshRow(row, now)
            ? "read"
            : "stale"
          : row.outcome;
  return (
    <Space orientation="vertical" size={16} className="full-width">
      <Alert
        showIcon
        type="info"
        title={t("fleet.hint")}
        description={t("fleet.scope")}
      />
      <Space wrap>
        <Button
          disabled={
            started || state.busy || state.phase !== "authenticated" || !visible
          }
          onClick={() => {
            if (
              !session ||
              controller.generation() !== epoch ||
              controller.snapshot().session !== session ||
              controller.snapshot().busy ||
              document.visibilityState === "hidden"
            )
              return;
            const next = Object.freeze({ epoch, session });
            currentRun.current = next;
            setRun(next);
          }}
        >
          {t("fleet.start")}
        </Button>
        <Button
          disabled={!started}
          onClick={() => {
            currentRun.current = null;
            setRun(null);
          }}
        >
          {t("fleet.stop")}
        </Button>
        <Typography.Text>
          {t(started ? "fleet.running" : "fleet.stopped")}
        </Typography.Text>
        <Typography.Text>
          {t("fleet.known", { known, total: current?.rows.length ?? 0 })}
        </Typography.Text>
      </Space>
      {current?.error && (
        <Alert
          showIcon
          type="warning"
          title={t(
            current.error.code === "fleet_registry_changed"
              ? "fleet.registryChanged"
              : errorMessage(current.error),
          )}
        />
      )}
      {reading && (
        <Typography.Text role="status">{t("fleet.reading")}</Typography.Text>
      )}
      {!current?.rows.length && <Empty description={t("fleet.unread")} />}
      {current?.rows.map((row) => {
        const outcome = status(row),
          confirmed = outcome === "read",
          page = row.page;
        return (
          <Card
            key={row.target?.node_id ?? "local"}
            size="small"
            title={row.target?.name ?? t("fleet.local")}
          >
            <Space orientation="vertical" className="full-width" size={12}>
              <Typography.Text code>{row.nodeId}</Typography.Text>
              <Tag color={confirmed ? "blue" : "default"}>
                {t(`fleet.state.${outcome}`)}
              </Tag>
              <Descriptions
                size="small"
                column={{ xs: 1, sm: 2 }}
                items={[
                  {
                    key: "active",
                    label: t("alerts.activeCount"),
                    children:
                      confirmed && page
                        ? intl.formatNumber(page.active_count)
                        : t("fleet.unknown"),
                  },
                  {
                    key: "recent",
                    label: t("alerts.recentCount"),
                    children:
                      confirmed && page
                        ? intl.formatNumber(page.recent_count)
                        : t("fleet.unknown"),
                  },
                ]}
              />
              {row.error && (
                <Typography.Text type="warning">
                  {t(errorMessage(row.error))}
                </Typography.Text>
              )}
              {page?.collection_error && (
                <Typography.Text type="warning">
                  {t("alerts.collectionError")}
                </Typography.Text>
              )}
              {page && page.dropped !== "0" && (
                <Typography.Text type="warning">
                  {t("alerts.dropped", { count: page.dropped })}
                </Typography.Text>
              )}
              {page && (
                <Collapse
                  items={[
                    {
                      key: "coverage",
                      label: t("alerts.coverage"),
                      children: <ObservationCoverage value={page.coverage} />,
                    },
                  ]}
                />
              )}
              <Link to={scopeHref("/alerts", row.target?.node_id ?? null)}>
                {t("fleet.open")}
              </Link>
            </Space>
          </Card>
        );
      })}
    </Space>
  );
}
