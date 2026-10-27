import {
  Alert,
  Button,
  Card,
  Descriptions,
  Empty,
  Input,
  Modal,
  Space,
  Table,
  Typography,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { Link } from "@umijs/max";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import type {
  AlertEvent,
  AlertEventPage,
  AlertEpisode,
} from "../../api/alertEvents";
import { alertCodes, type AlertCode } from "../../api/alerts";
import { apiError, ApiError, type ManagementClient } from "../../api/client";
import { canonicalRevision } from "../../api/proxy";
import { errorMessage } from "../../api/messages";
import { useManagement } from "../../auth/context";
import { scopeHref } from "../../routing/scope";
import type { AckReview } from "../../auth/alert-acknowledgements";
import { useMessages, type MessageKey } from "../../hooks/useMessages";
import EpisodeReview, { recordedTime } from "./EpisodeReview";

export default function EventHistory({
  origin,
  initialEvent,
}: {
  origin: string | null;
  initialEvent: string | null;
}) {
  const { controller, state } = useManagement(),
    { t, intl } = useMessages();
  const epoch = controller.generation(),
    session = state.session;
  const binding = useMemo(
    () => ({ epoch, session, origin, initialEvent }),
    [epoch, session, origin, initialEvent],
  );
  type MissingRead = {
    binding: typeof binding;
    serial: number;
    nodeId: string;
    episodeId: string;
    reviewToken: object;
  };
  const latest = useRef(binding);
  latest.current = binding;
  const mounted = useRef(false),
    pending = useRef<AbortController | null>(null),
    serial = useRef(0);
  const local = useRef<{ epoch: number; node: string } | null>(null);
  const missingReadRef = useRef<MissingRead | null>(null);
  const [view, setView] = useState<{
    binding: typeof binding;
    node: string | null;
    page: AlertEventPage | null;
    event: AlertEvent | null;
    episode: AlertEpisode | null;
    fresh: boolean;
    path: (string | undefined)[];
    loading: boolean;
    error: ApiError | null;
  } | null>(null);
  const [writeBinding, setWriteBinding] = useState<typeof binding | null>(null),
    [idInput, setIdInput] = useState(initialEvent ?? ""),
    [invalid, setInvalid] = useState(false),
    [missingRead, setMissingRead] = useState<MissingRead | null>(null),
    [finishMissing, setFinishMissing] = useState<{
      proof: MissingRead;
      review: AckReview;
    } | null>(null);
  const writing = writeBinding === binding;
  const current = view?.binding === binding ? view : null;
  const reviews = controller.alertAcknowledgements;
  const notes = useSyncExternalStore(reviews.subscribe, reviews.snapshot);
  const readBlocked =
    state.busy ||
    state.phase !== "authenticated" ||
    writing ||
    !!current?.loading;
  const belongs = () =>
    mounted.current &&
    latest.current === binding &&
    controller.generation() === epoch &&
    controller.snapshot().session === session;
  const validMissing = (proof: MissingRead, review: AckReview) =>
    belongs() &&
    !!session &&
    missingReadRef.current === proof &&
    proof.binding === binding &&
    proof.serial === serial.current &&
    local.current?.epoch === epoch &&
    local.current.node === proof.nodeId &&
    review.intent.nodeId === proof.nodeId &&
    review.intent.episodeId === proof.episodeId &&
    review.intent.administratorId === session.administrator.id &&
    review.token === proof.reviewToken &&
    reviews.find(review.intent)?.token === review.token &&
    review.phase === "unknown";
  type ReadResult = {
    page?: AlertEventPage;
    event?: AlertEvent;
    episode?: AlertEpisode;
  };
  const read = async (
    work: (
      client: ManagementClient,
      node: string,
      signal: AbortSignal,
    ) => Promise<ReadResult>,
    path?: (string | undefined)[],
    requestedEpisode?: string,
  ) => {
    if (!session || readBlocked || pending.current || !belongs()) return;
    const request = new AbortController(),
      number = ++serial.current;
    pending.current = request;
    missingReadRef.current = null;
    setMissingRead(null);
    setFinishMissing(null);
    const valid = () =>
      belongs() && !request.signal.aborted && serial.current === number;
    const original = { review: null as AckReview | null };
    setView((previous) => ({
      binding,
      node: local.current?.epoch === epoch ? local.current.node : null,
      page: previous?.binding === binding ? previous.page : null,
      event: previous?.binding === binding ? previous.event : null,
      episode: previous?.binding === binding ? previous.episode : null,
      fresh: false,
      path:
        path ?? (previous?.binding === binding ? previous.path : [undefined]),
      loading: true,
      error: null,
    }));
    try {
      const { node, result } = await controller.resource(
        session,
        async (client, _csrf, signal) => {
          const node =
            local.current?.epoch === epoch
              ? local.current.node
              : (await client.node(signal)).node_id;
          if (valid()) local.current = { epoch, node };
          if (requestedEpisode) {
            const review = reviews.find({
              administratorId: session.administrator.id,
              nodeId: node,
              episodeId: requestedEpisode,
            });
            if (review?.phase === "unknown") original.review = review;
          }
          return { node, result: await work(client, node, signal) };
        },
        request.signal,
      );
      if (valid()) {
        local.current = { epoch, node };
        setView((previous) => ({
          binding,
          node,
          page:
            result.page ??
            (result.episode && previous?.binding === binding
              ? previous.page
              : null),
          event:
            result.event ??
            (result.episode && previous?.binding === binding
              ? previous.event
              : null),
          episode: result.episode ?? null,
          fresh: result.episode !== undefined,
          path: path ?? previous?.path ?? [undefined],
          loading: false,
          error: null,
        }));
      }
    } catch (error) {
      if (valid()) {
        const problem = apiError(error),
          node = local.current?.epoch === epoch ? local.current.node : null;
        // Only the original exact-ID read supplies this local review evidence.
        // A list failure or a generic 404 cannot establish an episode's absence.
        if (
          requestedEpisode &&
          original.review &&
          node &&
          problem.status === 404 &&
          problem.code === "alert_history_not_queryable"
        ) {
          const proof = {
            binding,
            serial: number,
            nodeId: node,
            episodeId: requestedEpisode,
            reviewToken: original.review.token,
          };
          missingReadRef.current = proof;
          setMissingRead(proof);
        }
        setView((previous) =>
          previous
            ? {
                ...previous,
                node:
                  local.current?.epoch === epoch
                    ? local.current.node
                    : previous.node,
                loading: false,
                fresh: false,
                error: problem,
              }
            : null,
        );
      }
    } finally {
      if (pending.current === request) pending.current = null;
    }
  };
  const page = (path: (string | undefined)[]) =>
    read(
      async (client, node, signal) => ({
        page: await client.alertEvents(
          node,
          {
            before: path.at(-1),
            limit: 10,
            origin_node_id: origin ?? undefined,
          },
          signal,
        ),
      }),
      path,
    );
  const exact = (id: string) => {
    if (!canonicalRevision(id)) {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    return read(async (client, node, signal) => ({
      event: await client.alertEvent(node, id, signal),
    }));
  };
  const episode = (id: string) =>
    read(
      async (client, node, signal) => ({
        episode: await client.alertEpisode(node, id, signal),
      }),
      undefined,
      id,
    );
  const finishMissingReview = async () => {
    const snapshot = finishMissing;
    if (
      !snapshot ||
      readBlocked ||
      !validMissing(snapshot.proof, snapshot.review)
    )
      return;
    setWriteBinding(binding);
    try {
      await reviews.reviewed(snapshot.review.token, () =>
        validMissing(snapshot.proof, snapshot.review),
      );
    } finally {
      if (belongs()) {
        setWriteBinding(null);
        setFinishMissing(null);
      }
    }
  };
  useEffect(() => {
    mounted.current = true;
    if (initialEvent) void exact(initialEvent);
    else void page([undefined]);
    return () => {
      mounted.current = false;
      serial.current++;
      pending.current?.abort();
      pending.current = null;
    };
  }, [binding]);
  const time = (value: string | null) =>
    value === null
      ? t("alertEvents.unknownTime")
      : (recordedTime(value, intl.locale) ??
        t("alertEvents.outsideDate", { value }));
  const reason = (event: AlertEvent) =>
    t(
      alertCodes.includes(event.code as AlertCode)
        ? (`alerts.code.${event.code}` as MessageKey)
        : "alerts.code.unknown",
    );
  const columns: ColumnsType<AlertEvent> = [
    { title: t("alertEvents.sequence"), dataIndex: "sequence" },
    {
      title: t("alertEvents.transition"),
      render: (_, row) => t(`alertEvents.transition.${row.transition}`),
    },
    {
      title: t("alerts.kind"),
      render: (_, row) => t(`alerts.kind.${row.kind}`),
    },
    {
      title: t("alerts.subject"),
      render: (_, row) => (
        <Space orientation="vertical" size={4}>
          <Typography.Text code>{row.origin_node_id}</Typography.Text>
          {row.origin_node_id !== row.node_id && (
            <Space orientation="vertical" size={4}>
              <Typography.Text type="secondary">
                {t("alerts.foreignObservation")}
              </Typography.Text>
              <Link to={scopeHref("/alerts", row.origin_node_id)}>
                {t("alerts.sourceNode")}
              </Link>
            </Space>
          )}
          {row.resource_id && (
            <Typography.Text code>{row.resource_id}</Typography.Text>
          )}
        </Space>
      ),
    },
    { title: t("alerts.reason"), render: (_, row) => reason(row) },
    {
      title: t("alertEvents.recorded"),
      render: (_, row) => time(row.recorded_at_unix_ms),
    },
    {
      title: t("alerts.action"),
      render: (_, row) => (
        <Button
          size="small"
          disabled={readBlocked}
          onClick={() => void episode(row.episode_id)}
        >
          {t("alertEvents.openEpisode")}
        </Button>
      ),
    },
  ];
  const retained = notes.filter(
    (note) =>
      note.intent.administratorId === session?.administrator.id &&
      note.intent.nodeId === current?.node,
  );
  return (
    <Space orientation="vertical" size={16} className="full-width">
      <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
        {t("alertEvents.scope")}
      </Typography.Paragraph>
      <Alert showIcon type="info" title={t("alertEvents.warning")} />
      {current?.page?.trimmed !== undefined && current.page.trimmed !== "0" && (
        <Alert showIcon type="warning" title={t("alertEvents.trimmed")} />
      )}
      <Button
        aria-label={t("alertEvents.refresh")}
        aria-busy={!!current?.loading}
        loading={!!current?.loading}
        disabled={readBlocked}
        onClick={() => void page([undefined])}
      >
        {t("alertEvents.refresh")}
      </Button>
      <label htmlFor="alert-event-id">{t("alertEvents.eventId")}</label>
      <Typography.Text type="secondary">
        {t("alertEvents.exactHint")}
      </Typography.Text>
      <Space.Compact className="full-width">
        <Input
          id="alert-event-id"
          value={idInput}
          maxLength={19}
          status={invalid ? "error" : undefined}
          disabled={readBlocked}
          onChange={(event) => {
            setIdInput(event.target.value);
            setInvalid(false);
          }}
          onPressEnter={() => void exact(idInput)}
        />
        <Button disabled={readBlocked} onClick={() => void exact(idInput)}>
          {t("alertEvents.lookup")}
        </Button>
      </Space.Compact>
      {invalid && (
        <Typography.Text type="danger">
          {t("alertEvents.invalidId")}
        </Typography.Text>
      )}
      {current?.error && (
        <Alert
          showIcon
          type="warning"
          title={t(
            current.error.code === "alert_history_not_queryable"
              ? "alertEvents.missing"
              : errorMessage(current.error),
          )}
        />
      )}
      {retained.map((note) => (
        <Alert
          key={note.intent.episodeId}
          showIcon
          type="warning"
          title={t(
            note.phase === "pending"
              ? "alertEvents.confirming"
              : "alertEvents.unknown",
          )}
          description={
            <Space wrap>
              <Typography.Text>
                {t("alertEvents.episode")}: {note.intent.episodeId},{" "}
                {t("alertEvents.latest")}: {note.intent.transitionSequence}
              </Typography.Text>
              <Button
                disabled={readBlocked}
                onClick={() => void episode(note.intent.episodeId)}
              >
                {t("alertEvents.readOriginal")}
              </Button>
              {missingRead && validMissing(missingRead, note) && (
                <Space orientation="vertical" size={8}>
                  <Typography.Text>
                    {t("alertEvents.missingReview")}
                  </Typography.Text>
                  <Button
                    disabled={readBlocked}
                    onClick={() =>
                      setFinishMissing({ proof: missingRead, review: note })
                    }
                  >
                    {t("alertEvents.finish")}
                  </Button>
                </Space>
              )}
            </Space>
          }
        />
      ))}
      {current?.event && (
        <Card
          size="small"
          title={`${t("alertEvents.sequence")} ${current.event.sequence}`}
        >
          <Space orientation="vertical" className="full-width">
            <Typography.Text>
              {t(`alertEvents.transition.${current.event.transition}`)}:{" "}
              {reason(current.event)}
            </Typography.Text>
            <Descriptions
              column={{ xs: 1, sm: 2 }}
              size="small"
              items={[
                {
                  key: "origin",
                  label: t("alerts.subject"),
                  children: (
                    <Typography.Text code>
                      {current.event.origin_node_id}
                    </Typography.Text>
                  ),
                },
                {
                  key: "observer",
                  label: t("alertEvents.observer"),
                  children: (
                    <Typography.Text code>
                      {current.event.node_id}
                    </Typography.Text>
                  ),
                },
                {
                  key: "boot",
                  label: t("alertEvents.boot"),
                  children: (
                    <Typography.Text code>
                      {current.event.boot_id}
                    </Typography.Text>
                  ),
                },
                {
                  key: "episode",
                  label: t("alertEvents.episode"),
                  children: current.event.episode_id,
                },
                {
                  key: "observed",
                  label: t("alerts.observed"),
                  children: time(current.event.observed_at_unix_ms),
                },
                {
                  key: "recorded",
                  label: t("alertEvents.recorded"),
                  children: time(current.event.recorded_at_unix_ms),
                },
                ...(current.event.end_reason
                  ? [
                      {
                        key: "end",
                        label: t("alertEvents.endReason"),
                        children: t(
                          `alertEvents.end.${current.event.end_reason}`,
                        ),
                      },
                    ]
                  : []),
                ...(current.event.administrator_id
                  ? [
                      {
                        key: "actor",
                        label: t("alertEvents.ackBy"),
                        children: (
                          <Typography.Text code>
                            {current.event.administrator_id}
                          </Typography.Text>
                        ),
                      },
                    ]
                  : []),
              ]}
            />
            <Button
              disabled={readBlocked}
              onClick={() => {
                if (current.event) void episode(current.event.episode_id);
              }}
            >
              {t("alertEvents.openEpisode")}
            </Button>
          </Space>
        </Card>
      )}
      {current?.episode &&
        !(
          missingRead?.binding === binding &&
          missingRead.episodeId === current.episode.id
        ) && (
          <EpisodeReview
            key={`${epoch}:${current.episode.node_id}:${current.episode.id}`}
            value={current.episode}
            fresh={current.fresh}
            blocked={!!current.loading}
            current={belongs}
            onRead={(id) => void episode(id)}
            onValue={(value) =>
              setView((previous) =>
                previous?.binding === binding
                  ? { ...previous, episode: value, fresh: true, error: null }
                  : previous,
              )
            }
            onInvalid={() =>
              setView((previous) =>
                previous?.binding === binding
                  ? { ...previous, fresh: false }
                  : previous,
              )
            }
            onBusy={(value) => setWriteBinding(value ? binding : null)}
          />
        )}
      <Modal
        open={
          finishMissing !== null &&
          validMissing(finishMissing.proof, finishMissing.review)
        }
        title={t("alertEvents.finish")}
        okText={t("alertEvents.finish")}
        cancelText={t("users.cancel")}
        confirmLoading={writing}
        okButtonProps={{ disabled: readBlocked }}
        cancelButtonProps={{ disabled: writing }}
        onOk={() => void finishMissingReview()}
        onCancel={() => {
          if (!writing) setFinishMissing(null);
        }}
      >
        <Typography.Paragraph>
          {t("alertEvents.missingReview")}
        </Typography.Paragraph>
      </Modal>
      {current?.page && (
        <>
          <Table<AlertEvent>
            rowKey="sequence"
            columns={columns}
            dataSource={current.page.items}
            loading={current.loading}
            pagination={false}
            scroll={{ x: 1050 }}
            locale={{
              emptyText: <Empty description={t("alertEvents.empty")} />,
            }}
          />
          <Space wrap>
            <Button
              disabled={readBlocked || current.path.length <= 1}
              onClick={() => void page(current.path.slice(0, -1))}
            >
              {t("users.previous")}
            </Button>
            <Button
              disabled={
                readBlocked ||
                !!current.error ||
                current.page.next_cursor === null
              }
              onClick={() => {
                if (current.page?.next_cursor)
                  void page([...current.path, current.page.next_cursor]);
              }}
            >
              {t("users.next")}
            </Button>
          </Space>
        </>
      )}
    </Space>
  );
}
