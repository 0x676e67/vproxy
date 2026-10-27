import {
  Alert,
  Button,
  Card,
  Collapse,
  Descriptions,
  Drawer,
  Input,
  Space,
  Tag,
  Typography,
} from "antd";
import { useEffect, useMemo, useRef, useState } from "react";
import { apiError, type ApiError } from "../../api/client";
import {
  commandHistoryDate,
  type CommandHistoryEntry,
  type CommandHistoryPage,
} from "../../api/commandHistory";
import { errorMessage } from "../../api/messages";
import { canonicalId } from "../../api/proxy";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";

const PAGE_SIZE = 20;
function JobState({ entry }: { entry: CommandHistoryEntry }) {
  const { t } = useMessages();
  const job = entry.job;
  return (
    <Tag
      color={
        job.state === "applied"
          ? "green"
          : ["blocked", "rejected"].includes(job.state)
            ? "warning"
            : "default"
      }
    >
      {t(
        job.resource === "proxy_endpoints" && job.state === "saved"
          ? "connections.metadataSaved"
          : `control.job.${job.state}`,
      )}
    </Tag>
  );
}

function EntryDetails({ entry }: { entry: CommandHistoryEntry }) {
  const { t, intl } = useMessages();
  const date = (seconds: string | null) =>
    seconds === null
      ? t("commandHistory.unknownTime")
      : (commandHistoryDate(seconds)?.toLocaleString(intl.locale) ??
        t("commandHistory.rawTime", { seconds }));
  const identifier = (id: string | null) =>
    id === null ? (
      t("commandHistory.resultUnknown")
    ) : (
      <Typography.Text code style={{ overflowWrap: "anywhere" }}>
        {id}
      </Typography.Text>
    );
  const job = entry.job;
  return (
    <Space orientation="vertical" size={12} className="full-width">
      {entry.imported && (
        <Alert showIcon type="info" title={t("commandHistory.imported")} />
      )}
      <Descriptions
        size="small"
        column={1}
        items={[
          {
            key: "sequence",
            label: t("commandHistory.sequence"),
            children: entry.sequence,
          },
          {
            key: "job",
            label: t("control.jobId"),
            children: identifier(job.job_id),
          },
          {
            key: "controller",
            label: t("commandHistory.controller"),
            children: identifier(entry.controller_node_id),
          },
          {
            key: "target",
            label: t("commandHistory.target"),
            children: identifier(job.node_id),
          },
          {
            key: "administrator",
            label: t("commandHistory.administrator"),
            children: identifier(entry.administrator_id),
          },
          {
            key: "protocol",
            label: t("commandHistory.version"),
            children: `v${entry.protocol_version}`,
          },
          {
            key: "epoch",
            label: t("control.epoch"),
            children: job.controller_epoch,
          },
          {
            key: "command",
            label: t("control.sequence"),
            children: job.command_id,
          },
          {
            key: "revision",
            label: t("users.savedRevision"),
            children:
              job.resource === "proxy_endpoints"
                ? (job.metadata_revision ?? t("commandHistory.resultUnknown"))
                : (job.policy_revision ?? t("commandHistory.resultUnknown")),
          },
          {
            key: "attempts",
            label: t("control.attempts"),
            children: job.attempts,
          },
          {
            key: "user",
            label: t("commandHistory.userId"),
            children: identifier(entry.user_id),
          },
          {
            key: "credential",
            label: t("commandHistory.credentialId"),
            children: identifier(entry.credential_id),
          },
          {
            key: "recorded",
            label: t("commandHistory.recorded"),
            children: date(entry.recorded_at_unix_s),
          },
          {
            key: "updated",
            label: t("commandHistory.updated"),
            children: date(entry.updated_at_unix_s),
          },
          ...(job.outcome_code
            ? [
                {
                  key: "outcome",
                  label: t("commandHistory.outcome"),
                  children: (
                    <Typography.Text code>{job.outcome_code}</Typography.Text>
                  ),
                },
              ]
            : []),
        ]}
      />
    </Space>
  );
}

/** Reads only this controller's durable, non-secret journal. No ticket from this
 * drawer is passed to a write, refresh-receipt or retry control. */
export default function CommandHistory({
  localNodeId,
  targetId,
  disabled,
}: {
  localNodeId: string;
  targetId: string;
  disabled: boolean;
}) {
  const { controller, state } = useManagement();
  const { t } = useMessages();
  const epoch = controller.generation();
  const binding = useMemo(
    () => ({ epoch, localNodeId, targetId, session: state.session }),
    [epoch, localNodeId, targetId, state.session],
  );
  const latestBinding = useRef(binding);
  latestBinding.current = binding;
  const mounted = useRef(false);
  const serial = useRef(0);
  const pending = useRef<AbortController | null>(null);
  const [opened, setOpened] = useState<typeof binding | null>(null);
  const open = opened === binding;
  const [jobId, setJobId] = useState("");
  const [invalidJob, setInvalidJob] = useState(false);
  const [view, setView] = useState<{
    binding: typeof binding;
    page: CommandHistoryPage | null;
    entry: CommandHistoryEntry | null;
    path: (string | undefined)[];
    exact: boolean;
    loading: boolean;
    error: ApiError | null;
  } | null>(null);
  const current = view?.binding === binding ? view : null;
  const loading = current?.loading === true;
  const unavailable = disabled || state.busy || !state.session;
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      serial.current++;
      pending.current?.abort();
    };
  }, []);
  useEffect(
    () => () => {
      serial.current++;
      pending.current?.abort();
      pending.current = null;
    },
    [binding],
  );
  const close = () => {
    serial.current++;
    pending.current?.abort();
    pending.current = null;
    setOpened(null);
    setView(null);
    setJobId("");
    setInvalidJob(false);
  };
  const read = async (path: (string | undefined)[], exactJob?: string) => {
    const session = state.session;
    if (unavailable || !session || !mounted.current || pending.current) return;
    if (exactJob !== undefined && !canonicalId(exactJob)) {
      setInvalidJob(true);
      return;
    }
    setInvalidJob(false);
    const request = new AbortController(),
      id = ++serial.current;
    pending.current = request;
    const belongs = () =>
      mounted.current &&
      !request.signal.aborted &&
      id === serial.current &&
      latestBinding.current === binding &&
      controller.generation() === epoch &&
      controller.snapshot().session === session;
    setView({
      binding,
      page: null,
      entry: null,
      path,
      exact: exactJob !== undefined,
      loading: true,
      error: null,
    });
    try {
      const result = await controller.resource<
        CommandHistoryPage | CommandHistoryEntry
      >(
        session,
        (client, _csrf, signal) =>
          exactJob === undefined
            ? client.targetCommandHistory(
                targetId,
                localNodeId,
                { before: path.at(-1), limit: PAGE_SIZE },
                signal,
              )
            : client.targetCommandHistoryEntry(
                targetId,
                localNodeId,
                exactJob,
                signal,
              ),
        request.signal,
      );
      if (belongs())
        setView({
          binding,
          page: "items" in result ? result : null,
          entry: "items" in result ? null : result,
          path,
          exact: exactJob !== undefined,
          loading: false,
          error: null,
        });
    } catch (problem) {
      if (belongs())
        setView({
          binding,
          page: null,
          entry: null,
          path,
          exact: exactJob !== undefined,
          loading: false,
          error: apiError(problem),
        });
    } finally {
      if (pending.current === request) pending.current = null;
    }
  };
  const title = (entry: CommandHistoryEntry) => (
    <Space wrap>
      <Typography.Text>
        {t(`commandHistory.action.${entry.action}`)}
      </Typography.Text>
      <JobState entry={entry} />
      <Typography.Text code>{entry.job.job_id}</Typography.Text>
    </Space>
  );
  return (
    <>
      <Button
        disabled={unavailable}
        onClick={() => {
          setOpened(binding);
          setJobId("");
          void read([undefined]);
        }}
      >
        {t("commandHistory.open")}
      </Button>
      <Drawer
        open={open}
        title={t("commandHistory.title")}
        onClose={close}
        destroyOnHidden
        styles={{ wrapper: { width: "min(800px, 100vw)" } }}
        extra={<Button onClick={close}>{t("commandHistory.close")}</Button>}
      >
        {open && (
          <Space orientation="vertical" size={16} className="full-width">
            <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
              {t("commandHistory.scope")}
            </Typography.Paragraph>
            <Typography.Text code style={{ overflowWrap: "anywhere" }}>
              {targetId}
            </Typography.Text>
            <Alert
              type="warning"
              showIcon
              title={t("commandHistory.limit")}
              description={
                <Space orientation="vertical" size={8}>
                  <span>{t("commandHistory.secret")}</span>
                  <span>{t("commandHistory.historical")}</span>
                </Space>
              }
            />
            <Button
              aria-label={t("commandHistory.refresh")}
              aria-busy={loading}
              loading={loading}
              disabled={unavailable || loading}
              onClick={() => void read([undefined])}
            >
              {t("commandHistory.refresh")}
            </Button>
            <label htmlFor={`command-history-${targetId}`}>
              {t("commandHistory.lookupLabel")}
            </label>
            <Space.Compact className="full-width">
              <Input
                id={`command-history-${targetId}`}
                value={jobId}
                maxLength={22}
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                status={invalidJob ? "error" : undefined}
                disabled={unavailable || loading}
                aria-describedby={`command-history-hint-${targetId}`}
                onChange={(event) => {
                  setJobId(event.target.value);
                  setInvalidJob(false);
                }}
                onPressEnter={() => void read([undefined], jobId)}
              />
              <Button
                disabled={unavailable || loading}
                onClick={() => void read([undefined], jobId)}
              >
                {t("commandHistory.lookup")}
              </Button>
            </Space.Compact>
            <Typography.Text
              id={`command-history-hint-${targetId}`}
              type={invalidJob ? "danger" : "secondary"}
            >
              {t(
                invalidJob
                  ? "commandHistory.invalidJob"
                  : "commandHistory.lookupHint",
              )}
            </Typography.Text>
            {current?.error && (
              <Alert
                type="warning"
                showIcon
                title={t(
                  current.exact && current.error.status === 404
                    ? "commandHistory.missing"
                    : "commandHistory.unavailable",
                )}
                description={t(errorMessage(current.error))}
              />
            )}
            {current?.entry && (
              <Card size="small" title={title(current.entry)}>
                <EntryDetails entry={current.entry} />
              </Card>
            )}
            {current?.page && (
              <>
                {current.page.trimmed && (
                  <Alert
                    type="info"
                    showIcon
                    title={t("commandHistory.trimmed")}
                  />
                )}
                {current.page.oldest_sequence !== null && (
                  <Typography.Text type="secondary">
                    {t("commandHistory.oldest")}: {current.page.oldest_sequence}
                  </Typography.Text>
                )}
                {current.page.items.length === 0 ? (
                  <Alert
                    type="info"
                    showIcon
                    title={t("commandHistory.empty")}
                  />
                ) : (
                  <Collapse
                    items={current.page.items.map((entry) => ({
                      key: entry.job.job_id,
                      label: title(entry),
                      children: <EntryDetails entry={entry} />,
                    }))}
                  />
                )}
                <Space wrap>
                  <Button
                    disabled={
                      unavailable || loading || current.path.length <= 1
                    }
                    onClick={() => void read(current.path.slice(0, -1))}
                  >
                    {t("commandHistory.previous")}
                  </Button>
                  <Button
                    disabled={
                      unavailable ||
                      loading ||
                      current.page.next_cursor === null
                    }
                    onClick={() => {
                      if (current.page?.next_cursor)
                        void read([...current.path, current.page.next_cursor]);
                    }}
                  >
                    {t("commandHistory.next")}
                  </Button>
                </Space>
              </>
            )}
          </Space>
        )}
      </Drawer>
    </>
  );
}
