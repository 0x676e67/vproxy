import { ProCard } from "@ant-design/pro-components";
import {
  Alert,
  Button,
  Descriptions,
  Modal,
  Space,
  Tag,
  Typography,
} from "antd";
import { useEffect, useRef, useState } from "react";
import { apiError, type ApiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import type { Job, PolicyJob } from "../../api/targets";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";

type Action = "refresh" | "retry" | "supersede";
/** A durable ticket is not a replay button. Every retry/supersession is explicit. */
export default function CommandPanel({
  targetId,
  job,
  busy,
  onChange,
  onBusy,
  onRefresh,
  onUserResult,
  userResultBusy = false,
  canStart,
}: {
  targetId: string;
  job: Job | null | undefined;
  busy: boolean;
  onChange: (job: Job | null) => void;
  onBusy: (busy: boolean) => void;
  onRefresh: () => void;
  onUserResult?: (job: PolicyJob) => void;
  userResultBusy?: boolean;
  /** Pure predicate used both for presentation and immediately before dispatch. */
  canStart?: (action: Action | "read", jobId?: string) => boolean;
}) {
  const { t } = useMessages();
  const { controller, state } = useManagement();
  const epoch = controller.generation();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [confirmation, setConfirmation] = useState<{
    action: Action;
    id: string;
    epoch: number;
  } | null>(null);
  const request = useRef<AbortController | null>(null);
  const canRun = (action: Action | "read", jobId?: string): boolean =>
    canStart?.(action, jobId) !== false;
  useEffect(() => {
    setConfirmation(null);
    setError(null);
    return () => {
      request.current?.abort();
      onBusy(false);
    };
  }, [epoch, targetId, onBusy]);
  const run = async (action: Action | "read", jobId?: string) => {
    if (
      !state.session ||
      state.busy ||
      busy ||
      request.current ||
      !canRun(action, jobId)
    )
      return;
    if (
      (job?.resource === "proxy_endpoints" || job?.maintenance !== undefined) &&
      action !== "read" &&
      action !== "refresh"
    )
      return;
    const work = new AbortController();
    request.current = work;
    const generation = controller.generation();
    setPending(true);
    onBusy(true);
    setError(null);
    try {
      const result = await controller.resource(
        state.session,
        (client, csrf, signal) =>
          action === "read"
            ? client.targetJob(targetId, signal)
            : job?.resource === "proxy_endpoints" && action === "refresh"
              ? client.refreshEndpointCommand(
                  targetId,
                  job.job_id,
                  csrf,
                  signal,
                )
              : job?.maintenance !== undefined && action === "refresh"
                ? client.maintenanceRefresh(targetId, job.job_id, csrf, signal)
                : client.jobAction(targetId, action, jobId!, csrf, signal),
        work.signal,
      );
      if (!work.signal.aborted && generation === controller.generation()) {
        onChange(result);
        setConfirmation(null);
      }
    } catch (error) {
      if (!work.signal.aborted && generation === controller.generation())
        setError(apiError(error));
    } finally {
      if (request.current === work) {
        request.current = null;
        setPending(false);
        onBusy(false);
      }
    }
  };
  const disabled = busy || pending || state.busy;
  const unsettled = job?.state === "pending" || job?.state === "blocked";
  return (
    <ProCard
      title={t("control.command")}
      variant="outlined"
      extra={
        <Button
          loading={pending}
          disabled={disabled || !canRun("read")}
          onClick={() => void run("read")}
        >
          {t("control.readTicket")}
        </Button>
      }
    >
      <Space orientation="vertical" className="full-width">
        {error && (
          <Alert
            type="error"
            title={t(errorMessage(error))}
            action={
              <Button
                disabled={disabled || !canRun("read")}
                onClick={onRefresh}
              >
                {t("users.refresh")}
              </Button>
            }
          />
        )}
        {job ? (
          <>
            <Descriptions
              column={{ xs: 1, sm: 2, lg: 3 }}
              items={[
                {
                  key: "state",
                  label: t("users.state"),
                  children: (
                    <Tag
                      color={
                        job.state === "applied"
                          ? "green"
                          : job.state === "rejected" || job.state === "blocked"
                            ? "warning"
                            : "default"
                      }
                    >
                      {t(
                        job.resource === "proxy_endpoints" &&
                          job.state === "saved"
                          ? "connections.metadataSaved"
                          : `control.job.${job.state}`,
                      )}
                    </Tag>
                  ),
                },
                {
                  key: "id",
                  label: t("control.jobId"),
                  children: (
                    <Typography.Text className="managed-identifier">
                      {job.job_id}
                    </Typography.Text>
                  ),
                },
                {
                  key: "epoch",
                  label: t("control.epoch"),
                  children: job.controller_epoch,
                },
                {
                  key: "number",
                  label: t("control.sequence"),
                  children: job.command_id,
                },
                {
                  key: "revision",
                  label: t(
                    job.resource === "proxy_endpoints"
                      ? "connections.metadataRevision"
                      : "users.savedRevision",
                  ),
                  children:
                    (job.resource === "proxy_endpoints"
                      ? job.metadata_revision
                      : job.policy_revision) ?? "—",
                },
                {
                  key: "attempts",
                  label: t("control.attempts"),
                  children: job.attempts,
                },
                ...(job.routing
                  ? [
                      {
                        key: "routing",
                        label: t("resources.id"),
                        children: (
                          <Typography.Text
                            code
                            copyable
                            className="managed-identifier"
                          >
                            {job.routing.kind}: {job.routing.id}
                          </Typography.Text>
                        ),
                      },
                    ]
                  : []),
                ...(job.preset
                  ? [
                      {
                        key: "preset",
                        label: t("presets.title"),
                        children: (
                          <Typography.Text
                            code
                            copyable
                            className="managed-identifier"
                          >
                            {job.preset.kind}: {job.preset.id}
                          </Typography.Text>
                        ),
                      },
                    ]
                  : []),
                ...(job.maintenance !== undefined
                  ? [
                      {
                        key: "maintenance",
                        label: t("maintenance.intent"),
                        children: t(
                          job.maintenance.accepting
                            ? "maintenance.accepting"
                            : "maintenance.paused",
                        ),
                      },
                    ]
                  : []),
              ]}
            />
            <Typography.Paragraph type="secondary">
              {t(
                job.resource === "proxy_endpoints"
                  ? "connections.metadataTicketHint"
                  : "control.ticketHint",
              )}
            </Typography.Paragraph>
            {job.maintenance !== undefined && (
              <Typography.Paragraph type="secondary">
                {t("maintenance.queue")}
              </Typography.Paragraph>
            )}
            <Space wrap>
              {onUserResult &&
                job.resource === undefined &&
                job.user_creation === true &&
                !job.routing &&
                !job.preset &&
                job.state !== "rejected" &&
                job.state !== "superseded" && (
                  <Button
                    loading={userResultBusy}
                    disabled={disabled || !canRun("read", job.job_id)}
                    onClick={() => onUserResult(job)}
                  >
                    {t("control.readCreatedUser")}
                  </Button>
                )}
              {(job.resource === "proxy_endpoints" ||
              job.maintenance !== undefined
                ? (["refresh"] as const)
                : (["refresh", "retry", "supersede"] as const)
              ).map((action) => (
                <Button
                  key={action}
                  danger={action !== "refresh"}
                  disabled={
                    disabled ||
                    (action !== "refresh" && !unsettled) ||
                    !canRun(action, job.job_id)
                  }
                  onClick={() =>
                    action === "refresh"
                      ? void run(action, job.job_id)
                      : setConfirmation({ action, id: job.job_id, epoch })
                  }
                >
                  {t(
                    job.resource === "proxy_endpoints"
                      ? "connections.checkDeclaration"
                      : `control.${action}`,
                  )}
                </Button>
              ))}
            </Space>
            {onUserResult && job.user_creation === true && (
              <Typography.Text type="secondary">
                {t("control.readCreatedUserHint")}
              </Typography.Text>
            )}
          </>
        ) : (
          <Typography.Text type="secondary">
            {t(job === undefined ? "control.jobUnread" : "control.noJob")}
          </Typography.Text>
        )}
      </Space>
      {confirmation && confirmation.epoch === epoch && (
        <Modal
          open
          maskClosable={false}
          title={t(`control.${confirmation.action}`)}
          confirmLoading={pending}
          okButtonProps={{
            disabled: disabled || !canRun(confirmation.action, confirmation.id),
          }}
          okText={t("users.confirm")}
          cancelText={t("users.cancel")}
          onCancel={() => !pending && setConfirmation(null)}
          onOk={() => void run(confirmation.action, confirmation.id)}
        >
          <Alert
            type="warning"
            showIcon
            title={t("control.secretUnavailable")}
          />
          <Typography.Paragraph>
            {t(
              confirmation.action === "retry"
                ? "control.retryHint"
                : "control.supersedeHint",
            )}
          </Typography.Paragraph>
        </Modal>
      )}
    </ProCard>
  );
}
