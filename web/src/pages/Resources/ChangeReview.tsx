import { Alert, Button, Collapse, Descriptions, Space, Typography } from "antd";
import type { RoutingChange } from "../../auth/routing-changes";
import { errorMessage } from "../../api/messages";
import { useMessages, type MessageKey } from "../../hooks/useMessages";

/** A current snapshot supports a new decision; it does not replay the old write. */
export default function ChangeReview({
  change,
  epoch,
  reading,
  blocked,
  readFailed,
  read,
  proceed,
}: {
  change: RoutingChange;
  epoch: number;
  reading: boolean;
  blocked: boolean;
  readFailed: boolean;
  read: () => void;
  proceed: () => void;
}) {
  const { t } = useMessages();
  const observed =
    change.observation?.generation === epoch ? change.observation : null;
  const pending = change.phase === "pending";
  const waiting = change.phase === "waiting";
  const action: Record<RoutingChange["intent"]["action"], MessageKey> = {
    create: "resources.register",
    retire: "resources.retire",
    drain: "resources.drain",
    resume: "resources.resume",
    add_member: "resources.addMember",
    remove_member: "resources.removeMember",
    set_preset: "users.save",
  };
  const differentTicket =
    !!change.ticket &&
    !!observed &&
    (observed.job?.node_id !== change.ticket.node_id ||
      observed.job.job_id !== change.ticket.job_id ||
      observed.job.controller_epoch !== change.ticket.controller_epoch ||
      observed.job.command_id !== change.ticket.command_id ||
      observed.job.expected_policy_revision !==
        change.ticket.expected_policy_revision);
  const ready =
    !!observed &&
    observed.writable &&
    observed.job?.state !== "pending" &&
    observed.job?.state !== "blocked";
  return (
    <Alert
      showIcon
      type={
        pending ? "info" : change.phase === "rejected" ? "error" : "warning"
      }
      title={t(
        pending
          ? "resources.changePending"
          : waiting
            ? "users.operationPending"
            : change.phase === "rejected"
              ? "users.operationRejected"
              : "users.operationUnknown",
      )}
      description={
        <Space orientation="vertical" className="full-width">
          <Typography.Text>
            {t(
              pending
                ? "resources.changePendingHint"
                : waiting
                  ? "resources.changeWaitingHint"
                  : change.phase === "rejected"
                    ? "resources.changeRejectedHint"
                    : "users.mutationUncertain",
            )}
          </Typography.Text>
          <Typography.Text>
            {t(action[change.intent.action])}:{" "}
            {t(
              change.intent.kind === "pool_preset"
                ? "presets.title"
                : `resources.${change.intent.kind}`,
            )}
          </Typography.Text>
          {change.error && (
            <Typography.Text>{t(errorMessage(change.error))}</Typography.Text>
          )}
          {observed && (
            <>
              <Typography.Text>
                {t("resources.changeObservationHint")}
              </Typography.Text>
              <Typography.Text>
                {t("resources.globalRevision")}: {observed.policyRevision}
              </Typography.Text>
              {!ready && (
                <Typography.Text>
                  {t("resources.changeNotReady")}
                </Typography.Text>
              )}
              {differentTicket && (
                <Typography.Text>
                  {t("resources.changeTicketChanged")}
                </Typography.Text>
              )}
            </>
          )}
          {!pending && (
            <Space wrap>
              <Button
                disabled={blocked || reading}
                loading={reading}
                onClick={read}
              >
                {t("resources.readChangeState")}
              </Button>
              <Button
                disabled={blocked || reading || readFailed || !ready}
                onClick={proceed}
              >
                {t("control.continueChange")}
              </Button>
            </Space>
          )}
          <Collapse
            size="small"
            items={[
              {
                key: "details",
                label: t("users.operationDetails"),
                children: (
                  <Descriptions
                    column={{ xs: 1, sm: 2 }}
                    items={[
                      {
                        key: "node",
                        label: t("control.changeNode"),
                        children: (
                          <Typography.Text className="managed-identifier">
                            {change.scope.peer ?? change.scope.nodeId}
                          </Typography.Text>
                        ),
                      },
                      {
                        key: "resource",
                        label: t("resources.id"),
                        children: (
                          <Typography.Text className="managed-identifier">
                            {change.intent.resourceId ??
                              t("resources.changeNewResource")}
                          </Typography.Text>
                        ),
                      },
                      ...(change.intent.memberId
                        ? [
                            {
                              key: "member",
                              label: t("resources.changeMemberId"),
                              children: (
                                <Typography.Text className="managed-identifier">
                                  {change.intent.memberId}
                                </Typography.Text>
                              ),
                            },
                          ]
                        : []),
                      {
                        key: "revision",
                        label: t("control.changeExpectedRevision"),
                        children: change.intent.expectedRevision,
                      },
                      ...(change.ticket
                        ? [
                            {
                              key: "ticket",
                              label: t("control.jobId"),
                              children: (
                                <Typography.Text className="managed-identifier">
                                  {change.ticket.job_id}
                                </Typography.Text>
                              ),
                            },
                          ]
                        : []),
                    ]}
                  />
                ),
              },
            ]}
          />
          <Typography.Text type="secondary">
            {t("resources.changeMemoryHint")}
          </Typography.Text>
        </Space>
      }
    />
  );
}
