import { Alert, Button, Descriptions, Space, Typography } from "antd";
import type { NodeChange } from "../../auth/node-changes";
import { errorMessage } from "../../api/messages";
import { useMessages } from "../../hooks/useMessages";

/** A current read supports a new decision, never attribution of a lost reply. */
export default function ChangeReview({
  change,
  epoch,
  reading,
  blocked,
  readFailed,
  read,
  proceed,
}: {
  change: NodeChange;
  epoch: number;
  reading: boolean;
  blocked: boolean;
  readFailed: boolean;
  read: () => void;
  proceed: () => void;
}) {
  const { t } = useMessages();
  if (
    change.intent.kind === "maintenance" ||
    change.intent.kind === "runtime-drain" ||
    change.intent.kind === "proxy-service"
  )
    return null;
  const pending = change.phase === "pending";
  const observed =
    change.observation?.generation === epoch ? change.observation : null;
  const intent = change.intent;
  const action =
    intent.action === "configure"
      ? "control.editTarget"
      : intent.action === "register"
        ? "control.addTarget"
        : (`control.${intent.action}` as const);
  return (
    <Alert
      showIcon
      type={
        pending ? "info" : change.phase === "rejected" ? "error" : "warning"
      }
      title={t(
        pending
          ? "control.changePending"
          : change.phase === "rejected"
            ? "users.operationRejected"
            : "users.operationUnknown",
      )}
      description={
        <Space orientation="vertical" className="full-width">
          <Typography.Text>
            {t(
              pending
                ? "control.changePendingHint"
                : change.phase === "rejected"
                  ? "control.changeRejectedHint"
                  : "users.mutationUncertain",
            )}
          </Typography.Text>
          {change.error && (
            <Typography.Text>{t(errorMessage(change.error))}</Typography.Text>
          )}
          <Descriptions
            column={{ xs: 1, sm: 2 }}
            items={[
              {
                key: "node",
                label: t("control.changeNode"),
                children: (
                  <Typography.Text className="managed-identifier">
                    {change.scope.nodeId}
                  </Typography.Text>
                ),
              },
              {
                key: "action",
                label: t("control.changeAction"),
                children: t(action),
              },
              {
                key: "subject",
                label: t("control.nodeId"),
                children: (
                  <Typography.Text className="managed-identifier">
                    {intent.kind === "target"
                      ? intent.targetId
                      : (intent.controllerId ?? t("control.localScope"))}
                  </Typography.Text>
                ),
              },
              {
                key: "expected",
                label: t(
                  intent.kind === "target"
                    ? "control.changeExpectedRevision"
                    : "control.changeExpectedEpoch",
                ),
                children:
                  intent.kind === "target"
                    ? (intent.expectedRevision ?? t("control.changeNewTarget"))
                    : intent.expectedEpoch,
              },
            ]}
          />
          {observed && (
            <>
              <Typography.Text>
                {t("control.changeObservationHint")}
              </Typography.Text>
              <Descriptions
                column={{ xs: 1, sm: 2 }}
                items={[
                  {
                    key: "owner",
                    label: t("control.controller"),
                    children: (
                      <Typography.Text className="managed-identifier">
                        {observed.owner.controller_node_id ??
                          t("control.localScope")}
                      </Typography.Text>
                    ),
                  },
                  {
                    key: "epoch",
                    label: t("control.epoch"),
                    children: observed.owner.epoch,
                  },
                  ...(intent.kind === "target" && observed.target
                    ? [
                        {
                          key: "origin",
                          label: t("control.origin"),
                          children: (
                            <Typography.Text className="managed-identifier">
                              {observed.target.origin}
                            </Typography.Text>
                          ),
                        },
                        {
                          key: "revision",
                          label: t("control.configRevision"),
                          children: observed.target.revision,
                        },
                        {
                          key: "state",
                          label: t("control.deliveryEnabled"),
                          children: t(
                            observed.target.retired
                              ? "control.retired"
                              : observed.target.active
                                ? "control.configured"
                                : "control.paused",
                          ),
                        },
                      ]
                    : []),
                ]}
              />
              {intent.kind === "target" && !observed.target && (
                <Typography.Text>{t("control.changeMissing")}</Typography.Text>
              )}
            </>
          )}
          {!pending && (
            <>
              <Typography.Text type="secondary">
                {t("control.changeReviewHint")}
              </Typography.Text>
              <Space wrap>
                <Button
                  disabled={blocked || reading}
                  loading={reading}
                  onClick={read}
                >
                  {t("control.readChangeState")}
                </Button>
                <Button
                  disabled={blocked || reading || readFailed || !observed}
                  onClick={proceed}
                >
                  {t("control.continueChange")}
                </Button>
              </Space>
            </>
          )}
          <Typography.Text type="secondary">
            {t("control.changeMemoryHint")}
          </Typography.Text>
        </Space>
      }
    />
  );
}
