import { Link } from "@umijs/max";
import {
  Alert,
  Button,
  Card,
  Collapse,
  Descriptions,
  Form,
  Grid,
  Modal,
  Radio,
  Select,
  Space,
  Steps,
  Typography,
} from "antd";
import { useEffect, useRef, useState } from "react";
import { apiError, type ApiError, type NodeView } from "../../api/client";
import { errorMessage } from "../../api/messages";
import type { RemotePolicy, Target } from "../../api/targets";
import { usersHref } from "../../api/targets";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";
import { TargetFields, type TargetInput } from "./TargetForm";
import { SetupIssue, setupCommands, verifySetup } from "./setup";

/** Instructions are not enrollment evidence. Only an explicit, owner-scoped
 * read can produce a verification result, scoped to this session and registry. */
export default function NodeSetupGuide({
  node,
  target,
  controllerAvailable,
  register,
  close,
  registered,
}: {
  node: NodeView;
  target: Target | null;
  controllerAvailable: boolean;
  register: (
    value: TargetInput,
    signal: AbortSignal,
  ) => Promise<Target | undefined>;
  close: () => void;
  registered: () => void;
}) {
  const { controller, state } = useManagement();
  const { t } = useMessages();
  const screens = Grid.useBreakpoint();
  const generation = controller.generation();
  const [form] = Form.useForm();
  const [step, setStep] = useState(target ? 4 : 0);
  const [saved, setSaved] = useState(target);
  const [busy, setBusy] = useState<"save" | "verify" | null>(null);
  const [uncertain, setUncertain] = useState(false);
  const [preparation, setPreparation] = useState<"new" | "existing">(
    target ? "existing" : "new",
  );
  const [error, setError] = useState<ApiError | SetupIssue | null>(null);
  const [verified, setVerified] = useState<{
    policy: RemotePolicy;
    generation: number;
    controllerId: string;
    nodeId: string;
    revision: string;
    origin: string;
  } | null>(null);
  const pending = useRef<AbortController | null>(null);
  const serial = useRef(0);
  const mounted = useRef(false);
  const heading = useRef<HTMLDivElement | null>(null);
  const commands = setupCommands(node.node_id, saved?.node_id);
  // An instruction choice never clears a saved or unconfirmed registration.
  // In either state, hide commands that would create another node identity.
  const existingPreparation =
    !!saved || uncertain || preparation === "existing";
  const titles = [
    t("setup.prepare"),
    t("setup.enroll"),
    t("setup.grant"),
    t("setup.save"),
    t("setup.verify"),
  ];
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      serial.current++;
      pending.current?.abort();
    };
  }, [generation, state.session]);
  useEffect(() => heading.current?.focus(), [step]);
  const current = (request: AbortController, operation: number) =>
    mounted.current &&
    !request.signal.aborted &&
    operation === serial.current &&
    generation === controller.generation();
  const cancel = () => {
    serial.current++;
    pending.current?.abort();
    pending.current = null;
    setBusy(null);
    setVerified(null);
  };
  const dismiss = () => {
    if (busy === "save") return;
    cancel();
    close();
  };
  const selectStep = (next: number) => {
    if (busy === "save" || (next === 4 && !saved)) return;
    cancel();
    setError(null);
    setStep(next);
  };
  const save = async (value: TargetInput) => {
    const session = state.session;
    if (!session || state.busy || pending.current || saved || uncertain) return;
    if (value.node_id === node.node_id) {
      setError(new SetupIssue("setup.changed"));
      return;
    }
    const request = new AbortController();
    const operation = ++serial.current;
    pending.current = request;
    setBusy("save");
    setError(null);
    setVerified(null);
    try {
      // The page owns registration admission and its uncertain result. Closing
      // this guide must not discard that note or admit a second registration.
      const result = await register(
        { ...value, server_ip: value.server_ip || null },
        request.signal,
      );
      if (!current(request, operation)) return;
      if (!result) {
        setUncertain(true);
        return;
      }
      if (
        result.node_id !== value.node_id ||
        result.origin !== value.origin ||
        result.active !== value.active ||
        result.retired
      )
        throw new SetupIssue("setup.changed");
      setSaved(result);
      setStep(4);
      registered();
    } catch (failure) {
      if (current(request, operation)) {
        // Even a malformed/lost response may follow a committed registration.
        // This mounted guide cannot issue another POST; recover from the list.
        setUncertain(true);
        setError(failure instanceof SetupIssue ? failure : apiError(failure));
      }
    } finally {
      if (pending.current === request) {
        pending.current = null;
        if (mounted.current) setBusy(null);
      }
    }
  };
  const verify = async () => {
    const session = state.session;
    if (
      !session ||
      state.busy ||
      pending.current ||
      !saved ||
      !controllerAvailable ||
      !saved.active ||
      saved.retired ||
      saved.rollback_detected
    )
      return;
    const request = new AbortController();
    const operation = ++serial.current;
    pending.current = request;
    setBusy("verify");
    setVerified(null);
    setError(null);
    try {
      const result = await controller.resource(
        session,
        (client, _csrf, signal) =>
          verifySetup(client, saved, node.node_id, signal),
        request.signal,
      );
      if (current(request, operation))
        setVerified({
          policy: result,
          generation,
          controllerId: node.node_id,
          nodeId: saved.node_id,
          revision: saved.revision,
          origin: saved.origin,
        });
    } catch (failure) {
      if (current(request, operation))
        setError(failure instanceof SetupIssue ? failure : apiError(failure));
    } finally {
      if (pending.current === request) {
        pending.current = null;
        if (mounted.current) setBusy(null);
      }
    }
  };
  const details = (text: string, title = t("setup.commands")) => (
    <Collapse
      items={[
        {
          key: "commands",
          label: title,
          children: (
            <>
              <Typography.Paragraph type="secondary">
                {t("setup.placeholderHint")}
              </Typography.Paragraph>
              <pre
                className="connection-example"
                role="region"
                aria-label={title}
                tabIndex={0}
              >
                <code>{text}</code>
              </pre>
            </>
          ),
        },
      ]}
    />
  );
  const verificationBlocked =
    !saved || !saved.active || saved.retired || saved.rollback_detected;
  const proof =
    verified &&
    !verificationBlocked &&
    controllerAvailable &&
    verified.generation === generation &&
    verified.controllerId === node.node_id &&
    verified.nodeId === saved?.node_id &&
    verified.revision === saved.revision &&
    verified.origin === saved.origin
      ? verified.policy
      : null;
  if (state.phase !== "authenticated" || state.busy || !state.session)
    return null;
  return (
    <Modal
      open
      title={t("setup.title")}
      width={880}
      style={{ top: 16 }}
      maskClosable={false}
      closable={busy !== "save"}
      keyboard={busy !== "save"}
      onCancel={dismiss}
      destroyOnHidden
      styles={{
        body: {
          maxHeight: "min(70vh, calc(100dvh - 220px))",
          overflowY: "auto",
        },
      }}
      footer={
        <Space wrap>
          <Button onClick={dismiss} disabled={busy === "save"}>
            {t("setup.close")}
          </Button>
          {step > 0 && (
            <Button
              disabled={busy === "save"}
              onClick={() => selectStep(step - 1)}
            >
              {t("setup.previous")}
            </Button>
          )}
          {step < 3 && (
            <Button type="primary" onClick={() => selectStep(step + 1)}>
              {t("setup.next")}
            </Button>
          )}
          {step === 3 && !saved && (
            <Button
              type="primary"
              loading={busy === "save"}
              disabled={uncertain || state.busy}
              onClick={() => form.submit()}
            >
              {t("setup.saveAction")}
            </Button>
          )}
          {step === 3 && saved && (
            <Button type="primary" onClick={() => selectStep(4)}>
              {t("setup.next")}
            </Button>
          )}
          {step === 4 && (
            <Button
              type="primary"
              loading={busy === "verify"}
              disabled={
                verificationBlocked || !controllerAvailable || state.busy
              }
              onClick={() => void verify()}
            >
              {t("setup.verifyAction")}
            </Button>
          )}
        </Space>
      }
    >
      <Space
        orientation="vertical"
        size={12}
        className="full-width node-setup-guide"
      >
        <Typography.Paragraph type="secondary">
          {t("setup.progressHint")}
        </Typography.Paragraph>
        {screens.sm ? (
          <Steps
            size="small"
            current={step}
            onChange={selectStep}
            items={titles.map((title, index) => ({
              title,
              status: index === step ? "process" : "wait",
              disabled: busy === "save" || (index === 4 && !saved),
            }))}
          />
        ) : (
          <Select
            aria-label={t("setup.stepNavigation")}
            className="full-width"
            value={step}
            disabled={busy === "save"}
            onChange={selectStep}
            options={titles.map((title, index) => ({
              value: index,
              label: t("setup.stepLabel", {
                current: index + 1,
                total: titles.length,
                title,
              }),
              disabled: index === 4 && !saved,
            }))}
          />
        )}
        <div
          ref={heading}
          tabIndex={-1}
          role="heading"
          aria-level={3}
          className="node-setup-heading"
        >
          {titles[step]}
        </div>
        {error && (
          <Alert
            type="error"
            showIcon
            title={t(
              error instanceof SetupIssue
                ? error.messageKey
                : errorMessage(error),
            )}
            description={t(
              uncertain ? "setup.saveUncertain" : "setup.failureHint",
            )}
          />
        )}
        {uncertain && (
          <Button
            onClick={() => {
              registered();
              dismiss();
            }}
          >
            {t("setup.recoverRegistry")}
          </Button>
        )}
        {step === 0 && (
          <>
            {!saved && !uncertain ? (
              <Radio.Group
                aria-label={t("setup.preparationMode")}
                value={preparation}
                onChange={(event) => setPreparation(event.target.value)}
              >
                <Space wrap>
                  <Radio value="new">{t("setup.newChild")}</Radio>
                  <Radio value="existing">{t("setup.existingChild")}</Radio>
                </Space>
              </Radio.Group>
            ) : (
              <Typography.Paragraph>
                {t("setup.existingLocked")}
              </Typography.Paragraph>
            )}
            <Typography.Paragraph type="secondary">
              {t("setup.pkiRequired")}
            </Typography.Paragraph>
            {existingPreparation ? (
              <>
                <Typography.Paragraph>
                  {t("setup.prepareHint")}
                </Typography.Paragraph>
                {details(commands.prepare)}
              </>
            ) : (
              <>
                {[
                  {
                    title: t("setup.offlinePrepare"),
                    hint: t("setup.offlinePrepareHint"),
                    command: commands.prepareChild,
                  },
                  {
                    title: t("setup.offlineSign"),
                    hint: t("setup.offlineSignHint"),
                    command: commands.signChild,
                  },
                  {
                    title: t("setup.offlinePlan"),
                    hint: t("setup.offlinePlanHint"),
                    command: commands.planChild,
                  },
                ].map((item, index) => (
                  <Card
                    key={item.title}
                    size="small"
                    title={item.title}
                    styles={{
                      title: { whiteSpace: "normal", overflowWrap: "anywhere" },
                    }}
                  >
                    {index === 0 && (
                      <Alert
                        type="warning"
                        showIcon
                        style={{ marginBottom: 12 }}
                        title={t("setup.offlineAuthority")}
                        description={t("setup.newOutputs")}
                      />
                    )}
                    <Typography.Paragraph>{item.hint}</Typography.Paragraph>
                    {details(item.command)}
                    {index === 2 && (
                      <>
                        <Typography.Paragraph>
                          {t("setup.startHint")}
                        </Typography.Paragraph>
                        {details(commands.startChild, t("setup.startPosix"))}
                        {details(
                          commands.startChildWindows,
                          t("setup.startWindows"),
                        )}
                      </>
                    )}
                  </Card>
                ))}
                <Typography.Paragraph>
                  {t("setup.offlinePathsHint")}
                </Typography.Paragraph>
                <Descriptions
                  column={1}
                  items={[
                    {
                      key: "state",
                      label: t("setup.childStatePath"),
                      value: "<CHILD_PREPARED_DIR>/state",
                    },
                    {
                      key: "certificate",
                      label: t("setup.childCertificatePath"),
                      value: "<CHILD_LAUNCH_DIR>/node.pem",
                    },
                    {
                      key: "key",
                      label: t("setup.childKeyPath"),
                      value: "<CHILD_PREPARED_DIR>/node.key",
                    },
                    {
                      key: "ca",
                      label: t("setup.childCaPath"),
                      value: "<CHILD_LAUNCH_DIR>/node-ca.pem",
                    },
                  ].map(({ key, label, value }) => ({
                    key,
                    label,
                    children: (
                      <Typography.Text code className="managed-identifier">
                        {value}
                      </Typography.Text>
                    ),
                  }))}
                />
                <Collapse
                  items={[
                    {
                      key: "proxy",
                      label: t("setup.optionalProxy"),
                      children: (
                        <>
                          <Typography.Paragraph>
                            {t("setup.optionalProxyHint")}
                          </Typography.Paragraph>
                          {details(commands.proxyChild)}
                        </>
                      ),
                    },
                    {
                      key: "service",
                      label: t("setup.optionalService"),
                      children: (
                        <>
                          <Typography.Paragraph>
                            {t("setup.optionalServiceHint")}
                          </Typography.Paragraph>
                          {details(commands.serviceChild)}
                        </>
                      ),
                    },
                  ]}
                />
              </>
            )}
            <Collapse
              items={[
                {
                  key: "addresses",
                  label: t("setup.addressDetails"),
                  children: (
                    <>
                      <Typography.Paragraph>
                        {t("setup.independent")}
                      </Typography.Paragraph>
                      <Descriptions
                        column={1}
                        items={[
                          {
                            key: "controller",
                            label: t("setup.controllerId"),
                            children: (
                              <Typography.Text
                                code
                                className="managed-identifier"
                              >
                                {node.node_id}
                              </Typography.Text>
                            ),
                          },
                          {
                            key: "admin",
                            label: t("setup.adminOrigin"),
                            children: t("setup.adminOriginHint"),
                          },
                          {
                            key: "node",
                            label: t("control.origin"),
                            children: t("setup.nodeOriginHint"),
                          },
                          {
                            key: "proxy",
                            label: "public_address",
                            children: t("setup.proxyAddressHint"),
                          },
                        ]}
                      />
                    </>
                  ),
                },
              ]}
            />
          </>
        )}
        {step === 1 && (
          <>
            <Alert
              type="warning"
              showIcon
              title={t("setup.enrollHint")}
              description={t("setup.privateKeysStayLocal")}
            />
            <Typography.Paragraph>
              {t("setup.registrationHint")}
            </Typography.Paragraph>
            {details(commands.registerMain + "\n\n" + commands.registerChild)}
            <Typography.Paragraph>{t("setup.probeHint")}</Typography.Paragraph>
            {details(commands.probeMain + "\n\n" + commands.probeChild)}
          </>
        )}
        {step === 2 && (
          <>
            <Alert
              type="warning"
              showIcon
              title={t("setup.offlineGrant")}
              description={t("setup.stopHint")}
            />
            <Descriptions
              column={1}
              items={[
                {
                  key: "controller",
                  label: t("setup.controllerId"),
                  children: (
                    <Typography.Text code className="managed-identifier">
                      {node.node_id}
                    </Typography.Text>
                  ),
                },
              ]}
            />
            <Typography.Paragraph>{t("setup.epochHint")}</Typography.Paragraph>
            {details(commands.grant)}
            <Typography.Paragraph>
              {t("setup.restartHint")}
            </Typography.Paragraph>
          </>
        )}
        {step === 3 && (
          <>
            <Alert
              type="info"
              showIcon
              title={t(saved ? "setup.saved" : "control.enrollmentRequired")}
              description={t("setup.savedHint")}
            />
            {saved && (
              <Descriptions
                column={1}
                items={[
                  {
                    key: "id",
                    label: t("control.nodeId"),
                    children: (
                      <Typography.Text className="managed-identifier">
                        {saved.node_id}
                      </Typography.Text>
                    ),
                  },
                  {
                    key: "origin",
                    label: t("control.origin"),
                    children: (
                      <Typography.Text className="managed-identifier">
                        {saved.origin}
                      </Typography.Text>
                    ),
                  },
                ]}
              />
            )}
          </>
        )}
        {!saved && (
          <div hidden={step !== 3}>
            <Form
              form={form}
              layout="vertical"
              preserve={false}
              disabled={!!busy || uncertain}
              initialValues={{
                node_id: "",
                origin: "",
                active: true,
                server_ip: "",
              }}
              onFinish={(value) =>
                void save({ ...value, server_ip: value.server_ip || null })
              }
            >
              <TargetFields target={null} />
            </Form>
          </div>
        )}
        {step === 4 && saved && (
          <>
            <Alert
              type={proof ? "success" : "info"}
              showIcon
              title={t(proof ? "setup.verified" : "setup.saved")}
              description={t(proof ? "setup.verifiedHint" : "setup.savedHint")}
            />
            <Descriptions
              column={1}
              items={[
                {
                  key: "id",
                  label: t("control.nodeId"),
                  children: (
                    <Typography.Text className="managed-identifier">
                      {saved.node_id}
                    </Typography.Text>
                  ),
                },
                {
                  key: "origin",
                  label: t("control.origin"),
                  children: (
                    <Typography.Text className="managed-identifier">
                      {saved.origin}
                    </Typography.Text>
                  ),
                },
                ...(proof
                  ? [
                      {
                        key: "owner",
                        label: t("setup.controllerId"),
                        children: (
                          <Typography.Text className="managed-identifier">
                            {proof.controller_node_id}
                          </Typography.Text>
                        ),
                      },
                      {
                        key: "epoch",
                        label: t("control.epoch"),
                        children: proof.controller_epoch,
                      },
                      {
                        key: "revision",
                        label: t("users.savedRevision"),
                        children: proof.saved_revision,
                      },
                      {
                        key: "proxy",
                        label: t("users.proxyState"),
                        children: t(
                          proof.proxy_running
                            ? "setup.runtimeObserved"
                            : "users.apiOnly",
                        ),
                      },
                    ]
                  : []),
              ]}
            />
            {!controllerAvailable && (
              <Alert
                type="warning"
                showIcon
                title={t("control.tlsUnavailable")}
              />
            )}
            {verificationBlocked && (
              <Alert type="warning" showIcon title={t("setup.inactive")} />
            )}
            {proof && (
              <Link to={usersHref(saved.node_id)}>
                {t("control.manageUsers")}
              </Link>
            )}
            <Collapse
              items={[
                {
                  key: "troubleshoot",
                  label: t("setup.troubleshoot"),
                  children: (
                    <Typography.Paragraph>
                      {t("setup.failureHint")}
                    </Typography.Paragraph>
                  ),
                },
              ]}
            />
          </>
        )}
      </Space>
    </Modal>
  );
}
