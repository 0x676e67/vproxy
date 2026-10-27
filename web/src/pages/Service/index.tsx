import { PageContainer, ProCard } from "@ant-design/pro-components";
import { Link } from "@umijs/max";
import {
  Alert,
  Button,
  Col,
  Collapse,
  Form,
  Input,
  InputNumber,
  Modal,
  Row,
  Select,
  Space,
  Tag,
  Typography,
} from "antd";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { ApiError, apiError, type ManagementClient } from "../../api/client";
import { errorMessage } from "../../api/messages";
import {
  publicEndpointAddress,
  publicEndpointInput,
  type ListenerProtocol,
} from "../../api/endpoints";
import {
  serviceConfiguration,
  type ServiceChange,
  type ServiceConfiguration,
  type ServiceReceipt,
} from "../../api/proxyService";
import { drainNonce } from "../../api/runtime";
import { useManagement } from "../../auth/context";
import type { Token } from "../../auth/node-changes";
import ManagementGate from "../../components/ManagementGate";
import { useMessages } from "../../hooks/useMessages";

interface ListenerFields {
  protocol: ListenerProtocol;
  ip: string;
  port: number;
  host: string;
  publicPort: number;
}
interface Fields {
  listeners: ListenerFields[];
  workers: number;
  concurrent: number;
  connect_timeout: number;
}
function fields(config: ServiceConfiguration): Fields {
  return {
    ...config,
    listeners: config.listeners.map((item) => {
      const bind = /^(?:\[(.+)\]|([^:]+)):([0-9]+)$/.exec(item.bind);
      if (!bind) throw new ApiError("format");
      const address =
        item.public_address === null
          ? null
          : publicEndpointAddress(item.public_address);
      return {
        protocol: item.protocol,
        ip: bind[1] ?? bind[2],
        port: Number(bind[3]),
        host: address?.host ?? "",
        publicPort: address?.port ?? Number(bind[3]),
      };
    }),
  };
}
function configuration(value: Fields, node: string): ServiceConfiguration {
  return serviceConfiguration(
    {
      ...value,
      listeners: value.listeners.map((item) => ({
        protocol: item.protocol,
        bind: `${item.ip.includes(":") ? `[${item.ip}]` : item.ip}:${item.port}`,
        public_address: item.host
          ? publicEndpointInput(item.host, String(item.publicPort))
          : null,
      })),
    },
    node,
  );
}
function defaultListener(): ListenerFields {
  return {
    protocol: "https",
    ip: "0.0.0.0",
    port: 18443,
    host: window.location.hostname.replace(/^\[|\]$/g, ""),
    publicPort: 18443,
  };
}

async function readService(
  client: ManagementClient,
  expectedNode: string | null,
  signal: AbortSignal,
) {
  const node = await client.node(signal);
  if (expectedNode !== null && node.node_id !== expectedNode)
    throw new ApiError("format");
  const [owner, status] = await Promise.all([
    client.owner(signal),
    client.proxyService(node.node_id, signal),
  ]);
  return { node, owner, status };
}

/** Only delays an exact receipt read. Cancelling must not leave a timer or
 * cause another service submission, including after navigating away. */
function waitForFollowUp(signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      reject(new DOMException("Aborted", "AbortError"));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    }, 1000);
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  });
}

/** Local Native service only. Unknown writes retain their exact non-secret
 * identity through the shared review journal and are never automatically replayed. */
export function LiveService() {
  const { controller, state } = useManagement();
  const { t } = useMessages();
  const session = state.session;
  const epoch = controller.generation();
  const changes = controller.nodeChanges;
  useSyncExternalStore(changes.subscribe, changes.snapshot);
  const [view, setView] = useState<Awaited<
    ReturnType<typeof readService>
  > | null>(null);
  const [base, setBase] = useState<string | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [invalid, setInvalid] = useState(false);
  const [busy, setBusy] = useState(false);
  const [following, setFollowing] = useState(false);
  const [reading, setReading] = useState(false);
  const [receipt, setReceipt] = useState<ServiceReceipt | null>(null);
  const [confirmation, setConfirmation] = useState<ServiceChange | null>(null);
  const [form] = Form.useForm<Fields>();
  const watchedListeners = Form.useWatch("listeners", form) as
    ListenerFields[] | undefined;
  const initialized = useRef(false);
  const alive = useRef(false);
  const read = useRef<AbortController | null>(null);
  const write = useRef<AbortController | null>(null);
  const current = () =>
    alive.current &&
    controller.generation() === epoch &&
    controller.snapshot().session === session;
  const scope =
    session && view
      ? { administratorId: session.administrator.id, nodeId: view.node.node_id }
      : null;
  const change = scope ? changes.find(scope) : null;
  const own = change?.intent.kind === "proxy-service" ? change : null;
  const editable =
    !!view &&
    view.status.mode === "web" &&
    view.owner.controller_node_id === null &&
    !state.busy;
  const blocked =
    !editable || reading || busy || !!error || !!change || !!changes.issue();

  async function refresh(reset: boolean, inspect = false) {
    if (!session || !current() || read.current || write.current) return;
    const request = new AbortController();
    read.current = request;
    setReading(true);
    setError(null);
    try {
      const next = await controller.resource(
        session,
        (client, _, signal) =>
          readService(client, view?.node.node_id ?? null, signal),
        request.signal,
      );
      if (!current() || request.signal.aborted) return;
      setView(next);
      if (reset || !initialized.current) {
        form.setFieldsValue(
          next.status.saved?.configuration
            ? fields(next.status.saved.configuration)
            : {
                listeners: [defaultListener()],
                workers: 1,
                concurrent: 1024,
                connect_timeout: 10,
              },
        );
        initialized.current = true;
        setBase(next.status.saved?.revision ?? null);
        setInvalid(false);
      }
      if (inspect && own?.intent.kind === "proxy-service") {
        const operation = own.intent.operation;
        setReceipt(null);
        try {
          const original = await controller.resource(
            session,
            (client, _, signal) =>
              client.proxyServiceOperation(operation, signal),
            request.signal,
          );
          if (current()) setReceipt(original);
        } finally {
          if (current())
            changes.observe(own.token, {
              generation: epoch,
              owner: next.owner,
              target: null,
            });
        }
      }
    } catch (cause) {
      if (current() && !request.signal.aborted) setError(apiError(cause));
    } finally {
      if (read.current === request) {
        read.current = null;
        if (current()) setReading(false);
      }
    }
  }
  useEffect(() => {
    alive.current = true;
    void refresh(false);
    return () => {
      alive.current = false;
      read.current?.abort();
      read.current = null;
      write.current?.abort();
    };
    // Each authenticated generation mounts its own form below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function propose(enabled: boolean, values?: Fields) {
    if (!current() || blocked || !view?.status.saved || !base) return;
    try {
      const config =
        enabled && values
          ? configuration(values, view.node.node_id)
          : view.status.saved.configuration;
      if (!config) return;
      setConfirmation({
        expected_node_id: view.node.node_id,
        expected_revision: enabled ? base : view.status.saved.revision,
        controller_epoch: view.owner.epoch,
        request_id: drainNonce(),
        enabled,
        configuration: config,
      });
      setInvalid(false);
    } catch {
      setInvalid(true);
    }
  }
  async function apply() {
    if (
      !session ||
      !scope ||
      !confirmation ||
      !current() ||
      blocked ||
      write.current
    )
      return;
    const input = confirmation;
    const request = new AbortController();
    write.current = request;
    setBusy(true);
    setError(null);
    setReceipt(null);
    setConfirmation(null);
    const { configuration: _, ...operation } = input;
    let dispatched = false;
    let token: Token | null = null;
    try {
      token = await changes.begin(
        scope,
        { kind: "proxy-service", operation },
        () => current() && !request.signal.aborted,
      );
      if (!token || !current() || request.signal.aborted) return;
      dispatched = true;
      const result = await controller.resource(
        session,
        (client, csrf, signal) => client.setProxyService(input, csrf, signal),
        request.signal,
      );
      if (!current()) {
        changes.fail(token, new ApiError("network"));
        return;
      }
      let observedReceipt = result.operation;
      setReceipt(observedReceipt);
      setView((previous) =>
        previous
          ? {
              ...previous,
              status: { ...previous.status, runtime: result.runtime },
            }
          : previous,
      );
      if (input.enabled || base === input.expected_revision)
        setBase(observedReceipt.revision);
      if (observedReceipt.state === "pending") {
        setFollowing(true);
        // Retain this submission's journal lease until an exact terminal
        // receipt or uncertainty. Never poll restored/lost-response intents.
        // Both the count and wall-clock budget bound automatic work.
        const deadline = setTimeout(() => request.abort(), 30_000);
        try {
          for (let attempt = 0; attempt < 15; attempt += 1) {
            await waitForFollowUp(request.signal);
            if (!current()) throw new ApiError("network");
            const observed = await controller.resource(
              session,
              async (client, _, signal) => {
                const [next, original] = await Promise.all([
                  readService(client, input.expected_node_id, signal),
                  client.proxyServiceOperation(operation, signal),
                ]);
                return { next, original };
              },
              request.signal,
            );
            if (!current() || request.signal.aborted)
              throw new ApiError("network");
            observedReceipt = observed.original;
            setView(observed.next);
            setReceipt(observedReceipt);
            if (observedReceipt.state !== "pending") break;
          }
        } finally {
          clearTimeout(deadline);
        }
      }
      if (observedReceipt.state === "pending") changes.serviceAccepted(token);
      else changes.succeed(token);
    } catch (cause) {
      if (token) changes.fail(token, apiError(cause));
      if (current() && !request.signal.aborted) setError(apiError(cause));
    } finally {
      if (token) {
        if (!dispatched) changes.notStarted(token);
        changes.release(token);
      }
      if (write.current === request) write.current = null;
      if (current()) {
        setBusy(false);
        setFollowing(false);
        void refresh(false);
      }
    }
  }
  const status = view?.status;
  const runtime = !reading && !error ? status?.runtime : undefined;
  return (
    <PageContainer title={t("service.title")}>
      <Space orientation="vertical" className="full-width" size={16}>
        <ProCard
          title={view?.node.name ?? t("node.local")}
          variant="outlined"
          extra={
            <Button
              loading={reading}
              disabled={busy || state.busy}
              onClick={() => void refresh(false)}
            >
              {t("service.refresh")}
            </Button>
          }
        >
          <Space orientation="vertical" className="full-width">
            {!runtime && <Tag>{t("service.state.unknown")}</Tag>}
            {runtime && (
              <Space wrap>
                <Tag
                  color={
                    runtime.state === "running"
                      ? "green"
                      : runtime.state === "failed"
                        ? "error"
                        : "default"
                  }
                >
                  {t(`service.state.${runtime.state}`)}
                </Tag>
                {runtime.configuration_revision && (
                  <Typography.Text type="secondary">
                    {t("service.liveRevision", {
                      revision: runtime.configuration_revision,
                    })}
                  </Typography.Text>
                )}
              </Space>
            )}
            {runtime?.error && (
              <Alert
                type="error"
                showIcon
                title={t(`service.error.${runtime.error}`)}
              />
            )}
            {runtime?.state === "running" &&
              runtime.listeners.map((item, index) => (
                <Typography.Text key={index} code>
                  {item.protocol.toUpperCase()} {item.bind}
                  {item.public_address ? ` → ${item.public_address}` : ""}
                </Typography.Text>
              ))}
            <Typography.Text type="secondary">
              {t("service.notTested")}
            </Typography.Text>
            {runtime?.state === "running" && (
              <Link to="/users">{t("service.users")}</Link>
            )}
          </Space>
        </ProCard>
        {error && (
          <Alert type="error" showIcon title={t(errorMessage(error))} />
        )}
        {status && status.mode !== "web" && (
          <Alert
            type="info"
            showIcon
            title={t(
              status.mode === "startup" ? "service.startup" : "service.upgrade",
            )}
          />
        )}
        {view?.owner.controller_node_id && (
          <Alert type="warning" showIcon title={t("service.delegated")} />
        )}
        {changes.issue() && (
          <Alert
            type="warning"
            showIcon
            title={t("control.changeStorageBlocked")}
          />
        )}
        {change && !own && (
          <Alert
            type="warning"
            showIcon
            title={t("service.otherChange")}
            action={<Link to="/nodes">{t("menu.nodes")}</Link>}
          />
        )}
        {own && (
          <Alert
            type="warning"
            showIcon
            title={t(following ? "service.following" : "service.unconfirmed")}
            description={
              <Space orientation="vertical">
                <Typography.Text>
                  {t(following ? "service.followingHint" : "service.noReplay")}
                </Typography.Text>
                {receipt && !following && (
                  <Typography.Text>
                    {t(`service.receipt.${receipt.state}`)}
                  </Typography.Text>
                )}
                <Space wrap>
                  <Button
                    disabled={busy || reading || own.phase === "pending"}
                    onClick={() => void refresh(false, true)}
                  >
                    {t("service.inspect")}
                  </Button>
                  <Button
                    disabled={
                      busy ||
                      reading ||
                      own.phase === "pending" ||
                      own.observation?.generation !== epoch ||
                      receipt?.state === "pending"
                    }
                    onClick={() =>
                      void changes.continue(own.token, epoch, current)
                    }
                  >
                    {t("service.acknowledge")}
                  </Button>
                </Space>
              </Space>
            }
          />
        )}
        {!own && receipt && (
          <Alert
            showIcon
            type={receipt.state === "applied" ? "success" : "warning"}
            title={t(`service.receipt.${receipt.state}`)}
          />
        )}
        <ProCard
          title={t("service.configuration")}
          variant="outlined"
          extra={
            <Button
              disabled={busy || reading || !!confirmation}
              onClick={() => void refresh(true)}
            >
              {t("service.reload")}
            </Button>
          }
        >
          <Form
            form={form}
            layout="vertical"
            disabled={blocked || !!confirmation}
            onFinish={(values) => propose(true, values)}
          >
            <Form.List name="listeners">
              {(items, { add, remove }) => (
                <Space orientation="vertical" className="full-width" size={16}>
                  {items.map(({ key, name, ...rest }) => (
                    <ProCard
                      key={key}
                      variant="outlined"
                      title={t("service.listener", { number: name + 1 })}
                      extra={
                        items.length > 1 && (
                          <Button
                            type="text"
                            disabled={blocked || !!confirmation}
                            onClick={() => remove(name)}
                          >
                            {t("service.remove")}
                          </Button>
                        )
                      }
                    >
                      <Row gutter={16}>
                        <Col xs={24} sm={8}>
                          <Form.Item
                            {...rest}
                            name={[name, "protocol"]}
                            label={t("service.protocol")}
                            rules={[{ required: true }]}
                          >
                            <Select
                              options={[
                                "https",
                                "socks5",
                                "http",
                                "masque",
                                "auto",
                              ].map((value) => ({
                                value,
                                label: value.toUpperCase(),
                              }))}
                            />
                          </Form.Item>
                        </Col>
                        <Col xs={24} sm={6}>
                          <Form.Item
                            {...rest}
                            name={[name, "port"]}
                            label={t("service.port")}
                            rules={[{ required: true }]}
                          >
                            <InputNumber
                              min={1}
                              max={65535}
                              precision={0}
                              className="full-width"
                              onChange={(port) => {
                                const previous = watchedListeners?.[name];
                                if (
                                  port !== null &&
                                  previous?.publicPort === previous?.port
                                )
                                  form.setFieldValue(
                                    ["listeners", name, "publicPort"],
                                    port,
                                  );
                              }}
                            />
                          </Form.Item>
                        </Col>
                        <Col xs={24} sm={10}>
                          <Form.Item
                            {...rest}
                            name={[name, "host"]}
                            label={t("service.host")}
                          >
                            <Input maxLength={253} autoComplete="off" />
                          </Form.Item>
                        </Col>
                      </Row>
                      <Collapse
                        size="small"
                        items={[
                          {
                            key: "bind",
                            label: t("service.advanced"),
                            forceRender: true,
                            children: (
                              <Row gutter={16}>
                                <Col xs={24} sm={12}>
                                  <Form.Item
                                    {...rest}
                                    name={[name, "ip"]}
                                    label={t("service.bind")}
                                    rules={[{ required: true }]}
                                  >
                                    <Input maxLength={64} autoComplete="off" />
                                  </Form.Item>
                                </Col>
                                <Col xs={24} sm={12}>
                                  <Form.Item
                                    {...rest}
                                    name={[name, "publicPort"]}
                                    label={t("service.publicPort")}
                                    rules={[{ required: true }]}
                                  >
                                    <InputNumber
                                      min={1}
                                      max={65535}
                                      precision={0}
                                      className="full-width"
                                    />
                                  </Form.Item>
                                </Col>
                              </Row>
                            ),
                          },
                        ]}
                      />
                    </ProCard>
                  ))}
                  <Button
                    disabled={blocked || !!confirmation || items.length >= 16}
                    onClick={() =>
                      add({
                        ...defaultListener(),
                        protocol: "socks5",
                        port: 1080,
                        publicPort: 1080,
                      })
                    }
                  >
                    {t("service.add")}
                  </Button>
                </Space>
              )}
            </Form.List>
            <Typography.Paragraph type="secondary">
              {t("service.defaultEgress")}
            </Typography.Paragraph>
            <Collapse
              items={[
                {
                  key: "limits",
                  label: t("service.limits"),
                  forceRender: true,
                  children: (
                    <Row gutter={16}>
                      <Col xs={24} sm={8}>
                        <Form.Item
                          name="workers"
                          label={t("service.workers")}
                          rules={[{ required: true }]}
                        >
                          <InputNumber
                            min={1}
                            max={256}
                            precision={0}
                            className="full-width"
                          />
                        </Form.Item>
                      </Col>
                      <Col xs={24} sm={8}>
                        <Form.Item
                          name="concurrent"
                          label={t("service.concurrent")}
                          rules={[{ required: true }]}
                        >
                          <InputNumber
                            min={1}
                            max={2147483647}
                            precision={0}
                            className="full-width"
                          />
                        </Form.Item>
                      </Col>
                      <Col xs={24} sm={8}>
                        <Form.Item
                          name="connect_timeout"
                          label={t("service.timeout")}
                          rules={[{ required: true }]}
                        >
                          <InputNumber
                            min={1}
                            max={300}
                            precision={0}
                            className="full-width"
                          />
                        </Form.Item>
                      </Col>
                    </Row>
                  ),
                },
              ]}
            />
            {invalid && (
              <Alert type="error" showIcon title={t("service.invalid")} />
            )}
            <Space wrap className="management-form-notice">
              <Button type="primary" htmlType="submit" loading={busy}>
                {t(
                  runtime?.state === "running"
                    ? "service.apply"
                    : "service.start",
                )}
              </Button>
              <Button
                danger
                disabled={
                  blocked ||
                  !status?.saved?.configuration ||
                  (runtime?.state === "stopped" && !status?.saved?.enabled)
                }
                onClick={() => propose(false)}
              >
                {t("service.stop")}
              </Button>
            </Space>
          </Form>
        </ProCard>
        <Modal
          open={confirmation !== null}
          title={t(
            confirmation?.enabled
              ? "service.confirmStart"
              : "service.confirmStop",
          )}
          onCancel={() => setConfirmation(null)}
          onOk={() => void apply()}
          okText={t(confirmation?.enabled ? "service.apply" : "service.stop")}
          okButtonProps={{ disabled: blocked }}
          cancelText={t("account.password.cancel")}
        >
          <Typography.Paragraph>
            {t(
              confirmation?.enabled
                ? "service.startWarning"
                : "service.stopWarning",
            )}
          </Typography.Paragraph>
          {confirmation?.configuration.listeners.map((item, index) => (
            <Typography.Paragraph key={index} code>
              {item.protocol.toUpperCase()} {item.bind}
            </Typography.Paragraph>
          ))}
        </Modal>
      </Space>
    </PageContainer>
  );
}
function AuthenticatedService() {
  const { controller } = useManagement();
  return <LiveService key={controller.generation()} />;
}
export default function ServicePage() {
  return (
    <ManagementGate>
      <AuthenticatedService />
    </ManagementGate>
  );
}
