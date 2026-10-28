import { Button, Drawer, Empty, Space, Tag, Typography, Alert } from "antd";
import type { ColumnsType } from "antd/es/table";
import Table from "../../components/DataTable";
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
  type RefObject,
} from "react";
import { Link } from "@umijs/max";
import { trafficHref } from "../../api/traffic";
import { apiError, type ApiError } from "../../api/client";
import type { ProxyOperations, ProxyScope, ScopeChange } from "../../api/scope";
import type { Page, ProxyCredential, ProxyUser } from "../../api/proxy";
import { errorMessage } from "../../api/messages";
import { useManagement } from "../../auth/context";
import type { MessageKey } from "../../hooks/useMessages";
import { useMessages } from "../../hooks/useMessages";
import ConnectionModal from "../../components/Presets/ConnectionModal";
import type { UserChange } from "../../api/userOperations";

export type MutationWork = (
  client: ProxyOperations,
  csrf: string,
  signal: AbortSignal,
) => Promise<ScopeChange>;
export interface Confirmation {
  title: MessageKey;
  detail: MessageKey;
  subject: { kind: "user" | "credential"; id: string };
  revision: string;
  secretExpected?: boolean;
  user: ProxyUser;
  credential?: ProxyCredential;
  credentialSequence?: number;
  danger?: boolean;
  work: MutationWork;
  userChange?: UserChange;
}
/** Public metadata only; replacing an observation invalidates an open review. */
export interface CredentialObservation {
  userId: string;
  sequence: number;
  revision: string | null;
  loading: boolean;
}

export default function Credentials({
  user,
  refresh,
  createdRevision,
  busy,
  createBlocked,
  readBlocked,
  close,
  confirm,
  notice,
  scope,
  onReadBusy,
  onObservation,
  focusRegion,
}: {
  user: ProxyUser;
  refresh: number;
  createdRevision?: string;
  busy: boolean;
  createBlocked: boolean;
  readBlocked: boolean;
  close: () => void;
  confirm: (operation: Confirmation, trigger: HTMLElement) => void;
  notice: ReactNode;
  scope: ProxyScope;
  onReadBusy: (busy: boolean) => void;
  onObservation: (value: CredentialObservation | null) => void;
  focusRegion: RefObject<HTMLElement | null>;
}) {
  const { controller, state } = useManagement();
  const { t } = useMessages();
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [generator, setGenerator] = useState<ProxyCredential | null>(null);
  const generatorTrigger = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (!generator) generatorTrigger.current?.focus();
  }, [generator]);
  const [view, setView] = useState<{
    page: Page<ProxyCredential> | null;
    loading: boolean;
    error: ApiError | null;
  }>({ page: null, loading: true, error: null });
  const pending = useRef<AbortController | null>(null);
  const serial = useRef(0);
  const epoch = controller.generation();
  const cursor = cursors.at(-1);
  const load = useCallback(() => {
    const session = state.session;
    if (!session || state.busy) return;
    pending.current?.abort();
    const request = new AbortController();
    pending.current = request;
    const id = ++serial.current;
    onObservation({
      userId: user.id,
      sequence: id,
      revision: null,
      loading: true,
    });
    setView((current) => ({ ...current, loading: true, error: null }));
    void controller
      .resource(
        session,
        (client, _csrf, signal) =>
          scope.kind === "local"
            ? client.credentials(
                { user_id: user.id, after: cursor, limit: 25 },
                signal,
              )
            : client.targetCredentials(
                scope.target.node_id,
                { user_id: user.id, after: cursor, limit: 25 },
                signal,
              ),
        request.signal,
      )
      .then((page) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          controller.generation() === epoch
        ) {
          setView({ page, loading: false, error: null });
          onObservation({
            userId: user.id,
            sequence: id,
            revision: page.revision,
            loading: false,
          });
        }
      })
      .catch((error) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          controller.generation() === epoch
        ) {
          setView({ page: null, loading: false, error: apiError(error) });
          onObservation({
            userId: user.id,
            sequence: id,
            revision: null,
            loading: false,
          });
        }
      });
  }, [
    controller,
    state.session,
    state.busy,
    user.id,
    cursor,
    epoch,
    scope.kind,
    scope.kind === "target" ? scope.target.node_id : null,
    onObservation,
  ]);
  useEffect(() => {
    load();
    return () => {
      serial.current++;
      pending.current?.abort();
      onObservation(null);
    };
  }, [load, refresh, onObservation]);
  const revision = view.page?.revision;
  const observationBlocked =
    view.loading ||
    !revision ||
    !!view.error ||
    (scope.kind === "target" && revision !== scope.policy.saved_revision);
  const disabled = busy || observationBlocked;
  const actions = (
    <Space wrap>
      <Button
        type="primary"
        disabled={createBlocked || observationBlocked || user.deleted}
        onClick={(event) =>
          confirm(
            {
              title: "users.createCredential",
              detail: "users.createCredentialHint",
              subject: { kind: "user", id: user.id },
              revision: revision!,
              secretExpected: true,
              user,
              credentialSequence: serial.current,
              work: (client, csrf, signal) =>
                client.createCredential(user.id, revision!, csrf, signal),
            },
            event.currentTarget,
          )
        }
      >
        {t(
          createdRevision
            ? "users.createCredentialAndConnect"
            : "users.createCredential",
        )}
      </Button>
      <Button onClick={load} disabled={readBlocked} loading={view.loading}>
        {t("users.refresh")}
      </Button>
    </Space>
  );
  const columns: ColumnsType<ProxyCredential> = [
    {
      title: t("users.login"),
      dataIndex: "login",
      render: (login: string) => (
        <Typography.Text code className="managed-identifier">
          {login}
        </Typography.Text>
      ),
    },
    {
      title: t("users.state"),
      render: (_, row) => (
        <Tag color={row.revoked ? "red" : row.active ? "green" : "default"}>
          {t(
            row.revoked
              ? "users.revoked"
              : row.active
                ? "users.enabled"
                : "users.disabled",
          )}
        </Tag>
      ),
    },
    { title: t("users.verifierRevision"), dataIndex: "verifier_revision" },
    {
      title: t("users.actions"),
      render: (_, row) => (
        <Space wrap>
          <Link
            to={trafficHref(
              { kind: "credential", id: row.id },
              scope.kind === "target" ? scope.target.node_id : null,
            )}
          >
            {t("traffic.open")}
          </Link>
          <Button
            size="small"
            disabled={
              readBlocked ||
              view.loading ||
              row.revoked ||
              !row.active ||
              user.deleted ||
              !user.active
            }
            type="primary"
            onClick={(event) => {
              generatorTrigger.current = event.currentTarget;
              setGenerator(row);
            }}
          >
            {t("presets.generator")}
          </Button>
          <Button
            size="small"
            disabled={disabled || row.revoked}
            onClick={(event) =>
              confirm(
                {
                  title: row.active ? "users.disable" : "users.enable",
                  detail: "users.disableHint",
                  subject: { kind: "credential", id: row.id },
                  revision: revision!,
                  user,
                  credential: row,
                  credentialSequence: serial.current,
                  work: (client, csrf, signal) =>
                    client.credentialState(
                      row.id,
                      !row.active,
                      revision!,
                      csrf,
                      signal,
                    ),
                },
                event.currentTarget,
              )
            }
          >
            {t(row.active ? "users.disable" : "users.enable")}
          </Button>
          <Button
            size="small"
            disabled={disabled || row.revoked}
            onClick={(event) =>
              confirm(
                {
                  title: "users.rotate",
                  detail: "users.rotateHint",
                  subject: { kind: "credential", id: row.id },
                  revision: revision!,
                  secretExpected: true,
                  user,
                  credential: row,
                  credentialSequence: serial.current,
                  danger: true,
                  work: (client, csrf, signal) =>
                    client.rotateCredential(row.id, revision!, csrf, signal),
                },
                event.currentTarget,
              )
            }
          >
            {t("users.rotate")}
          </Button>
          <Button
            size="small"
            danger
            disabled={disabled || row.revoked}
            onClick={(event) =>
              confirm(
                {
                  title: "users.revoke",
                  detail: "users.revokeHint",
                  subject: { kind: "credential", id: row.id },
                  revision: revision!,
                  user,
                  credential: row,
                  credentialSequence: serial.current,
                  danger: true,
                  work: (client, csrf, signal) =>
                    client.revokeCredential(row.id, revision!, csrf, signal),
                },
                event.currentTarget,
              )
            }
          >
            {t("users.revoke")}
          </Button>
        </Space>
      ),
    },
  ];
  return (
    <Drawer
      open
      size={1040}
      classNames={{
        body: "credential-workspace-body",
        wrapper: "credential-workspace-wrapper",
      }}
      title={t("users.credentialsFor", { name: user.name })}
      onClose={close}
      destroyOnHidden
    >
      <section
        ref={focusRegion}
        tabIndex={-1}
        aria-label={
          generator ? undefined : t("users.credentialsFor", { name: user.name })
        }
      >
        <div hidden={generator !== null}>
          <Space orientation="vertical" size={16} className="full-width">
            {createdRevision && (
              <Alert
                type="success"
                showIcon
                title={t("users.deliveryCreated", {
                  name: user.name,
                  revision: createdRevision,
                })}
                description={t("users.deliveryNext")}
              />
            )}
            {view.error && (
              <Alert
                type="error"
                showIcon
                title={t(errorMessage(view.error))}
                action={<Button onClick={load}>{t("users.readAgain")}</Button>}
              />
            )}
            {createdRevision && actions}
            {notice}
            {!createdRevision && actions}
            <Table<ProxyCredential>
              rowKey="id"
              columns={columns}
              dataSource={view.page?.items ?? []}
              loading={view.loading}
              pagination={false}
              scroll={{ x: 800 }}
              locale={{
                emptyText: <Empty description={t("users.noCredentials")} />,
              }}
            />
            <Space wrap>
              <Button
                disabled={view.loading || readBlocked || cursors.length <= 1}
                onClick={() => setCursors((value) => value.slice(0, -1))}
              >
                {t("users.previous")}
              </Button>
              <Typography.Text>
                {t("users.page", { page: cursors.length })}
              </Typography.Text>
              <Button
                disabled={
                  view.loading || readBlocked || !view.page?.next_cursor
                }
                onClick={() =>
                  setCursors((value) => [...value, view.page!.next_cursor!])
                }
              >
                {t("users.next")}
              </Button>
            </Space>
          </Space>
        </div>
      </section>
      {generator && !state.busy && (
        <ConnectionModal
          inline
          key={`${generator.id}:${epoch}`}
          user={user}
          credential={
            view.page?.items.find((row) => row.id === generator.id) ?? generator
          }
          peer={scope.kind === "target" ? scope.target.node_id : null}
          close={() => setGenerator(null)}
          onBusy={onReadBusy}
          readBlocked={view.loading}
        />
      )}
    </Drawer>
  );
}
