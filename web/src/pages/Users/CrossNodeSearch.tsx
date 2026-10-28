import {
  Alert,
  Button,
  Checkbox,
  Collapse,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Tag,
  Typography,
} from "antd";
import { useEffect, useRef, useState } from "react";
import Table from "../../components/DataTable";
import {
  ApiError,
  apiError,
  type ManagementClient,
  type SessionView,
} from "../../api/client";
import { errorMessage } from "../../api/messages";
import {
  userSearchQuery,
  type Page,
  type ProxyUser,
  type UserSearchInput,
  type UserSearchOptions,
} from "../../api/proxy";
import type { Target, TargetPage } from "../../api/targets";
import { useManagement } from "../../auth/context";
import { useMessages, type MessageKey } from "../../hooks/useMessages";

export type UserLocation = {
  targetId: string | null;
  userId: string;
  includeDeleted: boolean;
};

// This matches the existing managed-target capacity; local is a separate scope.
const MAX_TARGETS = 128;
const LOCAL = "local";
type Scope = { targetId: string | null; name: string };
type Group = {
  scope: Scope;
  status:
    "unread" | "reading" | "ready" | "cancelled" | "failed" | "unsupported";
  cursors: (string | undefined)[];
  page: Page<ProxyUser> | null;
  error: ApiError | null;
};
type Read = {
  abort: AbortController;
  serial: number;
  generation: number;
  session: SessionView;
};
const keyOf = (scope: Scope) => scope.targetId ?? LOCAL;
const statusKeys = {
  unread: "users.crossUnread",
  reading: "users.crossReading",
  ready: "users.crossReady",
  cancelled: "users.crossCancelled",
  failed: "users.crossFailed",
  unsupported: "users.searchUnsupported",
} as const satisfies Record<Group["status"], MessageKey>;

/** Explicit, read-only searches. Each group owns its cursor and observation;
 * locating a result passes only IDs so the destination must read it afresh. */
export default function CrossNodeSearch({
  onClose,
  onLocate,
}: {
  onClose: () => void;
  onLocate: (location: UserLocation) => void;
}) {
  const { t } = useMessages();
  const { controller, state } = useManagement();
  const [form] = Form.useForm<UserSearchInput>();
  const generation = useRef(controller.generation());
  const session = useRef(state.session);
  const mounted = useRef(true);
  const active = useRef<Read | null>(null);
  const serial = useRef(0);
  const submittedSerial = useRef<number | null>(null);
  const known = useRef(new Map<string, Target>());
  const applied = useRef<UserSearchOptions | null>(null);
  const groupsRef = useRef<Group[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [working, setWorking] = useState(false);
  const [directory, setDirectory] = useState<TargetPage | null>(null);
  const [directoryCursors, setDirectoryCursors] = useState<
    (string | undefined)[]
  >([undefined]);
  const [directoryError, setDirectoryError] = useState<ApiError | null>(null);
  const [loaded, setLoaded] = useState<Target[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const selectedRef = useRef<string[]>([]);
  const [includeDeleted, setIncludeDeleted] = useState(false);
  const [searchError, setSearchError] = useState<ApiError | null>(null);
  const available =
    state.phase === "authenticated" &&
    !state.busy &&
    state.session === session.current &&
    controller.generation() === generation.current;

  const usable = () => {
    const current = controller.snapshot();
    return (
      mounted.current &&
      current.phase === "authenticated" &&
      !current.busy &&
      current.session === session.current &&
      controller.generation() === generation.current
    );
  };
  const current = (read: Read) =>
    usable() &&
    active.current === read &&
    !read.abort.signal.aborted &&
    read.serial === serial.current &&
    read.generation === controller.generation();
  const publish = (change: (previous: Group[]) => Group[]) => {
    const next = change(groupsRef.current);
    groupsRef.current = next;
    setGroups(next);
  };
  const begin = (): Read | null => {
    if (!usable() || !session.current || active.current) return null;
    const read = {
      abort: new AbortController(),
      serial: ++serial.current,
      generation: controller.generation(),
      session: session.current,
    };
    active.current = read;
    setWorking(true);
    return read;
  };
  const finish = (read: Read) => {
    if (active.current === read) {
      active.current = null;
      if (mounted.current) setWorking(false);
    }
  };
  const one = async <T,>(
    read: Read,
    work: (client: ManagementClient, signal: AbortSignal) => Promise<T>,
  ) => {
    if (!current(read)) throw new DOMException("Aborted", "AbortError");
    // Each GET passes through the session fence independently, including its
    // authentication-loss handling, before any partial result is published.
    return controller.resource(
      read.session,
      (client, _csrf, signal) => work(client, signal),
      read.abort.signal,
    );
  };
  const invalidate = () => {
    ++serial.current;
    active.current?.abort.abort();
    applied.current = null;
    publish(() => []);
    setSearchError(null);
  };
  const cancel = () => {
    ++serial.current;
    active.current?.abort.abort();
    publish((previous) =>
      previous.map((group) =>
        group.status === "reading" || group.status === "unread"
          ? { ...group, status: "cancelled", page: null, error: null }
          : group,
      ),
    );
  };
  const close = () => {
    invalidate();
    onClose();
  };

  const readDirectory = async (
    cursors: (string | undefined)[],
  ): Promise<void> => {
    const read = begin();
    if (!read) return;
    setDirectory(null);
    setDirectoryCursors(cursors);
    setDirectoryError(null);
    try {
      const page = await one(read, (client, signal) =>
        client.targets({ after: cursors.at(-1), limit: 25 }, signal),
      );
      if (!current(read)) return;
      const after = cursors.at(-1);
      // The decoder bounds each page; a directory continuation must also move
      // past its requested ID instead of allowing an explicit Next cycle.
      if (
        (after !== undefined &&
          page.items.some((target) => target.node_id <= after)) ||
        (page.next_cursor !== null && cursors.includes(page.next_cursor))
      )
        throw new ApiError("format");
      const next = new Map(known.current);
      for (const target of page.items) next.set(target.node_id, target);
      if (next.size > MAX_TARGETS) throw new ApiError("format");
      known.current = next;
      setLoaded([...next.values()]);
      setDirectory(page);
    } catch (failure) {
      if (current(read)) setDirectoryError(apiError(failure));
    } finally {
      finish(read);
    }
  };

  const readGroup = async (
    read: Read,
    group: Group,
    options: UserSearchOptions,
    cursors: (string | undefined)[],
    expectedRevision?: string,
  ): Promise<boolean> => {
    if (!current(read)) return false;
    const key = keyOf(group.scope);
    publish((previous) =>
      previous.map((entry) =>
        keyOf(entry.scope) === key
          ? { ...entry, status: "reading", page: null, error: null }
          : entry,
      ),
    );
    try {
      const query = { ...options, after: cursors.at(-1) };
      const page = await one(read, (client, signal) =>
        group.scope.targetId === null
          ? client.userSearch(query, signal)
          : client.targetUserSearch(group.scope.targetId, query, signal),
      );
      if (!current(read)) return false;
      // Returning to page one is still part of this observation. Only an
      // explicit restart may adopt a new revision for this particular node.
      if (expectedRevision !== undefined && page.revision !== expectedRevision)
        throw new ApiError("server", "user_search_changed", 409);
      if (page.next_cursor !== null && cursors.includes(page.next_cursor))
        throw new ApiError("format");
      publish((previous) =>
        previous.map((entry) =>
          keyOf(entry.scope) === key
            ? { ...entry, status: "ready", page, cursors, error: null }
            : entry,
        ),
      );
    } catch (failure) {
      // resource already invalidates the session for authentication_required.
      // Peer denial and busy remain failures of this group, never local fallback.
      if (!current(read)) return false;
      const error = apiError(failure);
      const unsupported =
        error.status === 502 && error.code === "user_search_unsupported";
      publish((previous) =>
        previous.map((entry) =>
          keyOf(entry.scope) === key
            ? {
                ...entry,
                status: unsupported ? "unsupported" : "failed",
                page: null,
                cursors: [undefined],
                error,
              }
            : entry,
        ),
      );
    }
    return current(read);
  };

  const search = async (fields: UserSearchInput): Promise<void> => {
    if (!usable() || active.current || selectedRef.current.length === 0) return;
    const options: UserSearchOptions = {
      mode: fields.mode,
      q: fields.q.trim(),
      limit: 25,
      include_deleted: includeDeleted,
    };
    let initial: Group[];
    try {
      userSearchQuery(options);
      initial = selectedRef.current.map((key): Group => {
        const target = known.current.get(key);
        if (key !== LOCAL && !target) throw new ApiError("format");
        return {
          scope: {
            targetId: target?.node_id ?? null,
            name: target?.name ?? t("control.localScope"),
          },
          status: "unread",
          cursors: [undefined],
          page: null,
          error: null,
        };
      });
    } catch (failure) {
      setSearchError(apiError(failure));
      return;
    }
    const read = begin();
    if (!read) return;
    applied.current = options;
    setSearchError(null);
    publish(() => initial);
    try {
      for (const group of initial) {
        if (!(await readGroup(read, group, options, [undefined]))) break;
      }
    } finally {
      finish(read);
    }
  };
  const groupPage = async (
    group: Group,
    direction: "restart" | "previous" | "next",
  ): Promise<void> => {
    const options = applied.current;
    if (!options || !groupsRef.current.includes(group)) return;
    const expectedRevision =
      direction === "restart" ? undefined : group.page?.revision;
    if (direction !== "restart" && expectedRevision === undefined) return;
    let cursors: (string | undefined)[];
    if (direction === "restart") cursors = [undefined];
    else if (direction === "previous" && group.cursors.length > 1)
      cursors = group.cursors.slice(0, -1);
    else if (direction === "next" && group.page?.next_cursor)
      cursors = [...group.cursors, group.page.next_cursor];
    else return;
    const read = begin();
    if (!read) return;
    try {
      await readGroup(read, group, options, cursors, expectedRevision);
    } finally {
      finish(read);
    }
  };
  const choose = (values: string[]) => {
    if (!usable()) return;
    invalidate();
    selectedRef.current = values;
    setSelected(values);
  };
  const toggle = (key: string) =>
    choose(
      selectedRef.current.includes(key)
        ? selectedRef.current.filter((value) => value !== key)
        : [...selectedRef.current, key],
    );
  const locate = (group: Group, user: ProxyUser) => {
    const latest = groupsRef.current.find(
      (entry) => keyOf(entry.scope) === keyOf(group.scope),
    );
    if (
      !usable() ||
      active.current ||
      !applied.current ||
      latest !== group ||
      latest.status !== "ready" ||
      !latest.page?.items.includes(user)
    )
      return;
    onLocate({
      targetId: group.scope.targetId,
      userId: user.id,
      includeDeleted: applied.current.include_deleted === true,
    });
  };

  useEffect(() => {
    mounted.current = true;
    void readDirectory([undefined]);
    return () => {
      mounted.current = false;
      ++serial.current;
      active.current?.abort.abort();
      active.current = null;
    };
  }, [controller]);
  useEffect(() => {
    if (!available) {
      invalidate();
      selectedRef.current = [];
      setSelected([]);
      setDirectory(null);
      setDirectoryError(null);
    }
  }, [available]);

  const completed = groups.filter((group) =>
    ["ready", "failed", "unsupported"].includes(group.status),
  ).length;
  const blocked = working || !available;
  return (
    <Modal
      open={available}
      title={t("users.crossNodeSearch")}
      footer={null}
      onCancel={close}
      mask={{ closable: false }}
      width={960}
      style={{ maxWidth: "calc(100% - 32px)" }}
      destroyOnHidden
    >
      <Space orientation="vertical" size={16} className="full-width">
        <Typography.Paragraph type="secondary">
          {t("users.crossHint")}
        </Typography.Paragraph>
        <section aria-label={t("users.crossDirectory")}>
          <Space orientation="vertical" className="full-width">
            <Typography.Text strong>
              {t("users.crossDirectory")}
            </Typography.Text>
            <Typography.Text type="secondary">
              {t("users.crossSelected", {
                count: selected.length,
                loaded: loaded.length,
              })}
            </Typography.Text>
            <Space wrap>
              <Button
                disabled={!available}
                onClick={() => choose([LOCAL, ...known.current.keys()])}
              >
                {t("users.crossSelectLoaded")}
              </Button>
              <Button
                disabled={!available || selected.length === 0}
                onClick={() => choose([])}
              >
                {t("users.crossClearSelection")}
              </Button>
            </Space>
            <div style={{ maxHeight: 240, overflowY: "auto" }}>
              <Space orientation="vertical" className="full-width">
                <Checkbox
                  checked={selected.includes(LOCAL)}
                  disabled={!available}
                  onChange={() => toggle(LOCAL)}
                >
                  {t("control.localScope")}
                </Checkbox>
                {directory?.items.map((target) => (
                  <Checkbox
                    key={target.node_id}
                    checked={selected.includes(target.node_id)}
                    disabled={!available}
                    onChange={() => toggle(target.node_id)}
                  >
                    <span className="managed-identifier">
                      {target.name} · {target.node_id}
                    </span>
                  </Checkbox>
                ))}
              </Space>
            </div>
            {directory && directory.items.length === 0 && (
              <Typography.Text>
                {t("users.crossDirectoryEmpty")}
              </Typography.Text>
            )}
            {directory?.controller_available === false && (
              <Alert
                type="warning"
                showIcon
                title={t("users.crossControllerUnavailable")}
              />
            )}
            {directoryError && (
              <Alert
                type="error"
                showIcon
                title={t(errorMessage(directoryError))}
              />
            )}
            <Space wrap>
              <Button
                disabled={blocked || directoryCursors.length <= 1}
                onClick={() =>
                  void readDirectory(directoryCursors.slice(0, -1))
                }
              >
                {t("users.crossDirectoryPrevious")}
              </Button>
              <Button
                disabled={blocked || !directory?.next_cursor}
                onClick={() => {
                  if (directory?.next_cursor)
                    void readDirectory([
                      ...directoryCursors,
                      directory.next_cursor,
                    ]);
                }}
              >
                {t("users.crossDirectoryNext")}
              </Button>
              <Button
                disabled={blocked}
                onClick={() => void readDirectory(directoryCursors)}
              >
                {t("users.crossDirectoryRefresh")}
              </Button>
              <Typography.Text>
                {t("users.page", { page: directoryCursors.length })}
              </Typography.Text>
            </Space>
          </Space>
        </section>
        <Form<UserSearchInput>
          name="cross-node-user-search"
          form={form}
          layout="vertical"
          initialValues={{ mode: "name", q: "" }}
          aria-label={t("users.crossSearchForm")}
          onSubmitCapture={(event) => {
            if (submittedSerial.current !== null) {
              event.preventDefault();
              event.stopPropagation();
              return;
            }
            // Form validates asynchronously. Selection and include-deleted
            // changes must invalidate this intent, not silently change its GET.
            submittedSerial.current = serial.current;
          }}
          onFinish={(fields) => {
            const submitted = submittedSerial.current;
            submittedSerial.current = null;
            if (submitted === serial.current) void search(fields);
          }}
          onFinishFailed={() => {
            submittedSerial.current = null;
          }}
          onValuesChange={invalidate}
        >
          <div style={{ display: "flex", flexWrap: "wrap", gap: 16 }}>
            <Form.Item name="mode" label={t("users.searchMode")}>
              <Select
                disabled={!available}
                style={{ width: 140 }}
                options={[
                  { value: "name", label: t("users.searchName") },
                  { value: "id", label: t("users.searchId") },
                ]}
              />
            </Form.Item>
            <Form.Item
              name="q"
              label={t("users.searchQuery")}
              dependencies={["mode"]}
              style={{ flex: "1 1 240px", minWidth: 0 }}
              rules={[
                {
                  validator: async (_, value: unknown) => {
                    try {
                      userSearchQuery({
                        mode: form.getFieldValue("mode"),
                        q: typeof value === "string" ? value.trim() : "",
                      });
                    } catch {
                      throw new Error(t("users.searchInvalid"));
                    }
                  },
                },
              ]}
            >
              <Input disabled={!available} autoComplete="off" />
            </Form.Item>
          </div>
          <Space orientation="vertical" className="full-width">
            <Checkbox
              disabled={!available}
              checked={includeDeleted}
              onChange={(event) => {
                invalidate();
                setIncludeDeleted(event.target.checked);
              }}
            >
              {t("users.includeDeleted")}
            </Checkbox>
            <Space wrap>
              <Button
                type="primary"
                htmlType="submit"
                disabled={blocked || selected.length === 0}
              >
                {t("users.searchSubmit")}
              </Button>
              <Button disabled={!working} onClick={cancel}>
                {t("users.crossCancel")}
              </Button>
              <Button onClick={close}>{t("users.crossClose")}</Button>
            </Space>
          </Space>
        </Form>
        {searchError && (
          <Alert type="error" showIcon title={t(errorMessage(searchError))} />
        )}
        {groups.length > 0 && (
          <>
            <Typography.Text role="status" aria-live="polite">
              {t("users.crossProgress", { completed, total: groups.length })}
            </Typography.Text>
            <Collapse
              items={groups.map((group) => ({
                key: keyOf(group.scope),
                label: (
                  <Space wrap>
                    <span className="managed-identifier">
                      {group.scope.name} ·{" "}
                      {group.scope.targetId ?? t("control.localScope")}
                    </span>
                    <Tag>{t(statusKeys[group.status])}</Tag>
                  </Space>
                ),
                children: (
                  <section
                    aria-label={`${group.scope.name} · ${group.scope.targetId ?? t("control.localScope")}`}
                  >
                    <Space orientation="vertical" className="full-width">
                      {group.error && (
                        <Alert
                          type="warning"
                          showIcon
                          title={t(
                            group.status === "unsupported"
                              ? "users.searchUnsupported"
                              : errorMessage(group.error),
                          )}
                          description={
                            group.error.status === 409 &&
                            group.error.code === "user_search_changed"
                              ? t("users.searchChangedHint")
                              : undefined
                          }
                        />
                      )}
                      <Typography.Text>
                        {t(statusKeys[group.status])}
                      </Typography.Text>
                      {group.page && (
                        <>
                          <Typography.Text>
                            {t("users.crossRevision", {
                              revision: group.page.revision,
                            })}
                          </Typography.Text>
                          <Table<ProxyUser>
                            size="small"
                            rowKey="id"
                            pagination={false}
                            dataSource={group.page.items}
                            scroll={{ x: 560 }}
                            locale={{ emptyText: t("users.crossEmpty") }}
                            columns={[
                              {
                                title: t("users.name"),
                                dataIndex: "name",
                                render: (name: string) => (
                                  <span className="managed-identifier">
                                    {name}
                                  </span>
                                ),
                              },
                              {
                                title: t("users.historyUser"),
                                dataIndex: "id",
                                render: (id: string) => (
                                  <span className="managed-identifier">
                                    {id}
                                  </span>
                                ),
                              },
                              {
                                title: t("users.state"),
                                render: (_: unknown, user: ProxyUser) =>
                                  t(
                                    user.deleted
                                      ? "users.deleted"
                                      : user.active
                                        ? "users.enabled"
                                        : "users.disabled",
                                  ),
                              },
                              {
                                title: t("users.actions"),
                                render: (_: unknown, user: ProxyUser) => (
                                  <Button
                                    size="small"
                                    disabled={blocked}
                                    onClick={() => locate(group, user)}
                                  >
                                    {t("users.crossLocate")}
                                  </Button>
                                ),
                              },
                            ]}
                          />
                          {group.page.next_cursor && (
                            <Typography.Text type="secondary">
                              {t("users.crossMore")}
                            </Typography.Text>
                          )}
                        </>
                      )}
                      <Space wrap>
                        <Button
                          disabled={blocked}
                          onClick={() => void groupPage(group, "restart")}
                        >
                          {t("users.crossReadAgain")}
                        </Button>
                        <Button
                          disabled={
                            blocked ||
                            group.status !== "ready" ||
                            group.cursors.length <= 1
                          }
                          onClick={() => void groupPage(group, "previous")}
                        >
                          {t("users.crossPrevious")}
                        </Button>
                        <Button
                          disabled={
                            blocked ||
                            group.status !== "ready" ||
                            !group.page?.next_cursor
                          }
                          onClick={() => void groupPage(group, "next")}
                        >
                          {t("users.crossNext")}
                        </Button>
                      </Space>
                    </Space>
                  </section>
                ),
              }))}
            />
          </>
        )}
      </Space>
    </Modal>
  );
}
