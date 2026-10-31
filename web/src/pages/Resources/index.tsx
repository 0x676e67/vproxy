import {
  PageContainer,
  ProTable,
  type ProColumns,
} from "@ant-design/pro-components";
import {
  Alert,
  Button,
  Collapse,
  Descriptions,
  Drawer,
  Modal,
  Result,
  Space,
  Tabs,
  Tag,
  Typography,
} from "antd";
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import { Link, useLocation } from "@umijs/max";
import { apiError, ApiError, type ManagementClient } from "../../api/client";
import { errorMessage } from "../../api/messages";
import { trafficHref } from "../../api/traffic";
import type { PolicyStatus } from "../../api/proxy";
import {
  routingToken,
  type Pool,
  type Resource,
  type ResourceKind,
  type RoutingPage,
} from "../../api/routing";
import {
  nextCommand,
  resourcesHref,
  type Owner,
  type Target,
} from "../../api/targets";
import {
  readRoutingView,
  routingOperations,
  routingWritable,
  type RoutingContext,
  type RoutingScopeChange,
  type RoutingSubmission,
} from "../../api/remoteRouting";
import { useManagement } from "../../auth/context";
import {
  knownTicket,
  observedJob,
  type Intent,
  type Scope,
  type Token,
} from "../../auth/routing-changes";
import ManagementGate from "../../components/ManagementGate";
import { labelledColumns } from "../../components/DataTable";
import { useMessages, type MessageKey } from "../../hooks/useMessages";
import Members, { type RoutingWork } from "./Members";
import ResourceForm, { type ResourceFields } from "./ResourceForm";
import Health from "./Health";
import ScopePicker from "../../components/ScopePicker";
import CommandPanel from "../Users/CommandPanel";
import PresetEditor from "../../components/Presets/Editor";
import {
  setPresets,
  type PresetScopeChange,
  type PresetSubmission,
} from "../../api/remotePresets";
import ScopeError from "../../components/ScopeError";
import { resourceLocation, scopeHref } from "../../routing/scope";
import { useScopeNavigation } from "../../routing/ScopeNavigation";
import ChangeReview from "./ChangeReview";
import AddressLookup, { AddressFinder } from "./AddressLookup";

type MutationIntent = Pick<
  Intent,
  "action" | "kind" | "resourceId" | "memberId" | "expectedRevision"
>;
type ChangeResult = RoutingScopeChange | PresetScopeChange;
type ChangeWork<T extends ChangeResult> = (
  client: ManagementClient,
  csrf: string,
  signal: AbortSignal,
) => Promise<T>;

function Catalog({
  kind,
  onBusy,
  peer,
  onTarget,
}: {
  kind: ResourceKind;
  onBusy: (busy: boolean) => void;
  peer: string | null;
  onTarget: (target: Target | null) => void;
}) {
  const { controller, state } = useManagement();
  const { t } = useMessages();
  const epoch = controller.generation();
  const changes = controller.routingChanges;
  useSyncExternalStore(changes.subscribe, changes.snapshot);
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const cursor = cursors.at(-1);
  const [view, setView] = useState<{
    page: RoutingPage<Resource> | null;
    policy: PolicyStatus | null;
    owner: Owner | null;
    context: RoutingContext | null;
    nodeId: string | null;
    loading: boolean;
  }>({
    page: null,
    policy: null,
    owner: null,
    context: null,
    nodeId: null,
    loading: true,
  });
  const [submitted, setSubmitted] = useState<RoutingSubmission | null>(null);
  const [needsReview, setNeedsReview] = useState(false);
  const [commandBusy, setCommandBusy] = useState(false);
  const [presetBusy, setPresetBusy] = useState(false);
  const [presetPool, setPresetPool] = useState<{
    pool: Pool;
    id: number;
  } | null>(null);
  const [presetResult, setPresetResult] = useState<PresetSubmission | null>(
    null,
  );
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    onBusy(
      busy || commandBusy || presetBusy || (peer !== null && view.loading),
    );
  }, [busy, commandBusy, presetBusy, peer, view.loading, onBusy]);
  const [saved, setSaved] = useState<string | null>(null);
  const [form, setForm] = useState<{
    revision: string;
    epoch: number;
    id: number;
  } | null>(null);
  const [detail, setDetail] = useState<Resource | null>(null);
  const [members, setMembers] = useState<{ pool: Pool; id: number } | null>(
    null,
  );
  const [confirmation, setConfirmation] = useState<{
    title: MessageKey;
    hint: MessageKey;
    work: RoutingWork;
    epoch: number;
    id: number;
    intent: MutationIntent;
  } | null>(null);
  const read = useRef<AbortController | null>(null);
  const write = useRef<AbortController | null>(null);
  const serial = useRef(0);
  const editor = useRef(0);
  const mounted = useRef(false);
  const lastNode = useRef<string | null>(null);
  const commandLock = useRef(false);
  const presetLock = useRef(false);
  const contextRef = useRef(view.context);
  const verifiedNodeId = view.nodeId ?? lastNode.current;
  const scope: Scope | null =
    state.session && verifiedNodeId
      ? {
          administratorId: state.session.administrator.id,
          nodeId: verifiedNodeId,
          peer,
        }
      : null;
  const change = scope ? changes.find(scope) : null;
  const journalIssue = changes.issue();
  const scopeRef = useRef(scope);
  const invalidateReview = useCallback(() => {
    const currentScope = scopeRef.current;
    const record = currentScope ? changes.find(currentScope) : null;
    if (record) changes.invalidateObservation(record.token);
  }, [changes]);
  const updateContext = useCallback(
    (context: RoutingContext) => {
      invalidateReview();
      // Install read results before releasing a child request's synchronous
      // lock. A retained callback must never consult the previous job/owner.
      const installed = {
        ...context,
        localNodeId:
          context.localNodeId ?? contextRef.current?.localNodeId ?? null,
      };
      contextRef.current = installed;
      setNeedsReview(false);
      setView((current) => ({
        ...current,
        context: installed,
        policy: installed.policy,
        owner: installed.owner,
      }));
    },
    [invalidateReview],
  );
  function installJob(job: RoutingContext["job"]) {
    const context = contextRef.current;
    const installed = context ? { ...context, job } : null;
    contextRef.current = installed;
    setView((current) => ({ ...current, context: installed }));
  }
  function closeEditors() {
    editor.current++;
    setForm(null);
    setConfirmation(null);
    setDetail(null);
    setMembers(null);
    setPresetPool(null);
  }
  const load = useCallback(
    (preserveError = false, reviewToken?: Token) => {
      const session = state.session;
      if (
        !session ||
        state.busy ||
        write.current ||
        commandLock.current ||
        presetLock.current
      )
        return;
      const reviewingScope = scopeRef.current;
      if (
        reviewToken &&
        (!reviewingScope || changes.find(reviewingScope)?.token !== reviewToken)
      )
        return;
      invalidateReview();
      read.current?.abort();
      const request = new AbortController();
      read.current = request;
      const id = ++serial.current;
      setView((value) => ({ ...value, loading: true }));
      if (!preserveError) {
        setError(null);
      }
      void controller
        .resource(
          session,
          async (client, _csrf, signal) => {
            const { data: page, context } = await readRoutingView(
              client,
              peer,
              (read, signal) =>
                read.routingCatalog(kind, { after: cursor, limit: 25 }, signal),
              (page) => page.revision,
              signal,
            );
            // Remote chains already read this manager's identity. Local chains
            // need the same verified node boundary before retaining a write.
            const nodeId =
              context.localNodeId ?? (await client.node(signal)).node_id;
            if (reviewToken && nodeId !== reviewingScope?.nodeId)
              throw new ApiError("format");
            return {
              page,
              policy: context.policy,
              owner: context.owner,
              context: { ...context, localNodeId: nodeId },
              nodeId,
              loading: false,
            };
          },
          request.signal,
        )
        .then((value) => {
          if (
            !request.signal.aborted &&
            id === serial.current &&
            epoch === controller.generation()
          ) {
            const actualScope = {
              administratorId: session.administrator.id,
              nodeId: value.nodeId,
              peer,
            };
            contextRef.current = value.context;
            scopeRef.current = actualScope;
            // Render-time command guards also read this lock. Release it
            // before publishing the completed view, not in a later finally
            // that would leave disabled controls with no render to update them.
            if (read.current === request) read.current = null;
            const record = changes.find(actualScope);
            if (reviewToken) {
              if (record?.token !== reviewToken) return;
              const context = value.context;
              const remote =
                context.scope.kind === "target" ? context.scope.policy : null;
              const controllerEpoch =
                remote?.controller_epoch ?? context.owner?.epoch;
              const lastTerminalCommand =
                remote?.last_terminal_command ??
                context.owner?.last_terminal_command;
              if (
                controllerEpoch === undefined ||
                lastTerminalCommand === undefined
              )
                throw new ApiError("format");
              changes.observe(reviewToken, {
                generation: epoch,
                policyRevision: context.policy.saved_revision,
                controllerId:
                  remote?.controller_node_id ??
                  context.owner?.controller_node_id ??
                  null,
                controllerEpoch,
                lastTerminalCommand,
                targetRevision:
                  context.scope.kind === "target"
                    ? context.scope.target.revision
                    : null,
                writable: routingWritable(context),
                job: observedJob(context.job),
              });
            } else if (record) changes.invalidateObservation(record.token);
            if (lastNode.current !== null && lastNode.current !== value.nodeId)
              closeEditors();
            lastNode.current = value.nodeId;
            setView(value);
            setNeedsReview(false);
            onTarget(
              value.context.scope.kind === "target"
                ? value.context.scope.target
                : null,
            );
          }
        })
        .catch((failure) => {
          if (
            !request.signal.aborted &&
            id === serial.current &&
            epoch === controller.generation()
          ) {
            setError(apiError(failure));
            contextRef.current = null;
            if (read.current === request) read.current = null;
            setView((current) => ({
              ...current,
              page: null,
              policy: null,
              owner: null,
              context: null,
              nodeId: null,
              loading: false,
            }));
          }
        })
        .finally(() => {
          if (read.current === request) read.current = null;
        });
    },
    [
      controller,
      state.session,
      state.busy,
      epoch,
      kind,
      cursor,
      peer,
      onTarget,
      changes,
      invalidateReview,
    ],
  );
  useEffect(() => {
    load();
    return () => {
      serial.current++;
      read.current?.abort();
    };
  }, [load]);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      editor.current++;
      write.current?.abort();
      onBusy(false);
    };
  }, [epoch, onBusy]);
  useEffect(() => {
    setForm(null);
    setConfirmation(null);
    setDetail(null);
    setMembers(null);
    setPresetPool(null);
    setPresetResult(null);
    setSaved(null);
  }, [epoch]);
  const readOnly = !routingWritable(view.context);
  const disabled =
    busy ||
    presetBusy ||
    commandBusy ||
    needsReview ||
    state.busy ||
    view.loading ||
    readOnly ||
    !view.page ||
    !scope ||
    journalIssue !== null ||
    !changes.available(scope) ||
    !!error;
  function beginEditor(): number | null {
    const currentScope = scopeRef.current;
    if (
      disabled ||
      !mounted.current ||
      read.current ||
      write.current ||
      commandLock.current ||
      presetLock.current ||
      epoch !== controller.generation() ||
      !currentScope ||
      !changes.available(currentScope)
    )
      return null;
    closeEditors();
    return editor.current;
  }
  function beginReadEditor(): number | null {
    if (
      !mounted.current ||
      state.busy ||
      view.loading ||
      read.current ||
      write.current ||
      commandLock.current ||
      presetLock.current ||
      !view.page ||
      epoch !== controller.generation()
    )
      return null;
    closeEditors();
    return editor.current;
  }
  const refresh = () => {
    if (
      write.current ||
      read.current ||
      commandLock.current ||
      presetLock.current
    )
      return;
    closeEditors();
    if ((error?.code ?? change?.error?.code) === "invalid_csrf")
      void controller.check();
    else load();
  };
  const runChange = async <T extends ChangeResult>(
    intent: MutationIntent,
    context: RoutingContext,
    work: ChangeWork<T>,
    editorId: number,
    external?: AbortSignal,
    preset = false,
  ): Promise<T | null> => {
    const session = state.session;
    const currentScope = scopeRef.current;
    if (
      !session ||
      !currentScope ||
      !contextRef.current ||
      !mounted.current ||
      state.busy ||
      error ||
      view.loading ||
      needsReview ||
      read.current ||
      write.current ||
      commandLock.current ||
      (!preset && presetLock.current) ||
      editorId !== editor.current ||
      epoch !== controller.generation() ||
      external?.aborted ||
      !routingWritable(context) ||
      intent.expectedRevision !== context.policy.saved_revision ||
      (context.localNodeId !== null &&
        context.localNodeId !== currentScope.nodeId) ||
      (context.scope.kind === "local"
        ? peer !== null
        : context.scope.target.node_id !== peer ||
          context.localNodeId !== currentScope.nodeId)
    )
      return null;
    let metadata: Intent;
    try {
      const remote =
        context.scope.kind === "target" ? context.scope.policy : null;
      metadata = {
        ...intent,
        targetRevision:
          context.scope.kind === "target"
            ? context.scope.target.revision
            : null,
        controllerId:
          remote?.controller_node_id ??
          context.owner?.controller_node_id ??
          null,
        controllerEpoch:
          remote?.controller_epoch ?? context.owner?.epoch ?? null,
        commandId: remote ? nextCommand(remote.last_terminal_command) : null,
      };
    } catch (failure) {
      setError(apiError(failure));
      return null;
    }
    const request = new AbortController();
    write.current = request;
    const originalContext = contextRef.current;
    let token: Token | null = null;
    let admitted = false;
    // Cancellation is not a rollback. Record it synchronously even if the
    // transport ignores abort and its old response arrives after a remount.
    const cancelled = () => {
      if (!token) return;
      if (admitted) changes.fail(token, new ApiError("network"));
      else changes.notStarted(token);
    };
    const cancel = () => request.abort();
    request.signal.addEventListener("abort", cancelled, { once: true });
    external?.addEventListener("abort", cancel, { once: true });
    serial.current++;
    setBusy(true);
    setError(null);
    setSaved(null);
    const current = () => {
      const live = controller.snapshot();
      const actualScope = scopeRef.current;
      return (
        mounted.current &&
        live.phase === "authenticated" &&
        live.session === session &&
        !live.busy &&
        epoch === controller.generation() &&
        editor.current === editorId &&
        write.current === request &&
        !request.signal.aborted &&
        !external?.aborted &&
        read.current === null &&
        !commandLock.current &&
        (preset || !presetLock.current) &&
        contextRef.current === originalContext &&
        actualScope !== null &&
        actualScope.administratorId === currentScope.administratorId &&
        actualScope.nodeId === currentScope.nodeId &&
        actualScope.peer === currentScope.peer
      );
    };
    try {
      token = await changes.begin(currentScope, metadata, current);
      if (!token) return null;
      if (!current()) {
        changes.notStarted(token);
        return null;
      }
      const activeToken = token;
      const result = await controller.resource(
        session,
        async (client, csrf, signal) => {
          admitted = true;
          signal.addEventListener("abort", cancelled, { once: true });
          try {
            const result = await work(client, csrf, signal);
            if (
              result.submission &&
              !changes.captureTicket(activeToken, result.submission.job)
            )
              throw new ApiError("format");
            return result;
          } catch (failure) {
            // Classify a received guard rejection before session invalidation
            // can unmount this page. An earlier cancellation stays unknown.
            changes.fail(activeToken, apiError(failure));
            throw failure;
          } finally {
            signal.removeEventListener("abort", cancelled);
          }
        },
        request.signal,
      );
      if (request.signal.aborted || epoch !== controller.generation())
        throw new DOMException("Aborted", "AbortError");
      const record = changes.find(currentScope);
      if (
        record?.token !== token ||
        record.phase !== "pending" ||
        editor.current !== editorId
      )
        return null;
      // Retire the old callback before publishing a cleared claim. Another
      // microtask must not dispatch from that form before React closes it.
      editor.current++;
      const accepted =
        result.submission &&
        (!result.submission.response ||
          result.submission.job.state === "pending" ||
          result.submission.job.state === "blocked")
          ? changes.wait(token)
          : changes.succeed(token);
      return accepted ? result : null;
    } catch (failure) {
      if (token) {
        if (admitted) changes.fail(token, apiError(failure));
        else changes.notStarted(token);
      }
      if (
        mounted.current &&
        !request.signal.aborted &&
        epoch === controller.generation() &&
        editorId === editor.current
      ) {
        closeEditors();
      }
      return null;
    } finally {
      if (token) changes.release(token);
      external?.removeEventListener("abort", cancel);
      request.signal.removeEventListener("abort", cancelled);
      if (write.current === request) {
        write.current = null;
        if (mounted.current) setBusy(false);
      }
    }
  };
  const reviewCurrent = () => {
    if (
      !scope ||
      !change ||
      change.phase === "pending" ||
      !mounted.current ||
      state.busy ||
      read.current ||
      write.current ||
      commandLock.current ||
      presetLock.current ||
      epoch !== controller.generation()
    )
      return;
    closeEditors();
    load(false, change.token);
  };
  const proceed = async () => {
    if (
      !scope ||
      !change ||
      !mounted.current ||
      state.busy ||
      read.current ||
      write.current ||
      commandLock.current ||
      presetLock.current ||
      epoch !== controller.generation() ||
      changes.find(scope) !== change
    )
      return;
    // Retire open read-only editors before publishing a released claim.
    closeEditors();
    const editorId = editor.current;
    const session = state.session;
    const originalObservation = change.observation;
    const request = new AbortController();
    write.current = request;
    setBusy(true);
    const current = () => {
      const actualScope = scopeRef.current;
      const live = controller.snapshot();
      return (
        mounted.current &&
        !request.signal.aborted &&
        write.current === request &&
        live.phase === "authenticated" &&
        live.session === session &&
        !live.busy &&
        epoch === controller.generation() &&
        editor.current === editorId &&
        read.current === null &&
        !commandLock.current &&
        !presetLock.current &&
        actualScope !== null &&
        actualScope.administratorId === scope.administratorId &&
        actualScope.nodeId === scope.nodeId &&
        actualScope.peer === scope.peer
      );
    };
    let accepted = false;
    try {
      accepted = await changes.continue(
        change.token,
        epoch,
        () =>
          current() &&
          changes.find(scope)?.token === change.token &&
          changes.find(scope)?.observation === originalObservation,
      );
      if (!accepted || !current()) return;
      setError(null);
      setSubmitted(null);
      setPresetResult(null);
      setNeedsReview(false);
      setSaved(null);
    } finally {
      if (write.current === request) {
        write.current = null;
        if (mounted.current) setBusy(false);
      }
    }
    if (accepted && mounted.current && epoch === controller.generation())
      load();
  };
  const trackCommandBusy = useCallback(
    (value: boolean) => {
      commandLock.current = value;
      if (value) invalidateReview();
      setCommandBusy(value);
    },
    [invalidateReview],
  );
  const trackPresetBusy = useCallback(
    (value: boolean) => {
      presetLock.current = value;
      if (value) invalidateReview();
      setPresetBusy(value);
    },
    [invalidateReview],
  );
  function canStartCommand(action: string, jobId?: string): boolean {
    const currentScope = scopeRef.current;
    const context = contextRef.current;
    if (
      !mounted.current ||
      state.busy ||
      epoch !== controller.generation() ||
      read.current ||
      write.current ||
      commandLock.current ||
      presetLock.current ||
      !currentScope ||
      !context ||
      members ||
      presetPool
    )
      return false;
    if (action !== "read" && (!jobId || context.job?.job_id !== jobId))
      return false;
    if (
      (action === "retry" || action === "supersede") &&
      context.job?.state !== "pending" &&
      context.job?.state !== "blocked"
    )
      return false;
    const record = changes.find(currentScope);
    if (action === "read") return true;
    if (changes.issue() !== null) return false;
    if (!record) return true;
    if (
      !knownTicket(record, context.job) ||
      jobId !== record.ticket?.job_id ||
      context.scope.kind !== "target"
    )
      return false;
    return (
      context.scope.target.revision === record.intent.targetRevision &&
      context.scope.policy.controller_node_id === record.intent.controllerId &&
      context.scope.policy.controller_epoch === record.intent.controllerEpoch &&
      context.localNodeId === currentScope.nodeId &&
      context.scope.target.active &&
      !context.scope.target.retired &&
      !context.scope.target.rollback_detected
    );
  }
  const mutate = async (
    intent: MutationIntent,
    work: RoutingWork,
    editorId: number,
  ): Promise<RoutingScopeChange | null> => {
    const context = contextRef.current;
    if (!context) return null;
    const result = await runChange(
      intent,
      context,
      (client, csrf, signal) =>
        work(routingOperations(client, context), csrf, signal),
      editorId,
    );
    if (
      result &&
      mounted.current &&
      editorId + 1 === editor.current &&
      controller.generation() === epoch
    ) {
      // A successful reply retires the submitted form too. A member drawer can
      // stay open, but its next callback must use a fresh editor and read CAS.
      const nextEditor = editor.current;
      setSaved(result.revision);
      setForm(null);
      setConfirmation(null);
      setDetail(null);
      const updated =
        result.entity?.kind === "pool" ? result.entity.data : null;
      setMembers((current) =>
        current
          ? {
              pool: updated?.id === current.pool.id ? updated : current.pool,
              id: nextEditor,
            }
          : null,
      );
      setSubmitted(result.submission);
      if (result.submission) {
        setNeedsReview(true);
        if (!result.submission.response) setMembers(null);
        installJob(result.submission.job);
      }
      if (!result.submission || (result.submission.response && !members))
        load();
      return result;
    }
    return null;
  };
  const notice = error ? (
    <Alert
      type="error"
      showIcon
      title={t(errorMessage(error))}
      description={
        change?.phase === "unknown" ? t("users.mutationUncertain") : undefined
      }
      action={
        <Button disabled={busy} onClick={refresh}>
          {t("users.refresh")}
        </Button>
      }
    />
  ) : null;
  const columns: ProColumns<Resource>[] = [
    {
      title: t("resources.name"),
      dataIndex: "name",
      render: (_, row) => (
        <Space orientation="vertical" size={0}>
          <Typography.Text strong>{row.name}</Typography.Text>
          <Typography.Text code copyable className="managed-identifier">
            {row.id}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: t(
        kind === "prefixes"
          ? "resources.cidr"
          : kind === "addresses"
            ? "resources.ip"
            : "resources.family",
      ),
      render: (_, row) =>
        "cidr" in row
          ? row.cidr
          : "ip" in row
            ? row.ip
            : row.family === "v4"
              ? "IPv4"
              : "IPv6",
    },
    {
      title: t("users.state"),
      render: (_, row) => {
        const status =
          "retired" in row
            ? row.retired
              ? "retired"
              : "registered"
            : row.state;
        return (
          <Tag
            color={
              status === "retired"
                ? "default"
                : status === "draining"
                  ? "orange"
                  : "blue"
            }
          >
            {t(`resources.${status}`)}
          </Tag>
        );
      },
    },
    ...(kind === "pools"
      ? [
          {
            title: t("resources.memberCount"),
            render: (_: unknown, row: Resource) =>
              "member_count" in row ? row.member_count : "—",
          },
        ]
      : []),
    { title: t("resources.revision"), dataIndex: "revision" },
    {
      title: t("users.actions"),
      render: (_, row) => {
        const retired =
          "retired" in row ? row.retired : row.state === "retired";
        return (
          <Space wrap>
            <Button
              size="small"
              disabled={busy || state.busy}
              onClick={() => setDetail(row)}
            >
              {t("resources.details")}
            </Button>
            {"member_count" in row && (
              <Button
                size="small"
                disabled={busy || state.busy || view.loading}
                onClick={() => {
                  const id = beginReadEditor();
                  if (id !== null) setMembers({ pool: row, id });
                }}
              >
                {t("resources.members")}
              </Button>
            )}
            {"member_count" in row && (
              <Button
                size="small"
                disabled={busy || state.busy || view.loading || presetBusy}
                onClick={() => {
                  const id = beginReadEditor();
                  if (id !== null) setPresetPool({ pool: row, id });
                }}
              >
                {t("presets.title")}
              </Button>
            )}
            {!("retired" in row) && (
              <Button
                size="small"
                disabled={disabled || retired}
                onClick={() => {
                  const id = beginEditor();
                  if (id === null) return;
                  const next = row.state === "active" ? "draining" : "active";
                  setConfirmation({
                    title:
                      next === "active"
                        ? "resources.resume"
                        : "resources.drain",
                    hint: "resources.drainHint",
                    epoch,
                    id,
                    intent: {
                      kind: "ip" in row ? "addresses" : "pools",
                      action: next === "active" ? "resume" : "drain",
                      resourceId: row.id,
                      memberId: null,
                      expectedRevision: view.page!.revision,
                    },
                    work: (client, csrf, signal) =>
                      client.routingState(
                        "ip" in row ? "addresses" : "pools",
                        row.id,
                        next,
                        view.page!.revision,
                        csrf,
                        signal,
                      ),
                  });
                }}
              >
                {t(
                  row.state === "active"
                    ? "resources.drain"
                    : "resources.resume",
                )}
              </Button>
            )}
            <Button
              size="small"
              danger
              disabled={disabled || retired}
              onClick={() => {
                const id = beginEditor();
                if (id === null) return;
                setConfirmation({
                  title: "resources.retire",
                  hint: "resources.retireHint",
                  epoch,
                  id,
                  intent: {
                    kind,
                    action: "retire",
                    resourceId: row.id,
                    memberId: null,
                    expectedRevision: view.page!.revision,
                  },
                  work: (client, csrf, signal) =>
                    "retired" in row
                      ? client.retirePrefix(
                          row.id,
                          view.page!.revision,
                          csrf,
                          signal,
                        )
                      : client.routingState(
                          "ip" in row ? "addresses" : "pools",
                          row.id,
                          "retired",
                          view.page!.revision,
                          csrf,
                          signal,
                        ),
                });
              }}
            >
              {t("resources.retire")}
            </Button>
          </Space>
        );
      },
    },
  ];
  const submit = (values: ResourceFields, editorId: number) => {
    const current = form;
    if (!current || current.id !== editorId) return Promise.resolve(false);
    return mutate(
      {
        kind,
        action: "create",
        resourceId: null,
        memberId: null,
        expectedRevision: current.revision,
      },
      (client, csrf, signal) =>
        kind === "prefixes"
          ? client.createPrefix(
              { name: values.name, cidr: values.cidr },
              current.revision,
              csrf,
              signal,
            )
          : kind === "addresses"
            ? client.createAddress(
                {
                  name: values.name,
                  ip: values.ip,
                  prefix_id: values.prefix_id || null,
                },
                current.revision,
                csrf,
                signal,
              )
            : client.createPool(
                { name: values.name, family: values.family },
                current.revision,
                csrf,
                signal,
              ),
      editorId,
    ).then((result) => result !== null);
  };
  return (
    <Space orientation="vertical" size={16} className="full-width">
      {journalIssue && (
        <Alert
          showIcon
          type="warning"
          title={t("control.changeStorageBlocked")}
          description={t(`control.changeStorage.${journalIssue}`)}
        />
      )}
      {change?.restored && (
        <Alert
          showIcon
          type="warning"
          title={t("resources.changeRestored")}
          description={t("resources.changeRestoredHint")}
        />
      )}
      {change && (
        <ChangeReview
          change={change}
          epoch={epoch}
          reading={view.loading}
          blocked={state.busy || busy || commandBusy || presetBusy}
          readFailed={!!error}
          read={reviewCurrent}
          proceed={() => void proceed()}
        />
      )}
      {scope && !change && !journalIssue && !changes.available(scope) && (
        <Alert showIcon type="warning" title={t("resources.changeCapacity")} />
      )}
      {peer === null && view.owner?.controller_node_id && (
        <Alert
          type="warning"
          showIcon
          title={t("control.locallyManaged")}
          description={t("control.ownerHint")}
        />
      )}
      {peer !== null && view.context && !routingWritable(view.context) && (
        <Alert
          type="warning"
          showIcon
          title={t("control.grantRequired")}
          description={t("resources.remoteWriteHint")}
        />
      )}
      {submitted && !change && (
        <Alert
          showIcon
          type={
            submitted.response?.receipt.status === "rejected"
              ? "error"
              : "warning"
          }
          title={t(
            submitted.response?.receipt.status === "rejected"
              ? "control.rejected"
              : submitted.response
                ? "control.receiptReceived"
                : "control.intentSaved",
          )}
          description={t("resources.remoteIntentHint")}
        />
      )}
      {presetResult && !change && (
        <Alert
          showIcon
          type={
            presetResult.response?.receipt.status === "rejected"
              ? "error"
              : "warning"
          }
          title={t(
            presetResult.response?.receipt.status === "rejected"
              ? "control.rejected"
              : presetResult.response
                ? "control.receiptReceived"
                : "control.intentSaved",
          )}
          description={t("control.ticketHint")}
        />
      )}
      {peer !== null && view.context && (
        <CommandPanel
          targetId={peer}
          job={view.context.job}
          busy={busy || view.loading || !!members || !!presetPool}
          onBusy={trackCommandBusy}
          canStart={canStartCommand}
          onChange={(job) => {
            invalidateReview();
            const currentScope = scopeRef.current;
            const record = currentScope ? changes.find(currentScope) : null;
            if (record && job && knownTicket(record, job))
              changes.captureTicket(record.token, job);
            setNeedsReview(true);
            installJob(job);
          }}
          onRefresh={refresh}
        />
      )}
      {needsReview && !change && (
        <Alert
          type="warning"
          showIcon
          title={t("control.reviewBeforeEdit")}
          action={
            <Button disabled={busy || commandBusy} onClick={refresh}>
              {t("users.refresh")}
            </Button>
          }
        />
      )}
      {notice}
      {saved && (
        <Alert
          type="success"
          showIcon
          title={t("resources.saved", { revision: saved })}
        />
      )}
      <Space wrap>
        <Typography.Text>
          {t("resources.globalRevision")}: {view.page?.revision ?? "—"}
        </Typography.Text>
        <Typography.Text>
          {t("users.appliedRevision")}: {view.policy?.applied_revision ?? "—"}
        </Typography.Text>
        {view.policy && (
          <Tag>
            {t(
              view.policy.proxy_running
                ? view.policy.applied_revision === view.policy.saved_revision
                  ? "users.running"
                  : "users.pending"
                : "users.apiOnly",
            )}
          </Tag>
        )}
      </Space>
      <ProTable<Resource>
        className="management-data-table"
        rowKey="id"
        columns={labelledColumns(columns)}
        dataSource={view.page?.items ?? []}
        loading={view.loading || state.busy}
        search={false}
        options={false}
        pagination={false}
        scroll={{ x: 1100 }}
        headerTitle={t(`resources.${kind}`)}
        toolBarRender={() => [
          <Button
            key="refresh"
            aria-label={t("users.refresh")}
            aria-busy={view.loading}
            loading={view.loading}
            disabled={busy || state.busy}
            onClick={refresh}
          >
            {t("users.refresh")}
          </Button>,
          <Button
            key="register"
            type="primary"
            disabled={disabled}
            onClick={() => {
              const id = beginEditor();
              if (id !== null)
                setForm({ revision: view.page!.revision, epoch, id });
            }}
          >
            {t("resources.register")}
          </Button>,
        ]}
      />
      <Space wrap>
        <Button
          disabled={view.loading || busy || cursors.length <= 1}
          onClick={() => setCursors((value) => value.slice(0, -1))}
        >
          {t("users.previous")}
        </Button>
        <Typography.Text>
          {t("users.page", { page: cursors.length })}
        </Typography.Text>
        <Button
          disabled={view.loading || busy || !view.page?.next_cursor}
          onClick={() =>
            setCursors((value) => [...value, view.page!.next_cursor!])
          }
        >
          {t("users.next")}
        </Button>
      </Space>
      {form && form.epoch === epoch && !state.busy && (
        <ResourceForm
          key={form.id}
          kind={kind}
          busy={busy}
          blocked={disabled}
          notice={notice}
          close={() =>
            !write.current && form.id === editor.current && closeEditors()
          }
          submit={(values) => submit(values, form.id)}
        />
      )}
      {confirmation && confirmation.epoch === epoch && !state.busy && (
        <Modal
          open
          title={t(confirmation.title)}
          onOk={() =>
            void mutate(confirmation.intent, confirmation.work, confirmation.id)
          }
          onCancel={() =>
            !write.current &&
            confirmation.id === editor.current &&
            closeEditors()
          }
          okText={t("users.confirm")}
          cancelText={t("users.cancel")}
          confirmLoading={busy}
          okButtonProps={{ danger: true, disabled }}
          cancelButtonProps={{ disabled: busy }}
          closable={!busy}
          maskClosable={false}
        >
          {notice}
          <Typography.Paragraph>{t(confirmation.hint)}</Typography.Paragraph>
        </Modal>
      )}
      {detail && !state.busy && (
        <Drawer
          open
          size="large"
          title={detail.name}
          onClose={() => setDetail(null)}
          destroyOnHidden
        >
          <Alert type="info" showIcon title={t("resources.healthHint")} />
          {"member_count" in detail && (
            <Link to={trafficHref({ kind: "pool", id: detail.id }, peer)}>
              {t("traffic.open")}
            </Link>
          )}
          <Descriptions
            column={1}
            items={[
              {
                key: "id",
                label: t("resources.id"),
                children: (
                  <Typography.Text code copyable>
                    {detail.id}
                  </Typography.Text>
                ),
              },
              {
                key: "revision",
                label: t("resources.revision"),
                children: detail.revision,
              },
              {
                key: "value",
                label:
                  "cidr" in detail
                    ? t("resources.cidr")
                    : "ip" in detail
                      ? t("resources.ip")
                      : t("resources.family"),
                children:
                  "cidr" in detail
                    ? detail.cidr
                    : "ip" in detail
                      ? detail.ip
                      : detail.family === "v4"
                        ? "IPv4"
                        : "IPv6",
              },
              ...("prefix_id" in detail
                ? [
                    {
                      key: "prefix",
                      label: t("resources.prefixId"),
                      children: detail.prefix_id ?? "—",
                    },
                  ]
                : []),
              ...(!("cidr" in detail)
                ? [
                    {
                      key: "selector",
                      label: t("resources.selector"),
                      children: (
                        <Typography.Text
                          code
                          copyable
                          className="managed-identifier"
                        >{`-${"ip" in detail ? "exit" : "pool"}-${routingToken(detail.id)}`}</Typography.Text>
                      ),
                    },
                  ]
                : []),
            ]}
          />
          <Typography.Paragraph type="secondary">
            {t("resources.selectorHint")}
          </Typography.Paragraph>
        </Drawer>
      )}
      {members && !state.busy && (
        <Members
          key={members.pool.id}
          pool={members.pool}
          busy={busy}
          writeDisabled={disabled}
          mutationError={change?.phase === "unknown" ? change.error : null}
          peer={peer}
          onContext={updateContext}
          invalidateReview={invalidateReview}
          submission={submitted}
          refreshPolicy={refresh}
          mutate={(intent, work) => mutate(intent, work, members.id)}
          close={() => {
            if (!write.current && members.id === editor.current) {
              closeEditors();
              if (peer !== null) load();
            }
          }}
        />
      )}
      {presetPool && !state.busy && (
        <PresetEditor
          key={presetPool.id}
          entity={{
            kind: "pool",
            id: presetPool.pool.id,
            name: presetPool.pool.name,
          }}
          peer={peer}
          writeBlocked={disabled || presetPool.pool.state === "retired"}
          close={() =>
            !write.current &&
            !presetLock.current &&
            presetPool.id === editor.current &&
            closeEditors()
          }
          onBusy={trackPresetBusy}
          invalidateReview={invalidateReview}
          mutate={(context, mutation, revision, signal) => {
            if (
              mutation.action !== "set_pool_preset" ||
              mutation.preset.pool_id !== presetPool.pool.id
            )
              return Promise.resolve(null);
            return runChange(
              {
                kind: "pool_preset",
                action: "set_preset",
                resourceId: presetPool.pool.id,
                memberId: null,
                expectedRevision: revision,
              },
              context,
              (client, csrf, signal) =>
                setPresets(client, context, mutation, revision, csrf, signal),
              presetPool.id,
              signal,
              true,
            );
          }}
          saved={(result) => {
            trackPresetBusy(false);
            closeEditors();
            setSaved(result.revision);
            setSubmitted(null);
            setPresetResult(result.submission);
            if (result.submission) {
              setNeedsReview(true);
              installJob(result.submission.job);
            }
            if (!result.submission || result.submission.response) load();
          }}
        />
      )}
    </Space>
  );
}

function Resources({
  peer,
  address,
  findAddress,
  changeScope,
}: {
  peer: string | null;
  address: string | null;
  findAddress: (id: string | null) => void;
  changeScope: (peer: string | null) => void;
}) {
  const { t } = useMessages();
  const [kind, setKind] = useState<ResourceKind | "observations">(
    address === null ? "prefixes" : "addresses",
  );
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<Target | null>(null);
  const [lookupReading, setLookupReading] = useState(false);
  const [lookupVersion, setLookupVersion] = useState(0);
  const [lookupOpen, setLookupOpen] = useState(address !== null);
  useEffect(() => {
    if (address !== null) setLookupOpen(true);
  }, [address]);
  return (
    <PageContainer
      className="management-page"
      title={t("resources.title")}
      content={t("resources.description")}
    >
      <Space orientation="vertical" size={16} className="full-width">
        <ScopePicker
          value={peer}
          onChange={changeScope}
          disabled={busy}
          selected={selected}
        />
        <Collapse
          size="small"
          activeKey={lookupOpen ? ["lookup"] : []}
          onChange={(keys) => setLookupOpen(keys.length > 0)}
          items={[
            {
              key: "lookup",
              label: t("resources.lookupTitle"),
              children: (
                <AddressFinder
                  address={address}
                  blocked={busy || lookupReading}
                  onFind={(id) => {
                    setKind("addresses");
                    if (id === address)
                      setLookupVersion((version) => version + 1);
                    findAddress(id);
                  }}
                />
              ),
            },
          ]}
        />
        {peer !== null && (
          <Alert
            type="info"
            showIcon
            title={t("resources.remoteScope")}
            description={t("resources.remoteScopeHint")}
          />
        )}
        <Alert type="warning" showIcon title={t("resources.inventoryHint")} />
        {address !== null ? (
          <AddressLookup
            key={`${peer ?? "local"}:${address}:${lookupVersion}`}
            peer={peer}
            id={address}
            onTarget={setSelected}
            onLoading={setLookupReading}
            browse={() => {
              setKind("addresses");
              findAddress(null);
            }}
          />
        ) : (
          <>
            <Tabs
              activeKey={kind}
              onChange={(value) => {
                if (!busy) setKind(value as ResourceKind | "observations");
              }}
              items={(
                ["prefixes", "addresses", "pools", "observations"] as const
              ).map((key) => ({
                key,
                label: t(`resources.${key}`),
                disabled: busy && kind !== key,
              }))}
            />
            {kind === "observations" ? (
              <Health peer={peer} onTarget={setSelected} onBusy={setBusy} />
            ) : (
              <Catalog
                key={kind}
                kind={kind}
                onBusy={setBusy}
                peer={peer}
                onTarget={setSelected}
              />
            )}
          </>
        )}
      </Space>
    </PageContainer>
  );
}
export default function ResourcesPage() {
  const { t } = useMessages();
  const location = useLocation();
  const selectScope = useScopeNavigation();
  let peer: string | null;
  let address: string | null;
  try {
    ({ peer, address } = resourceLocation(location.search));
  } catch {
    return <ScopeError />;
  }
  return __VPROXY_DEMO__ ? (
    <Result
      status="info"
      title={t("users.demoTitle")}
      subTitle={t("users.demoDescription")}
    />
  ) : (
    <ManagementGate>
      <Resources
        key={peer ?? "local"}
        peer={peer}
        address={address}
        findAddress={(id) => selectScope(resourcesHref(peer, id))}
        changeScope={(target) => selectScope(scopeHref("/resources", target))}
      />
    </ManagementGate>
  );
}
