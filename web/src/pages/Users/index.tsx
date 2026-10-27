import { PageContainer, ProCard } from "@ant-design/pro-components";
import {
  Alert,
  Button,
  Checkbox,
  Collapse,
  Descriptions,
  Empty,
  Modal,
  Result,
  Space,
  Table,
  Tag,
  Typography,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { useCallback, useEffect, useRef, useState } from "react";
import { history, Link, useLocation } from "@umijs/max";
import { ApiError, apiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import type {
  Page,
  PolicyStatus,
  ProxyUser,
  ProxyCredential,
  UserSearchInput,
} from "../../api/proxy";
import { canonicalId } from "../../api/proxy";
import { trafficHref } from "../../api/traffic";
import { proxyOperations, scopeAccess, type ProxyScope } from "../../api/scope";
import type {
  Job,
  Owner,
  PolicyJob,
  RemotePolicy,
  Target,
} from "../../api/targets";
import { useManagement } from "../../auth/context";
import ManagementGate from "../../components/ManagementGate";
import { useMessages } from "../../hooks/useMessages";
import type { MessageKey } from "../../hooks/useMessages";
import Credentials, {
  type Confirmation,
  type CredentialObservation,
  type MutationWork,
} from "./Credentials";
import UserForm from "./UserForm";
import UserSearch from "./UserSearch";
import ScopePicker from "./ScopePicker";
import CommandPanel from "./CommandPanel";
import RoutingPermission from "./RoutingPermission";
import type { RoutingScopeChange } from "../../api/remoteRouting";
import type { PresetScopeChange } from "../../api/remotePresets";
import PresetEditor from "../../components/Presets/Editor";
import ConnectionModal from "../../components/Presets/ConnectionModal";
import ScopeError from "../../components/ScopeError";
import { scopeHref, scopeLocation } from "../../routing/scope";
import { useScopeNavigation } from "../../routing/ScopeNavigation";
import { createdUserDelivery, type CreatedUserDelivery } from "./delivery";
import { readLocalUserView } from "./localView";
import {
  userOperationInput,
  type UserChange,
  type UserOperation,
} from "../../api/userOperations";
import LocalOperations from "./LocalOperations";
import CrossNodeSearch, { type UserLocation } from "./CrossNodeSearch";

type CrossSearchPhase = "closed" | "open" | "locating" | "navigating";
interface UserHandoff {
  value: UserLocation;
  epoch: number;
  sourceKey: string;
  href: string;
}

interface OperationContext {
  title: MessageKey;
  subject: Confirmation["subject"] | null;
  revision: string;
  secretExpected?: boolean;
  userChange?: UserChange;
}
interface OperationScope {
  nodeId: string | null;
  targetRevision: string | null;
  controllerNodeId: string | null;
  controllerEpoch: string | null;
}
interface ReviewedConfirmation extends Confirmation {
  trigger: HTMLElement;
  epoch: number;
  scope: OperationScope;
  readSerial: number;
  credentialReadToken: object;
  node:
    | { kind: "local"; origin: string | null }
    | { kind: "target"; id: string; name: string; origin: string };
}
interface CancelFocus {
  epoch: number;
  targetId: string | null;
  userId: string;
  region: "users" | "credentials";
  trigger: HTMLElement;
}
interface OperationAttempt {
  context: OperationContext;
  scope: OperationScope;
  outcome: "unknown" | "rejected" | "pending" | "terminal";
  error: ApiError | null;
  ticket: Job | null;
  local: UserOperation | null;
  preparationFailed: boolean;
  fresh: boolean;
  scopeChanged: boolean;
  secretMissing: boolean;
}

function operationScope(
  target: Target | null,
  remote: RemotePolicy | null,
  owner: Owner | null,
): OperationScope {
  return {
    nodeId: target?.node_id ?? null,
    targetRevision: target?.revision ?? null,
    controllerNodeId:
      remote?.controller_node_id ?? owner?.controller_node_id ?? null,
    controllerEpoch: remote?.controller_epoch ?? owner?.epoch ?? null,
  };
}
function sameScope(left: OperationScope, right: OperationScope): boolean {
  return (
    left.nodeId === right.nodeId &&
    left.targetRevision === right.targetRevision &&
    left.controllerNodeId === right.controllerNodeId &&
    left.controllerEpoch === right.controllerEpoch
  );
}
function sameTicket(left: Job, right: Job | null | undefined): boolean {
  return (
    right !== null &&
    right !== undefined &&
    left.resource === undefined &&
    right.resource === undefined &&
    left.maintenance === undefined &&
    right.maintenance === undefined &&
    !right.routing &&
    !right.preset &&
    left.node_id === right.node_id &&
    left.job_id === right.job_id &&
    left.controller_epoch === right.controller_epoch &&
    left.command_id === right.command_id &&
    left.expected_policy_revision === right.expected_policy_revision
  );
}
function terminal(ticket: Job): boolean {
  return ticket.state !== "pending" && ticket.state !== "blocked";
}
/** Only route/body guards prove that a handler never admitted this write. */
function rejectedBeforeMutation(error: ApiError): boolean {
  if (error.kind !== "server") return false;
  switch (error.code) {
    case "invalid_host":
      return error.status === 400 || error.status === 403;
    case "invalid_origin":
    case "invalid_csrf":
    case "authentication_required":
      return error.status === 403;
    case "invalid_headers":
    case "invalid_body":
    case "invalid_json":
    case "invalid_revision":
    case "invalid_resource_id":
      return error.status === 400;
    case "body_timeout":
      return error.status === 408;
    case "body_too_large":
      return error.status === 413;
    case "json_required":
      return error.status === 415;
    case "misdirected_request":
      return error.status === 421;
    default:
      // Storage/publication errors may occur after commit, even with a 4xx.
      return false;
  }
}

function Users({
  targetId,
  changeScope,
  initialLocation = null,
  locateElsewhere,
}: {
  targetId: string | null;
  changeScope: (id: string | null) => void;
  initialLocation?: UserLocation | null;
  locateElsewhere: (value: UserLocation) => void | Promise<void>;
}) {
  const { t } = useMessages();
  const { controller, state } = useManagement();
  const session = state.session;
  const epoch = controller.generation();
  const [view, setView] = useState<{
    policy: PolicyStatus | null;
    page: Page<ProxyUser> | null;
    loading: boolean;
    target: Target | null;
    remote: RemotePolicy | null;
    owner: Owner | null;
    job: Job | null | undefined;
  }>({
    policy: null,
    page: null,
    loading: true,
    target: null,
    remote: null,
    owner: null,
    job: undefined,
  });
  const latestView = useRef(view);
  latestView.current = view;
  const [needsRemoteRefresh, setNeedsRemoteRefresh] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [attempt, setAttempt] = useState<OperationAttempt | null>(null);
  const [localOperationsOpen, setLocalOperationsOpen] = useState(false);
  const localOperationsTrigger = useRef<{
    element: HTMLButtonElement;
    epoch: number;
  } | null>(null);
  const [operationReadBusy, setOperationReadBusy] = useState(false);
  const operationRead = useRef<AbortController | null>(null);
  const attemptRef = useRef<OperationAttempt | null>(null);
  const rememberAttempt = useCallback((value: OperationAttempt | null) => {
    attemptRef.current = value;
    setAttempt(value);
  }, []);
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const cursor = cursors.at(-1);
  const [includeDeleted, setIncludeDeleted] = useState(
    initialLocation?.includeDeleted ?? false,
  );
  const [search, setSearch] = useState<UserSearchInput | null>(() =>
    initialLocation ? { mode: "id", q: initialLocation.userId } : null,
  );
  const [locateUserId, setLocateUserId] = useState<string | null>(
    initialLocation?.userId ?? null,
  );
  const [searchResetToken, setSearchResetToken] = useState<object>(() => ({}));
  const [locationCancelled, setLocationCancelled] = useState(false);
  const [crossPhase, setCrossPhaseState] = useState<CrossSearchPhase>(
    initialLocation ? "locating" : "closed",
  );
  const crossPhaseRef = useRef(crossPhase);
  const setCrossPhase = useCallback((value: CrossSearchPhase) => {
    crossPhaseRef.current = value;
    setCrossPhaseState(value);
  }, []);
  const crossEpoch = useRef(epoch);
  const crossTrigger = useRef<{
    element: HTMLButtonElement;
    epoch: number;
  } | null>(null);
  const [pendingCrossFocus, setPendingCrossFocus] = useState<{
    element: HTMLButtonElement;
    epoch: number;
  } | null>(null);
  const overlayOpening = useRef(false);
  const locateNotice = useRef<HTMLDivElement | null>(null);
  const locateFocus = useRef(initialLocation !== null);
  // A row/form opening in the same event batch must win before its state commits.
  useEffect(() => {
    overlayOpening.current = false;
  });
  useEffect(() => {
    if (!pendingCrossFocus || crossPhase !== "closed") return;
    setPendingCrossFocus(null);
    const { element, epoch: openingEpoch } = pendingCrossFocus;
    if (
      openingEpoch !== controller.generation() ||
      state.busy ||
      !element.isConnected ||
      element.disabled
    )
      return;
    const active = element.ownerDocument.activeElement;
    // The Modal is conditionally unmounted, so its after-close focus hook does
    // not run. Restore only an idle document; never steal another task's focus.
    if (!active || active === element.ownerDocument.body || active === element)
      element.focus();
  }, [pendingCrossFocus, crossPhase, controller, state.busy]);
  const [searchNeedsRestart, setSearchNeedsRestart] = useState(false);
  const [selected, setSelected] = useState<ProxyUser | null>(null);
  const [delivery, setDelivery] = useState<
    | (CreatedUserDelivery & {
        epoch: number;
        scope: OperationScope;
      })
    | null
  >(null);
  const [routingUser, setRoutingUser] = useState<ProxyUser | null>(null);
  const [presetUser, setPresetUser] = useState<ProxyUser | null>(null);
  const [routingBusy, setRoutingBusy] = useState(false);
  const [routingResult, setRoutingResult] = useState<
    RoutingScopeChange | PresetScopeChange | null
  >(null);
  const [form, setForm] = useState<{
    user: ProxyUser | null;
    revision: string;
    epoch: number;
    readSerial: number;
  } | null>(null);
  const [confirmation, setConfirmation] = useState<ReviewedConfirmation | null>(
    null,
  );
  const confirmationRef = useRef<ReviewedConfirmation | null>(null);
  const cancelReview = useRef<HTMLButtonElement | null>(null);
  const closeConfirmation = useCallback(() => {
    confirmationRef.current = null;
    setConfirmation(null);
  }, []);
  const [credentialObservation, setCredentialObservation] =
    useState<CredentialObservation | null>(null);
  const credentialObservationRef = useRef<CredentialObservation | null>(null);
  // A reopened drawer can reuse its numeric serial; identity must still change.
  const credentialReadToken = useRef<object>({});
  const observeCredentials = useCallback(
    (value: CredentialObservation | null) => {
      credentialReadToken.current = {};
      credentialObservationRef.current = value;
      setCredentialObservation(value);
    },
    [],
  );
  const [secret, setSecret] = useState<{
    login: string;
    value: string;
    epoch: number;
    credential: ProxyCredential;
    user: ProxyUser | null;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [commandBusy, setCommandBusy] = useState(false);
  const commandBusyRef = useRef(false);
  const observeCommandBusy = useCallback((value: boolean) => {
    commandBusyRef.current = value;
    setCommandBusy(value);
  }, []);
  const [refreshTick, setRefreshTick] = useState(0);
  const [pendingTaskFocus, setPendingTaskFocus] = useState<{
    epoch: number;
    targetId: string;
  } | null>(null);
  const [pendingCancelFocus, setPendingCancelFocus] =
    useState<CancelFocus | null>(null);
  const read = useRef<AbortController | null>(null);
  const write = useRef<AbortController | null>(null);
  const serial = useRef(0);
  const taskPanel = useRef<HTMLElement | null>(null);
  const usersRegion = useRef<HTMLElement | null>(null);
  const credentialsRegion = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (!pendingCancelFocus) return;
    // Consume once: a later idle state must not steal focus from a new task.
    setPendingCancelFocus(null);
    const region =
      pendingCancelFocus.region === "credentials"
        ? selected?.id === pendingCancelFocus.userId
          ? credentialsRegion.current
          : null
        : selected === null
          ? usersRegion.current
          : null;
    if (
      pendingCancelFocus.epoch !== controller.generation() ||
      pendingCancelFocus.targetId !== targetId ||
      confirmationRef.current ||
      form ||
      routingUser ||
      presetUser ||
      secret ||
      pendingTaskFocus ||
      write.current ||
      busy ||
      state.busy ||
      commandBusy ||
      routingBusy ||
      view.loading ||
      !region?.isConnected
    )
      return;
    const active = region.ownerDocument.activeElement;
    if (
      active &&
      active !== region.ownerDocument.body &&
      active !== pendingCancelFocus.trigger &&
      !region.contains(active)
    )
      return;
    const trigger = pendingCancelFocus.trigger;
    // Renders can replace the trigger. Keep the fallback in the same task area.
    if (
      trigger.isConnected &&
      region.contains(trigger) &&
      trigger.getAttribute("disabled") === null &&
      trigger.getAttribute("aria-disabled") !== "true"
    )
      trigger.focus();
    else region.focus();
  }, [
    pendingCancelFocus,
    controller,
    targetId,
    selected,
    form,
    routingUser,
    presetUser,
    secret,
    pendingTaskFocus,
    busy,
    state.busy,
    commandBusy,
    routingBusy,
    view.loading,
  ]);
  useEffect(() => {
    if (!pendingTaskFocus) return;
    setPendingTaskFocus(null);
    if (
      pendingTaskFocus.epoch === epoch &&
      pendingTaskFocus.epoch === controller.generation() &&
      pendingTaskFocus.targetId === targetId &&
      !state.busy &&
      !selected &&
      !form &&
      !confirmation
    )
      taskPanel.current?.focus();
  }, [
    pendingTaskFocus,
    epoch,
    targetId,
    state.busy,
    selected,
    form,
    confirmation,
    controller,
  ]);
  const load = useCallback(() => {
    if (!session || state.busy || searchNeedsRestart) return;
    if (
      crossPhaseRef.current === "open" ||
      crossPhaseRef.current === "navigating" ||
      (crossPhaseRef.current === "locating" &&
        (!locateUserId || search?.mode !== "id" || search.q !== locateUserId))
    )
      return;
    if (locateUserId) setLocationCancelled(false);
    read.current?.abort();
    const request = new AbortController();
    read.current = request;
    const id = ++serial.current;
    setError(null);
    latestView.current = { ...latestView.current, loading: true };
    setView(latestView.current);
    return controller
      .resource(
        session,
        async (client, _csrf, signal) => {
          if (targetId) {
            const target = await client.target(targetId, signal);
            const job = await client.targetJob(targetId, signal);
            if (
              !request.signal.aborted &&
              id === serial.current &&
              controller.generation() === epoch
            ) {
              latestView.current = { ...latestView.current, target, job };
              setView((current) => ({ ...current, target, job }));
            }
            // The controller serializes observations per peer. Parallel
            // remote reads would contend with each other, not improve speed.
            const policy = await client.targetPolicy(targetId, signal);
            const options = {
              after: cursor,
              limit: locateUserId && search?.q === locateUserId ? 1 : 25,
              include_deleted: includeDeleted,
            };
            const page = search
              ? await client.targetUserSearch(
                  targetId,
                  { ...options, ...search },
                  signal,
                )
              : await client.targetUsers(targetId, options, signal);
            if (policy.saved_revision !== page.revision)
              throw new ApiError(
                "server",
                search ? "user_search_changed" : "policy_conflict",
                409,
              );
            return { policy, page, target, remote: policy, owner: null, job };
          }
          const { policy, page, owner } = await readLocalUserView(
            client,
            {
              after: cursor,
              limit: locateUserId && search?.q === locateUserId ? 1 : 25,
              include_deleted: includeDeleted,
            },
            search,
            signal,
          );
          return {
            policy,
            page,
            target: null,
            remote: null,
            owner,
            job: null,
          };
        },
        request.signal,
      )
      .then((result) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          controller.generation() === epoch
        ) {
          latestView.current = { ...result, loading: false };
          setView(latestView.current);
          setNeedsRemoteRefresh(false);
          const current = attemptRef.current;
          if (current && current.outcome !== "unknown") {
            const matches = sameScope(
              current.scope,
              operationScope(result.target, result.remote, result.owner),
            );
            const ticket =
              matches &&
              current.ticket &&
              !terminal(current.ticket) &&
              sameTicket(current.ticket, result.job)
                ? result.job
                : current.ticket;
            const finished = current.local
              ? current.local.state !== "reserved"
              : ticket !== null && terminal(ticket);
            // Equal read revisions can still trail an already acknowledged write.
            const reachedKnownProgress =
              BigInt(result.policy.saved_revision) >=
                BigInt(
                  current.local?.saved_revision ??
                    ticket?.policy_revision ??
                    current.context.revision,
                ) &&
              (!ticket ||
                (result.remote !== null &&
                  BigInt(result.remote.last_terminal_command) >=
                    BigInt(ticket.command_id)));
            rememberAttempt({
              ...current,
              ticket,
              outcome: finished
                ? current.local?.state === "rejected"
                  ? "rejected"
                  : "terminal"
                : current.outcome,
              fresh:
                matches &&
                reachedKnownProgress &&
                (current.outcome === "rejected" || finished),
              scopeChanged: !matches,
            });
          }
        }
        if (
          !request.signal.aborted &&
          id === serial.current &&
          controller.generation() === epoch
        ) {
          setRefreshTick((value) => value + 1);
          return result;
        }
        return undefined;
      })
      .catch((failure) => {
        if (
          !request.signal.aborted &&
          id === serial.current &&
          controller.generation() === epoch
        ) {
          const error = apiError(failure);
          setError(error);
          if (
            search &&
            error.kind === "server" &&
            ((error.status === 409 && error.code === "user_search_changed") ||
              (error.status === 400 &&
                error.code === "invalid_user_search_cursor"))
          )
            setSearchNeedsRestart(true);
          latestView.current = {
            ...latestView.current,
            policy: null,
            page: null,
            loading: false,
          };
          setView(latestView.current);
        }
      });
  }, [
    controller,
    session,
    state.busy,
    epoch,
    cursor,
    includeDeleted,
    targetId,
    search,
    searchNeedsRestart,
    locateUserId,
    rememberAttempt,
  ]);
  useEffect(() => {
    if (crossEpoch.current !== epoch) {
      crossEpoch.current = epoch;
      crossTrigger.current = null;
      setPendingCrossFocus(null);
      setCrossPhase("closed");
      setLocationCancelled(false);
      locateFocus.current = false;
      if (locateUserId !== null) {
        setLocateUserId(null);
        setSearch(null);
        setCursors([undefined]);
        return;
      }
    }
    load();
    return () => {
      serial.current++;
      read.current?.abort();
    };
  }, [load, epoch, locateUserId, setCrossPhase]);
  useEffect(() => {
    setSecret(null);
    setForm(null);
    closeConfirmation();
    setSelected(null);
    setDelivery(null);
    setRoutingUser(null);
    setPresetUser(null);
    setRoutingResult(null);
    setLocalOperationsOpen(false);
    localOperationsTrigger.current = null;
    setOperationReadBusy(false);
    rememberAttempt(null);
    observeCredentials(null);
    return () => {
      confirmationRef.current = null;
      localOperationsTrigger.current = null;
      write.current?.abort();
      operationRead.current?.abort();
      operationRead.current = null;
    };
  }, [
    epoch,
    rememberAttempt,
    closeConfirmation,
    observeCredentials,
    setCrossPhase,
  ]);

  useEffect(() => {
    if (
      crossPhase === "locating" &&
      !view.loading &&
      (view.page !== null || error !== null)
    )
      setCrossPhase("closed");
    if (
      crossPhase === "closed" &&
      locateFocus.current &&
      locateUserId &&
      !view.loading &&
      view.page !== null
    ) {
      locateFocus.current = false;
      locateNotice.current?.focus();
    }
  }, [crossPhase, view.loading, view.page, error, locateUserId, setCrossPhase]);

  const mutate = async (
    work: MutationWork,
    context: OperationContext,
    deliverCreatedUser = false,
  ): Promise<boolean> => {
    if (
      !session ||
      crossPhaseRef.current !== "closed" ||
      latestView.current.loading ||
      state.busy ||
      commandBusy ||
      operationReadBusy ||
      routingBusy ||
      write.current ||
      attemptRef.current
    )
      return false;
    if (!scope || !revision || disabled) return false;
    const request = new AbortController();
    write.current = request;
    const generation = controller.generation();
    setBusy(true);
    setSecret(null);
    setDelivery(null);
    const capturedScope = operationScope(view.target, view.remote, view.owner);
    const capturedReadSerial = serial.current;
    // Pick metadata explicitly: confirmations also contain the old work closure.
    const capturedContext: OperationContext = {
      title: context.title,
      subject: context.subject ? { ...context.subject } : null,
      revision: context.revision,
      secretExpected: !!context.secretExpected,
    };
    let local: UserOperation | null = null;
    let executeSent = false;
    const localUserChange = scope.kind === "local" && context.userChange;
    try {
      if (localUserChange) {
        if (capturedScope.controllerEpoch === null)
          throw new ApiError("format");
        const input = userOperationInput({
          expected_revision: capturedContext.revision,
          expected_epoch: capturedScope.controllerEpoch,
          change: localUserChange,
        });
        const result = await controller.resource(
          session,
          async (client, csrf, signal) => {
            local = await client.reserveUserOperation(input, csrf, signal);
            if (
              request.signal.aborted ||
              signal.aborted ||
              controller.generation() !== generation ||
              serial.current !== capturedReadSerial ||
              write.current !== request
            )
              throw new DOMException("Aborted", "AbortError");
            executeSent = true;
            return client.executeUserOperation(local.id, input, csrf, signal);
          },
          request.signal,
        );
        if (request.signal.aborted || controller.generation() !== generation)
          return false;
        local = result;
        rememberAttempt({
          context: capturedContext,
          scope: capturedScope,
          outcome: result.state === "saved" ? "terminal" : "rejected",
          error: null,
          ticket: null,
          local: result,
          preparationFailed: false,
          fresh: false,
          scopeChanged: false,
          secretMissing: false,
        });
        setForm(null);
        closeConfirmation();
        let deliveryReadFailed = false;
        if (deliverCreatedUser && result.state === "saved" && result.user_id) {
          try {
            const page = await controller.resource(
              session,
              (client, _csrf, signal) =>
                client.userSearch(
                  { mode: "id", q: result.user_id!, limit: 1 },
                  signal,
                ),
              request.signal,
            );
            if (
              !request.signal.aborted &&
              controller.generation() === generation
            ) {
              const user = page.items[0];
              if (
                !user ||
                user.id !== result.user_id ||
                user.deleted ||
                BigInt(page.revision) < BigInt(result.saved_revision!)
              )
                throw new ApiError("format");
              setDelivery({
                user,
                revision: page.revision,
                epoch: generation,
                scope: capturedScope,
              });
              setSelected(user);
              setRoutingUser(null);
              setPresetUser(null);
            }
          } catch (failure) {
            // A follow-up read cannot undo the already known saved receipt.
            if (
              !request.signal.aborted &&
              controller.generation() === generation
            ) {
              deliveryReadFailed = true;
              setError(apiError(failure));
            }
          }
        }
        if (!deliveryReadFailed) load();
        return result.state === "saved";
      }
      const result = await controller.resource(
        session,
        (client, csrf, signal) =>
          work(proxyOperations(client, scope), csrf, signal),
        request.signal,
      );
      if (request.signal.aborted || controller.generation() !== generation)
        return false;
      const secretMissing = !!context.secretExpected && !result.secret;
      if (result.secret && result.credential) {
        setSecret({
          value: result.secret,
          login: result.credential.login,
          epoch: generation,
          credential: result.credential,
          user:
            result.user?.id === result.credential.user_id ? result.user : null,
        });
        // The page refresh must not remount a background credential reader
        // against the same peer while the one-time connection form reads it.
        setSelected(null);
        setDelivery(null);
      }
      if (deliverCreatedUser) {
        const created = createdUserDelivery(result);
        setDelivery(
          created
            ? { ...created, epoch: generation, scope: capturedScope }
            : null,
        );
        setSelected(created?.user ?? null);
        if (created) {
          setRoutingUser(null);
          setPresetUser(null);
        }
      }
      // The fulfilled promise must not retain a second reference to a secret.
      result.secret = null;
      if (result.submission) {
        rememberAttempt({
          context: capturedContext,
          scope: capturedScope,
          outcome: terminal(result.submission.job) ? "terminal" : "pending",
          error: null,
          ticket: result.submission.job,
          local: null,
          preparationFailed: false,
          fresh: false,
          scopeChanged: false,
          secretMissing,
        });
        setNeedsRemoteRefresh(true);
        setView((current) => ({ ...current, job: result.submission!.job }));
      }
      setForm(null);
      closeConfirmation();
      // A 202 may still own the peer's command claim. Do not immediately issue
      // a conflicting remote read or imply that a saved intent has finished.
      if (!result.submission || result.submission.response) load();
      return true;
    } catch (failure) {
      if (!request.signal.aborted && controller.generation() === generation) {
        const error = apiError(failure);
        rememberAttempt({
          context: capturedContext,
          scope: capturedScope,
          outcome: localUserChange
            ? executeSent
              ? "unknown"
              : "rejected"
            : rejectedBeforeMutation(error)
              ? "rejected"
              : "unknown",
          error,
          ticket: null,
          local,
          preparationFailed: !!localUserChange && !executeSent,
          fresh: false,
          scopeChanged: false,
          secretMissing: !!context.secretExpected,
        });
        // Discard stale form/confirmation closures; a read never replays them.
        setForm(null);
        closeConfirmation();
      }
      return false;
    } finally {
      if (write.current === request) {
        write.current = null;
        setBusy(false);
      }
    }
  };
  const revision = view.page?.revision;
  const scope: ProxyScope | null = !targetId
    ? { kind: "local" }
    : view.target && view.remote
      ? { kind: "target", target: view.target, policy: view.remote }
      : null;
  // The controller checks remote ownership against its own node identity,
  // never against this browser administrator's unrelated identity.
  const remoteBlocked =
    !!targetId &&
    (!view.target?.active ||
      view.target.retired ||
      view.target.rollback_detected ||
      view.job?.state === "pending" ||
      view.job?.state === "blocked");
  const access = scopeAccess(
    scope,
    view.owner,
    busy ||
      crossPhase !== "closed" ||
      operationReadBusy ||
      routingBusy ||
      commandBusy ||
      state.busy ||
      view.loading ||
      !revision ||
      !!error ||
      remoteBlocked ||
      needsRemoteRefresh,
  );
  const disabled = access.writeDisabled || attempt !== null;
  const canContinueCreation = () => {
    const current = attemptRef.current;
    const observed = credentialObservationRef.current;
    const latest = latestView.current;
    return (
      targetId === null &&
      current?.outcome === "terminal" &&
      current.local?.state === "saved" &&
      current.local.action === "create_user" &&
      current.fresh &&
      !current.scopeChanged &&
      !!selected &&
      current.local.user_id === selected.id &&
      delivery?.user.id === selected.id &&
      delivery.epoch === controller.generation() &&
      delivery.revision === latest.policy?.saved_revision &&
      delivery.revision === latest.page?.revision &&
      sameScope(delivery.scope, current.scope) &&
      sameScope(
        current.scope,
        operationScope(latest.target, latest.remote, latest.owner),
      ) &&
      observed?.userId === selected.id &&
      !observed.loading &&
      observed.revision === delivery.revision &&
      !latest.loading
    );
  };
  const confirm = (operation: Confirmation, trigger: HTMLElement) => {
    // This explicit next step acknowledges only the freshly observed, saved
    // creation of this user. Opening its review never dispatches a credential.
    const continuing =
      canContinueCreation() &&
      operation.title === "users.createCredential" &&
      operation.subject.kind === "user" &&
      operation.subject.id === selected?.id &&
      operation.user.id === selected?.id &&
      operation.revision === delivery?.revision &&
      operation.credentialSequence ===
        credentialObservationRef.current?.sequence;
    if (
      access.writeDisabled ||
      (attemptRef.current !== null && !continuing) ||
      crossPhaseRef.current !== "closed" ||
      latestView.current.loading ||
      confirmationRef.current ||
      operationRead.current ||
      commandBusyRef.current ||
      write.current
    )
      return;
    const node: ReviewedConfirmation["node"] =
      targetId && view.target
        ? {
            kind: "target",
            id: view.target.node_id,
            name: view.target.name,
            origin: view.target.origin,
          }
        : { kind: "local", origin: globalThis.location?.origin ?? null };
    const reviewed: ReviewedConfirmation = {
      ...operation,
      trigger,
      subject: { ...operation.subject },
      user: { ...operation.user, protocols: [...operation.user.protocols] },
      credential: operation.credential
        ? { ...operation.credential }
        : undefined,
      epoch,
      scope: operationScope(view.target, view.remote, view.owner),
      readSerial: serial.current,
      credentialReadToken: credentialReadToken.current,
      node,
    };
    if (continuing) rememberAttempt(null);
    confirmationRef.current = reviewed;
    setConfirmation(reviewed);
  };
  const reviewMatches = (reviewed: ReviewedConfirmation): boolean => {
    const observed = credentialObservationRef.current;
    const user =
      view.page?.items.find((item) => item.id === reviewed.user.id) ??
      (delivery?.user.id === reviewed.user.id &&
      delivery.epoch === reviewed.epoch &&
      delivery.revision === reviewed.revision &&
      sameScope(delivery.scope, reviewed.scope) &&
      sameScope(
        delivery.scope,
        operationScope(view.target, view.remote, view.owner),
      )
        ? delivery.user
        : undefined);
    return (
      confirmationRef.current === reviewed &&
      reviewed.epoch === controller.generation() &&
      reviewed.readSerial === serial.current &&
      reviewed.credentialReadToken === credentialReadToken.current &&
      reviewed.revision === revision &&
      reviewed.revision === view.policy?.saved_revision &&
      sameScope(
        reviewed.scope,
        operationScope(view.target, view.remote, view.owner),
      ) &&
      (reviewed.node.kind === "target"
        ? targetId === reviewed.node.id &&
          view.target?.name === reviewed.node.name &&
          view.target.origin === reviewed.node.origin
        : targetId === null &&
          reviewed.node.origin === (globalThis.location?.origin ?? null)) &&
      !!user &&
      user.name === reviewed.user.name &&
      user.revision === reviewed.user.revision &&
      user.active === reviewed.user.active &&
      user.deleted === reviewed.user.deleted &&
      !user.deleted &&
      (reviewed.credentialSequence === undefined ||
        (observed !== null &&
          !observed.loading &&
          observed.userId === user.id &&
          observed.sequence === reviewed.credentialSequence &&
          observed.revision === reviewed.revision)) &&
      (!reviewed.credential ||
        (reviewed.credential.user_id === user.id &&
          !reviewed.credential.revoked))
    );
  };
  const reviewBlocked =
    confirmation !== null &&
    (!reviewMatches(confirmation) ||
      disabled ||
      !!credentialObservation?.loading);
  const submitConfirmation = (reviewed: ReviewedConfirmation) => {
    if (
      !reviewMatches(reviewed) ||
      disabled ||
      credentialObservationRef.current?.loading ||
      write.current
    )
      return;
    void mutate(reviewed.work, reviewed);
  };
  const cancelConfirmation = (reviewed: ReviewedConfirmation) => {
    if (confirmationRef.current !== reviewed || busy || write.current) return;
    closeConfirmation();
    setPendingCancelFocus({
      epoch: reviewed.epoch,
      targetId: reviewed.scope.nodeId,
      userId: reviewed.user.id,
      region:
        reviewed.credentialSequence === undefined ? "users" : "credentials",
      trigger: reviewed.trigger,
    });
  };
  const returnLocalOperationsFocus = (
    closedRegion: HTMLElement | null = null,
  ) => {
    if (localOperationsOpen) return;
    const trigger = localOperationsTrigger.current;
    localOperationsTrigger.current = null;
    if (
      !trigger ||
      trigger.epoch !== controller.generation() ||
      targetId !== null ||
      state.phase !== "authenticated" ||
      !session ||
      state.busy ||
      !trigger.element.isConnected ||
      trigger.element.disabled ||
      trigger.element.getAttribute("aria-disabled") === "true"
    )
      return;
    const active = trigger.element.ownerDocument.activeElement;
    if (
      active === trigger.element.ownerDocument.body ||
      (active !== null && closedRegion?.contains(active))
    )
      trigger.element.focus();
  };
  const reviewLatest = () => {
    if (
      crossPhaseRef.current !== "closed" ||
      operationReadBusy ||
      operationRead.current
    )
      return;
    setForm(null);
    closeConfirmation();
    setRefreshTick((value) => value + 1);
    if (searchNeedsRestart && search) {
      setCursors([undefined]);
      setSearchNeedsRestart(false);
      setSearch({ ...search });
    } else load();
  };
  const invalidateListing = () => {
    // A new query invalidates row previews immediately, before the read effect.
    serial.current++;
    read.current?.abort();
    latestView.current = { ...latestView.current, page: null, loading: true };
    setView(latestView.current);
    setSelected(null);
    setDelivery(null);
    setForm(null);
    closeConfirmation();
    setRoutingUser(null);
    setPresetUser(null);
    setPendingCancelFocus(null);
  };
  const installListing = (
    query: UserSearchInput | null,
    deleted: boolean,
    located: string | null = null,
  ) => {
    invalidateListing();
    setCursors([undefined]);
    setIncludeDeleted(deleted);
    setSearchNeedsRestart(false);
    setSearch(query ? { ...query } : null);
    setLocateUserId(located);
    if (located !== null) setSearchResetToken({});
    setLocationCancelled(false);
  };
  const changeListing = (
    query: UserSearchInput | null,
    deleted = includeDeleted,
  ) => {
    if (
      crossPhaseRef.current !== "closed" ||
      busy ||
      routingBusy ||
      commandBusy ||
      state.busy ||
      write.current ||
      operationReadBusy ||
      operationRead.current
    )
      return;
    installListing(query, deleted);
  };
  const openCrossSearch = (element: HTMLButtonElement) => {
    if (
      !session ||
      epoch !== controller.generation() ||
      crossPhaseRef.current !== "closed" ||
      state.busy ||
      busy ||
      routingBusy ||
      commandBusyRef.current ||
      operationRead.current ||
      write.current ||
      latestView.current.loading ||
      credentialObservationRef.current?.loading ||
      overlayOpening.current ||
      attemptRef.current ||
      selected ||
      form ||
      confirmationRef.current ||
      secret ||
      routingUser ||
      presetUser ||
      localOperationsOpen ||
      localOperationsTrigger.current
    )
      return;
    crossTrigger.current = { element, epoch };
    setCrossPhase("open");
  };
  const locateUser = (value: UserLocation) => {
    if (
      crossPhaseRef.current !== "open" ||
      epoch !== controller.generation() ||
      state.busy ||
      write.current ||
      operationRead.current ||
      attemptRef.current ||
      !canonicalId(value.userId) ||
      (value.targetId !== null && !canonicalId(value.targetId))
    )
      return;
    if (value.targetId === targetId) {
      setCrossPhase("locating");
      locateFocus.current = true;
      installListing(
        { mode: "id", q: value.userId },
        value.includeDeleted,
        value.userId,
      );
    } else {
      // The old page remains locked until navigation actually unmounts it.
      // React batching and a void navigate result are not commit confirmation.
      setCrossPhase("navigating");
      const navigationSerial = serial.current;
      const failed = (failure: unknown) => {
        if (
          controller.generation() === epoch &&
          serial.current === navigationSerial &&
          crossPhaseRef.current === "navigating"
        ) {
          setError(apiError(failure));
          setPendingCrossFocus(crossTrigger.current);
          setCrossPhase("closed");
        }
      };
      try {
        void Promise.resolve(locateElsewhere(value)).catch(failed);
      } catch (failure) {
        failed(failure);
      }
    }
  };
  const cancelLocating = () => {
    if (crossPhaseRef.current !== "locating") return;
    serial.current++;
    read.current?.abort();
    latestView.current = {
      ...latestView.current,
      policy: null,
      page: null,
      loading: false,
    };
    setView(latestView.current);
    locateFocus.current = false;
    setLocationCancelled(true);
    setCrossPhase("closed");
  };
  const turnPage = (next: boolean) => {
    if (
      crossPhaseRef.current !== "closed" ||
      view.loading ||
      busy ||
      routingBusy ||
      commandBusy ||
      state.busy ||
      write.current ||
      operationReadBusy ||
      operationRead.current ||
      searchNeedsRestart ||
      error ||
      (next ? !view.page?.next_cursor : cursors.length <= 1)
    )
      return;
    const after = view.page?.next_cursor;
    invalidateListing();
    setCursors((value) => (next ? [...value, after!] : value.slice(0, -1)));
  };
  const observeJob = (job: Job | null) => {
    latestView.current = { ...latestView.current, job };
    setView((current) => ({ ...current, job }));
    const current = attemptRef.current;
    if (
      current?.ticket &&
      sameTicket(current.ticket, job) &&
      sameScope(
        current.scope,
        operationScope(view.target, view.remote, view.owner),
      )
    ) {
      // A current ticket can confirm only its own ID, never an unacknowledged write.
      const ticket = terminal(current.ticket) ? current.ticket : job!;
      rememberAttempt({
        ...current,
        ticket,
        outcome: terminal(ticket) ? "terminal" : "pending",
        fresh: false,
      });
    }
  };
  const inspectLocalOperation = (operation: UserOperation) => {
    const current = attemptRef.current;
    const known = current?.local;
    if (
      targetId !== null ||
      !current ||
      !known ||
      known.id !== operation.id ||
      known.node_id !== operation.node_id ||
      known.sequence !== operation.sequence ||
      known.expected_revision !== operation.expected_revision ||
      known.expected_epoch !== operation.expected_epoch ||
      known.action !== operation.action ||
      (known.action !== "create_user" && known.user_id !== operation.user_id) ||
      (known.state === "saved" && known.user_id !== operation.user_id)
    )
      return;
    // A previously confirmed terminal record never regresses to Reserved.
    const observed = known.state === "reserved" ? operation : known;
    const finished = observed.state !== "reserved";
    rememberAttempt({
      ...current,
      local: observed,
      outcome: finished
        ? observed.state === "saved"
          ? "terminal"
          : "rejected"
        : current.outcome,
      error: finished ? null : current.error,
      preparationFailed: current.preparationFailed && !finished,
      fresh: false,
      scopeChanged: !sameScope(
        current.scope,
        operationScope(view.target, view.remote, view.owner),
      ),
    });
  };
  const checkLocalOperation = async () => {
    const current = attemptRef.current;
    if (
      crossPhaseRef.current !== "closed" ||
      !session ||
      targetId !== null ||
      !current?.local ||
      busy ||
      state.busy ||
      operationRead.current ||
      write.current
    )
      return;
    const request = new AbortController();
    operationRead.current = request;
    const generation = controller.generation();
    setOperationReadBusy(true);
    setError(null);
    try {
      const operation = await controller.resource(
        session,
        (client, _csrf, signal) =>
          client.userOperation(current.local!.id, signal),
        request.signal,
      );
      if (
        !request.signal.aborted &&
        controller.generation() === generation &&
        attemptRef.current === current
      )
        inspectLocalOperation(operation);
    } catch (failure) {
      if (
        !request.signal.aborted &&
        controller.generation() === generation &&
        attemptRef.current === current
      )
        setError(apiError(failure));
    } finally {
      if (operationRead.current === request) {
        operationRead.current = null;
        setOperationReadBusy(false);
      }
    }
  };
  const readSavedUser = async () => {
    const current = attemptRef.current;
    const operation = current?.local;
    if (
      crossPhaseRef.current !== "closed" ||
      !session ||
      targetId !== null ||
      !current ||
      operation?.state !== "saved" ||
      operation.action !== "create_user" ||
      !operation.user_id ||
      !operation.saved_revision ||
      busy ||
      state.busy ||
      operationRead.current ||
      write.current
    )
      return;
    const userId = operation.user_id;
    const savedRevision = operation.saved_revision;
    const request = new AbortController();
    operationRead.current = request;
    const generation = controller.generation();
    const readSerial = serial.current;
    setOperationReadBusy(true);
    setError(null);
    try {
      const page = await controller.resource(
        session,
        (client, _csrf, signal) =>
          client.userSearch({ mode: "id", q: userId, limit: 1 }, signal),
        request.signal,
      );
      if (
        request.signal.aborted ||
        controller.generation() !== generation ||
        attemptRef.current !== current ||
        serial.current !== readSerial
      )
        return;
      const user = page.items[0];
      if (
        !user ||
        user.id !== userId ||
        user.deleted ||
        BigInt(page.revision) < BigInt(savedRevision)
      )
        throw new ApiError("format");
      setDelivery({
        user,
        revision: page.revision,
        epoch: generation,
        scope: current.scope,
      });
      setSelected(user);
      setRoutingUser(null);
      setPresetUser(null);
      load();
    } catch (failure) {
      if (
        !request.signal.aborted &&
        controller.generation() === generation &&
        attemptRef.current === current &&
        serial.current === readSerial
      )
        setError(apiError(failure));
    } finally {
      if (operationRead.current === request) {
        operationRead.current = null;
        setOperationReadBusy(false);
      }
    }
  };
  const readCreatedUser = async (expected: PolicyJob) => {
    if (
      crossPhaseRef.current !== "closed" ||
      !session ||
      !targetId ||
      !view.target ||
      !view.remote ||
      busy ||
      state.busy ||
      commandBusy ||
      routingBusy ||
      view.loading ||
      commandBusyRef.current ||
      credentialObservationRef.current?.loading ||
      operationRead.current ||
      write.current ||
      expected.user_creation !== true ||
      expected.routing ||
      expected.preset ||
      expected.state === "rejected" ||
      expected.state === "superseded" ||
      !sameTicket(expected, view.job)
    )
      return;
    const request = new AbortController();
    operationRead.current = request;
    const generation = controller.generation();
    const readSerial = serial.current;
    const capturedScope = operationScope(view.target, view.remote, view.owner);
    const current = (atSerial: number) =>
      !request.signal.aborted &&
      operationRead.current === request &&
      controller.generation() === generation &&
      serial.current === atSerial &&
      sameTicket(expected, latestView.current.job) &&
      latestView.current.job?.user_creation === true &&
      latestView.current.job.state !== "rejected" &&
      latestView.current.job.state !== "superseded" &&
      sameScope(
        capturedScope,
        operationScope(
          latestView.current.target,
          latestView.current.remote,
          latestView.current.owner,
        ),
      );
    setOperationReadBusy(true);
    setError(null);
    setDelivery(null);
    setSelected(null);
    try {
      const { result, page } = await controller.resource(
        session,
        async (client, csrf, signal) => {
          const result = await client.targetUserResult(
            targetId,
            expected,
            csrf,
            signal,
          );
          if (!current(readSerial))
            throw new DOMException("Aborted", "AbortError");
          const page = await client.targetUserSearch(
            targetId,
            { mode: "id", q: result.user_id, limit: 1 },
            signal,
          );
          return { result, page };
        },
        request.signal,
      );
      if (!current(readSerial)) return;
      const user = page.items[0];
      if (!user || user.deleted)
        throw new ApiError("server", "resource_not_found", 404);
      if (
        user.id !== result.user_id ||
        !result.job.policy_revision ||
        BigInt(page.revision) < BigInt(result.job.policy_revision)
      )
        throw new ApiError("format");
      // This may update only an already-bound attempt. An unknown submission
      // without a ticket stays unknown even when the latest job is inspected.
      observeJob(result.job);
      const refreshing = load();
      const refreshedSerial = serial.current;
      const refreshed = await refreshing;
      if (
        !refreshed ||
        !current(refreshedSerial) ||
        !sameScope(
          capturedScope,
          operationScope(refreshed.target, refreshed.remote, refreshed.owner),
        ) ||
        !sameTicket(expected, refreshed.job) ||
        refreshed.job?.user_creation !== true ||
        refreshed.job.state === "rejected" ||
        refreshed.job.state === "superseded"
      )
        return;
      // Opening the drawer starts its own remote read. Wait for the ordinary
      // policy/page refresh first, so these reads do not contend for one peer.
      setDelivery({
        user,
        revision: page.revision,
        epoch: generation,
        scope: capturedScope,
      });
      setSelected(user);
      setRoutingUser(null);
      setPresetUser(null);
    } catch (failure) {
      if (
        !request.signal.aborted &&
        operationRead.current === request &&
        controller.generation() === generation &&
        serial.current === readSerial
      )
        setError(apiError(failure));
    } finally {
      if (operationRead.current === request) {
        operationRead.current = null;
        setOperationReadBusy(false);
      }
    }
  };
  const beginNewOperation = () => {
    const current = attemptRef.current;
    if (
      crossPhaseRef.current !== "closed" ||
      !current?.fresh ||
      current.outcome === "unknown" ||
      current.outcome === "pending" ||
      error ||
      view.loading ||
      busy ||
      commandBusy ||
      operationReadBusy ||
      !sameScope(
        current.scope,
        operationScope(view.target, view.remote, view.owner),
      )
    )
      return;
    rememberAttempt(null);
  };
  const mutationNotice = attempt ? (
    <Alert
      type={
        attempt.outcome === "unknown" ||
        attempt.outcome === "rejected" ||
        attempt.ticket?.state === "rejected"
          ? "error"
          : "warning"
      }
      showIcon
      title={
        <Space wrap>
          <Typography.Text>{t(attempt.context.title)}</Typography.Text>
          <Typography.Text strong>
            {t(
              attempt.preparationFailed
                ? "users.operationPreparationFailed"
                : attempt.local?.state === "saved"
                  ? "users.operationSaved"
                  : attempt.outcome === "unknown"
                    ? "users.operationUnknown"
                    : attempt.outcome === "rejected" ||
                        attempt.ticket?.state === "rejected"
                      ? "users.operationRejected"
                      : attempt.outcome === "pending"
                        ? "users.operationPending"
                        : "users.operationFinished",
            )}
          </Typography.Text>
        </Space>
      }
      description={
        <Space orientation="vertical" size={8}>
          {attempt.error && (
            <Typography.Text>{t(errorMessage(attempt.error))}</Typography.Text>
          )}
          {attempt.local?.rejection && (
            <Typography.Text>
              {t(errorMessage(new ApiError("server", attempt.local.rejection)))}
            </Typography.Text>
          )}
          {attempt.local?.state === "saved" && (
            <Typography.Text>{t("users.historySavedHint")}</Typography.Text>
          )}
          <Typography.Text>
            {t(
              attempt.preparationFailed
                ? "users.operationPreparationHint"
                : attempt.outcome === "unknown"
                  ? "users.operationUnknownHint"
                  : attempt.outcome === "pending"
                    ? "users.operationPendingHint"
                    : attempt.fresh
                      ? "users.operationReviewedHint"
                      : "users.operationReadHint",
            )}
          </Typography.Text>
          {attempt.scope.nodeId &&
            !attempt.ticket &&
            attempt.outcome === "unknown" && (
              <Typography.Text>{t("users.recentTaskNotProof")}</Typography.Text>
            )}
          {attempt.ticket && (
            <Tag>{t(`control.job.${attempt.ticket.state}`)}</Tag>
          )}
          {attempt.ticket && !sameTicket(attempt.ticket, view.job) && (
            <Typography.Text>{t("users.operationTaskChanged")}</Typography.Text>
          )}
          {attempt.ticket?.state === "superseded" && (
            <Typography.Text>
              {t("users.supersededNotRollback")}
            </Typography.Text>
          )}
          {attempt.scopeChanged && (
            <Typography.Text>
              {t("users.operationScopeChanged")}
            </Typography.Text>
          )}
          {attempt.secretMissing &&
            attempt.outcome !== "rejected" &&
            attempt.ticket?.state !== "rejected" && (
              <Typography.Text>
                {t("users.operationSecretMissing")}
              </Typography.Text>
            )}
          <Collapse
            size="small"
            items={[
              {
                key: "details",
                label: t("users.operationDetails"),
                children: (
                  <Space orientation="vertical" size={4}>
                    <Typography.Text className="managed-identifier">
                      {attempt.scope.nodeId
                        ? t("users.operationOnNode", {
                            id: attempt.scope.nodeId,
                            revision: attempt.context.revision,
                          })
                        : t("users.operationOnLocal", {
                            revision: attempt.context.revision,
                          })}
                    </Typography.Text>
                    {attempt.context.subject && (
                      <Typography.Text className="managed-identifier">
                        {t(
                          attempt.context.subject.kind === "user"
                            ? "users.operationUser"
                            : "users.operationCredential",
                          { id: attempt.context.subject.id },
                        )}
                      </Typography.Text>
                    )}
                    {attempt.ticket && (
                      <Typography.Text className="managed-identifier">
                        {t("control.jobId")}: {attempt.ticket.job_id}
                      </Typography.Text>
                    )}
                    {attempt.local && (
                      <Typography.Text className="managed-identifier">
                        {t("users.operationId")}: {attempt.local.id}
                      </Typography.Text>
                    )}
                  </Space>
                ),
              },
            ]}
          />
          <Space wrap>
            {attempt.local?.state === "saved" &&
              attempt.local.action === "create_user" && (
                <Button
                  loading={operationReadBusy}
                  disabled={
                    busy || state.busy || operationReadBusy || view.loading
                  }
                  onClick={() => void readSavedUser()}
                >
                  {t("users.readSavedUser")}
                </Button>
              )}
            {attempt.local && (
              <Button
                loading={operationReadBusy}
                disabled={busy || state.busy || operationReadBusy}
                onClick={() => void checkLocalOperation()}
              >
                {t("users.checkOperation")}
              </Button>
            )}
            <Button
              disabled={
                busy ||
                commandBusy ||
                state.busy ||
                view.loading ||
                operationReadBusy
              }
              onClick={reviewLatest}
            >
              {t("users.readLatest")}
            </Button>
            {attempt.error?.code === "invalid_csrf" && (
              <Button
                disabled={state.busy}
                onClick={() => void controller.check()}
              >
                {t("users.checkSession")}
              </Button>
            )}
            {attempt.scope.nodeId && (
              <Button
                disabled={busy || state.busy}
                onClick={() => {
                  if (!targetId) return;
                  // The drawer must unmount before focus can leave its trap.
                  setSelected(null);
                  setPendingTaskFocus({ epoch, targetId });
                }}
              >
                {t(
                  attempt.ticket && sameTicket(attempt.ticket, view.job)
                    ? "users.viewExactTask"
                    : "users.readRecentTask",
                )}
              </Button>
            )}
            {attempt.fresh &&
              attempt.outcome !== "unknown" &&
              attempt.outcome !== "pending" && (
                <Button
                  disabled={
                    busy ||
                    commandBusy ||
                    state.busy ||
                    view.loading ||
                    operationReadBusy ||
                    !!error
                  }
                  onClick={beginNewOperation}
                >
                  {t("users.reviewNewOperation")}
                </Button>
              )}
          </Space>
        </Space>
      }
    />
  ) : null;
  const readNotice = error ? (
    <Alert
      type="error"
      showIcon
      title={t(errorMessage(error))}
      description={t(
        search &&
          error.kind === "server" &&
          error.status === 502 &&
          error.code === "user_search_unsupported"
          ? "users.searchUnsupportedHint"
          : searchNeedsRestart
            ? "users.searchChangedHint"
            : "users.readFailedHint",
      )}
      action={
        <Button
          disabled={
            busy ||
            commandBusy ||
            state.busy ||
            view.loading ||
            operationReadBusy
          }
          onClick={reviewLatest}
        >
          {t("users.readAgain")}
        </Button>
      }
    />
  ) : null;
  const workflowNotice = (
    <>
      {mutationNotice}
      {readNotice}
    </>
  );
  const columns: ColumnsType<ProxyUser> = [
    {
      title: t("users.name"),
      dataIndex: "name",
      render: (name: string, user) => (
        <Space orientation="vertical" size={0}>
          <Typography.Text strong>{name}</Typography.Text>
          <Typography.Text type="secondary" className="managed-identifier">
            {user.id}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: t("users.state"),
      render: (_, user) => (
        <Tag color={user.deleted ? "red" : user.active ? "green" : "default"}>
          {t(
            user.deleted
              ? "users.deleted"
              : user.active
                ? "users.enabled"
                : "users.disabled",
          )}
        </Tag>
      ),
    },
    {
      title: t("users.protocols"),
      render: (_, user) =>
        user.protocols.length
          ? user.protocols.map((protocol) => (
              <Tag key={protocol}>
                {protocol === "http" ? "HTTP / HTTPS" : protocol.toUpperCase()}
              </Tag>
            ))
          : t("users.noProtocols"),
    },
    { title: t("users.limit"), dataIndex: "concurrent_limit" },
    { title: t("users.userRevision"), dataIndex: "revision" },
    {
      title: t("users.actions"),
      render: (_, user) => (
        <Space wrap>
          <Link to={trafficHref({ kind: "user", id: user.id }, targetId)}>
            {t("traffic.open")}
          </Link>
          <Button
            size="small"
            disabled={access.readDisabled}
            onClick={() => {
              if (
                crossPhaseRef.current !== "closed" ||
                operationRead.current ||
                latestView.current.loading
              )
                return;
              overlayOpening.current = true;
              setRoutingUser(null);
              setPresetUser(null);
              setDelivery(null);
              setSelected(user);
            }}
          >
            {t("users.credentials")}
          </Button>
          <Button
            size="small"
            disabled={access.readDisabled}
            onClick={() => {
              if (
                crossPhaseRef.current !== "closed" ||
                operationRead.current ||
                latestView.current.loading
              )
                return;
              overlayOpening.current = true;
              setSelected(null);
              setPresetUser(null);
              setRoutingUser(user);
            }}
          >
            {t("resources.permission")}
          </Button>
          <Button
            size="small"
            disabled={access.readDisabled}
            onClick={() => {
              if (
                crossPhaseRef.current !== "closed" ||
                operationRead.current ||
                latestView.current.loading
              )
                return;
              overlayOpening.current = true;
              setSelected(null);
              setRoutingUser(null);
              setPresetUser(user);
            }}
          >
            {t("presets.title")}
          </Button>
          <Button
            size="small"
            disabled={disabled || user.deleted}
            onClick={() => {
              if (
                crossPhaseRef.current !== "closed" ||
                latestView.current.loading
              )
                return;
              overlayOpening.current = true;
              setForm({
                user,
                revision: revision!,
                epoch,
                readSerial: serial.current,
              });
            }}
          >
            {t("users.edit")}
          </Button>
          <Button
            size="small"
            disabled={disabled || user.deleted}
            onClick={(event) =>
              confirm(
                {
                  title: user.active ? "users.disable" : "users.enable",
                  detail: "users.disableHint",
                  subject: { kind: "user", id: user.id },
                  revision: revision!,
                  user,
                  userChange: {
                    action: "set_user_active",
                    id: user.id,
                    active: !user.active,
                  },
                  work: (client, csrf, signal) =>
                    client.userState(
                      user.id,
                      !user.active,
                      revision!,
                      csrf,
                      signal,
                    ),
                },
                event.currentTarget,
              )
            }
          >
            {t(user.active ? "users.disable" : "users.enable")}
          </Button>
          <Button
            size="small"
            danger
            disabled={disabled || user.deleted}
            onClick={(event) =>
              confirm(
                {
                  title: "users.delete",
                  detail: "users.deleteHint",
                  subject: { kind: "user", id: user.id },
                  revision: revision!,
                  user,
                  danger: true,
                  userChange: { action: "delete_user", id: user.id },
                  work: (client, csrf, signal) =>
                    client.deleteUser(user.id, revision!, csrf, signal),
                },
                event.currentTarget,
              )
            }
          >
            {t("users.delete")}
          </Button>
        </Space>
      ),
    },
  ];
  return (
    <PageContainer
      className="management-page"
      title={t("users.title")}
      content={t("users.description")}
    >
      <section ref={usersRegion} tabIndex={-1} aria-label={t("users.title")}>
        <Space orientation="vertical" size={16} className="full-width">
          <ScopePicker
            value={targetId}
            onChange={(value) => {
              if (crossPhaseRef.current === "closed") changeScope(value);
            }}
            disabled={
              busy ||
              routingBusy ||
              commandBusy ||
              state.busy ||
              crossPhase !== "closed"
            }
            selected={view.target}
          />
          {crossPhase === "navigating" && (
            <Alert type="info" showIcon title={t("users.crossLocating")} />
          )}
          {crossPhase === "locating" && (
            <Alert
              type="info"
              showIcon
              title={t("users.crossLocating")}
              action={
                <Button onClick={cancelLocating}>
                  {t("users.crossLocateCancel")}
                </Button>
              }
            />
          )}
          {!targetId && view.owner?.controller_node_id && (
            <Alert
              type="warning"
              showIcon
              title={t("control.locallyManaged")}
              description={t("control.ownerHint")}
            />
          )}
          {targetId && (
            <Alert
              type="info"
              showIcon
              title={t("control.remoteScope")}
              description={t("control.grantRequired")}
            />
          )}
          {needsRemoteRefresh && !attempt && (
            <Alert
              type="warning"
              showIcon
              title={t("control.reviewBeforeEdit")}
              action={
                <Button onClick={reviewLatest}>{t("users.readLatest")}</Button>
              }
            />
          )}
          {routingResult?.submission && (
            <Alert
              showIcon
              type={
                routingResult.submission.response?.receipt.status === "rejected"
                  ? "error"
                  : "warning"
              }
              title={t(
                routingResult.submission.response?.receipt.status === "rejected"
                  ? "control.rejected"
                  : routingResult.submission.response
                    ? "control.receiptReceived"
                    : "control.intentSaved",
              )}
              description={t("control.ticketHint")}
            />
          )}
          {targetId && (
            <section
              ref={taskPanel}
              tabIndex={-1}
              aria-label={t("control.command")}
            >
              <CommandPanel
                targetId={targetId}
                job={view.job}
                busy={
                  busy ||
                  crossPhase !== "closed" ||
                  view.loading ||
                  operationReadBusy ||
                  routingBusy ||
                  !!credentialObservation?.loading
                }
                onChange={observeJob}
                onBusy={observeCommandBusy}
                canStart={() =>
                  crossPhaseRef.current === "closed" &&
                  !operationRead.current &&
                  !credentialObservationRef.current?.loading
                }
                onRefresh={reviewLatest}
                onUserResult={(job) => void readCreatedUser(job)}
                userResultBusy={operationReadBusy}
              />
            </section>
          )}
          {view.policy && !view.policy.proxy_running && (
            <Alert
              type="warning"
              showIcon
              title={t("users.proxyNotStarted")}
              description={t("users.proxyNotStartedHint")}
            />
          )}
          {!selected && !form && !confirmation && workflowNotice}
          <ProCard
            title={t("users.proxyState")}
            variant="outlined"
            loading={view.loading && !view.policy}
          >
            {view.policy ? (
              <Space orientation="vertical" className="full-width">
                <Space wrap>
                  <Tag
                    color={
                      !view.policy.proxy_running
                        ? "default"
                        : view.policy.applied_revision === null
                          ? "error"
                          : view.policy.applied_revision !==
                              view.policy.saved_revision
                            ? "warning"
                            : "green"
                    }
                  >
                    {t(
                      view.policy.proxy_running
                        ? view.policy.applied_revision === null
                          ? "users.degraded"
                          : view.policy.applied_revision !==
                              view.policy.saved_revision
                            ? "users.pending"
                            : "users.running"
                        : "users.apiOnly",
                    )}
                  </Tag>
                  {!targetId && !view.policy.proxy_running && (
                    <Link to="/service">{t("service.start")}</Link>
                  )}
                </Space>
                <Collapse
                  size="small"
                  items={[
                    {
                      key: "policy",
                      label: t("users.policy"),
                      children: (
                        <>
                          <Descriptions
                            column={{ xs: 1, sm: 2, lg: 3 }}
                            items={[
                              {
                                key: "saved",
                                label: t("users.savedRevision"),
                                children: view.policy.saved_revision,
                              },
                              {
                                key: "applied",
                                label: t("users.appliedRevision"),
                                children: view.policy.applied_revision ?? "—",
                              },
                              {
                                key: "durable",
                                label: t("users.durableRevision"),
                                children:
                                  view.policy.durable_applied_revision ?? "—",
                              },
                              {
                                key: "users",
                                label: t("users.userCount"),
                                children: view.policy.user_count,
                              },
                              {
                                key: "credentials",
                                label: t("users.credentialCount"),
                                children: view.policy.credential_count,
                              },
                            ]}
                          />
                          <Typography.Paragraph type="secondary">
                            {t("users.revisionHint")}
                          </Typography.Paragraph>
                        </>
                      ),
                    },
                  ]}
                />
              </Space>
            ) : (
              <Typography.Text type="secondary">—</Typography.Text>
            )}
          </ProCard>
          <ProCard
            title={t("users.list")}
            variant="outlined"
            extra={
              <Space wrap>
                <Checkbox
                  checked={includeDeleted}
                  disabled={
                    busy ||
                    routingBusy ||
                    commandBusy ||
                    state.busy ||
                    operationReadBusy
                  }
                  onChange={(event) => {
                    changeListing(search, event.target.checked);
                  }}
                >
                  {t("users.includeDeleted")}
                </Checkbox>
                <Button
                  aria-label={t("users.refresh")}
                  aria-busy={view.loading}
                  loading={view.loading}
                  disabled={
                    busy ||
                    commandBusy ||
                    state.busy ||
                    operationReadBusy ||
                    crossPhase !== "closed"
                  }
                  onClick={() => {
                    if (
                      crossPhaseRef.current !== "closed" ||
                      operationReadBusy ||
                      operationRead.current
                    )
                      return;
                    if (searchNeedsRestart) reviewLatest();
                    else load();
                  }}
                >
                  {t("users.refresh")}
                </Button>
                <Button
                  type="primary"
                  disabled={disabled}
                  onClick={() => {
                    if (
                      crossPhaseRef.current !== "closed" ||
                      latestView.current.loading
                    )
                      return;
                    overlayOpening.current = true;
                    setForm({
                      user: null,
                      revision: revision!,
                      epoch,
                      readSerial: serial.current,
                    });
                  }}
                >
                  {t("users.create")}
                </Button>
                {targetId === null && (
                  <Button
                    disabled={
                      busy ||
                      state.busy ||
                      operationReadBusy ||
                      !!selected ||
                      !!form ||
                      !!confirmation ||
                      !!secret
                    }
                    onClick={(event) => {
                      if (crossPhaseRef.current !== "closed") return;
                      if (!(event.currentTarget instanceof HTMLButtonElement))
                        return;
                      localOperationsTrigger.current = {
                        element: event.currentTarget,
                        epoch: controller.generation(),
                      };
                      setLocalOperationsOpen(true);
                    }}
                  >
                    {t("users.localOperations")}
                  </Button>
                )}
                <Button
                  disabled={
                    crossPhase !== "closed" ||
                    view.loading ||
                    busy ||
                    state.busy ||
                    routingBusy ||
                    commandBusy ||
                    operationReadBusy ||
                    attempt !== null ||
                    !!selected ||
                    !!form ||
                    !!confirmation ||
                    !!secret ||
                    !!routingUser ||
                    !!presetUser ||
                    localOperationsOpen
                  }
                  onClick={(event) => {
                    if (event.currentTarget instanceof HTMLButtonElement)
                      openCrossSearch(event.currentTarget);
                  }}
                >
                  {t("users.crossOpen")}
                </Button>
              </Space>
            }
          >
            {locateUserId &&
              !view.loading &&
              (view.page !== null || locationCancelled) && (
                <div ref={locateNotice} tabIndex={-1}>
                  <Alert
                    showIcon
                    type={
                      view.page?.items.some((user) => user.id === locateUserId)
                        ? "success"
                        : "info"
                    }
                    title={t(
                      locationCancelled
                        ? "users.crossLocationCancelled"
                        : view.page?.items.some(
                              (user) => user.id === locateUserId,
                            )
                          ? "users.crossLocated"
                          : "users.crossMissing",
                    )}
                    description={
                      locationCancelled
                        ? undefined
                        : t("users.crossLocationHint")
                    }
                  />
                </div>
              )}
            <Alert
              type="info"
              showIcon
              title={t("users.admissionHint")}
              className="management-form-notice"
            />
            <UserSearch
              value={search}
              resetToken={searchResetToken}
              disabled={
                crossPhase !== "closed" ||
                busy ||
                routingBusy ||
                commandBusy ||
                state.busy ||
                operationReadBusy
              }
              active={search !== null}
              submit={(query) => changeListing(query)}
              clear={() => changeListing(null)}
            />
            {search && (
              <Typography.Paragraph className="managed-identifier">
                {t("users.searchResults")}:{" "}
                {t(
                  search.mode === "name"
                    ? "users.searchName"
                    : "users.searchId",
                )}{" "}
                · {search.q}
              </Typography.Paragraph>
            )}
            <Table<ProxyUser>
              rowKey="id"
              columns={columns}
              dataSource={view.page?.items ?? []}
              loading={view.loading || state.busy}
              pagination={false}
              scroll={{ x: 1000 }}
              locale={{
                emptyText: view.page ? (
                  <Empty
                    description={t(
                      search ? "users.searchEmpty" : "users.empty",
                    )}
                  />
                ) : (
                  "—"
                ),
              }}
            />
            <Space wrap>
              <Button
                disabled={
                  view.loading ||
                  busy ||
                  operationReadBusy ||
                  searchNeedsRestart ||
                  !!error ||
                  cursors.length <= 1
                }
                onClick={() => turnPage(false)}
              >
                {t("users.previous")}
              </Button>
              <Typography.Text>
                {t("users.page", { page: cursors.length })}
              </Typography.Text>
              <Button
                disabled={
                  view.loading ||
                  busy ||
                  operationReadBusy ||
                  searchNeedsRestart ||
                  !!error ||
                  !view.page?.next_cursor
                }
                onClick={() => turnPage(true)}
              >
                {t("users.next")}
              </Button>
            </Space>
          </ProCard>
        </Space>
      </section>
      {crossPhase === "open" && !state.busy && (
        <CrossNodeSearch
          onClose={() => {
            if (crossPhaseRef.current === "open") {
              setPendingCrossFocus(crossTrigger.current);
              setCrossPhase("closed");
            }
          }}
          onLocate={locateUser}
        />
      )}
      {selected && !secret && !state.busy && scope && !view.loading && (
        <Credentials
          key={selected.id}
          user={
            view.page?.items.find((user) => user.id === selected.id) ?? selected
          }
          refresh={refreshTick}
          createdRevision={
            delivery?.user.id === selected.id ? delivery.revision : undefined
          }
          busy={disabled}
          createBlocked={
            access.writeDisabled || (attempt !== null && !canContinueCreation())
          }
          readBlocked={access.readDisabled}
          close={() => {
            setSelected(null);
            setDelivery(null);
          }}
          confirm={confirm}
          notice={!form && !confirmation ? workflowNotice : null}
          scope={scope}
          onReadBusy={setRoutingBusy}
          onObservation={observeCredentials}
          focusRegion={credentialsRegion}
        />
      )}
      {routingUser && !state.busy && (
        <RoutingPermission
          key={routingUser.id}
          user={
            view.page?.items.find((user) => user.id === routingUser.id) ??
            routingUser
          }
          writeBlocked={disabled}
          peer={targetId}
          close={() => !routingBusy && setRoutingUser(null)}
          onBusy={setRoutingBusy}
          saved={(result) => {
            setRoutingUser(null);
            setRoutingResult(result);
            if (result.submission) {
              setNeedsRemoteRefresh(true);
              setView((current) => ({
                ...current,
                job: result.submission!.job,
              }));
              if (result.submission.response) load();
            } else reviewLatest();
          }}
        />
      )}
      {presetUser && !state.busy && (
        <PresetEditor
          key={presetUser.id}
          entity={{ kind: "user", id: presetUser.id, name: presetUser.name }}
          peer={targetId}
          writeBlocked={disabled || presetUser.deleted}
          close={() => !routingBusy && setPresetUser(null)}
          onBusy={setRoutingBusy}
          saved={(result) => {
            setPresetUser(null);
            setRoutingResult(result);
            if (result.submission) {
              setNeedsRemoteRefresh(true);
              setView((current) => ({
                ...current,
                job: result.submission!.job,
              }));
              if (result.submission.response) load();
            } else reviewLatest();
          }}
        />
      )}
      {form && form.epoch === epoch && !state.busy && (
        <UserForm
          user={form.user}
          busy={busy}
          notice={workflowNotice}
          close={() => !busy && setForm(null)}
          submit={(input) =>
            form.readSerial !== serial.current
              ? Promise.resolve(false)
              : mutate(
                  (client, csrf, signal) =>
                    form.user
                      ? client.updateUser(
                          form.user.id,
                          input,
                          form.revision,
                          csrf,
                          signal,
                        )
                      : client.createUser(input, form.revision, csrf, signal),
                  {
                    title: form.user ? "users.edit" : "users.create",
                    subject: form.user
                      ? { kind: "user", id: form.user.id }
                      : null,
                    revision: form.revision,
                    userChange: form.user
                      ? { ...input, action: "update_user", id: form.user.id }
                      : { ...input, action: "create_user" },
                  },
                  !form.user,
                )
          }
        />
      )}
      {targetId === null && (
        <LocalOperations
          open={localOperationsOpen}
          onClose={() => setLocalOperationsOpen(false)}
          onClosed={returnLocalOperationsFocus}
          onInspect={inspectLocalOperation}
          disabled={busy || state.busy || operationReadBusy}
        />
      )}
      {confirmation && confirmation.epoch === epoch && !state.busy && (
        <Modal
          open
          title={t(confirmation.title)}
          mask={{ closable: false }}
          focusable={{ focusTriggerAfterClose: false }}
          closable={!busy}
          onCancel={() => cancelConfirmation(confirmation)}
          style={{ top: 16, margin: "0 auto", paddingBottom: 0 }}
          styles={{
            body: { maxHeight: "calc(100dvh - 220px)", overflowY: "auto" },
          }}
          afterOpenChange={(open) => {
            if (
              open &&
              confirmationRef.current === confirmation &&
              confirmation.epoch === controller.generation() &&
              !write.current
            )
              cancelReview.current?.focus();
          }}
          footer={
            <Space wrap>
              <Button
                ref={cancelReview}
                autoFocus
                disabled={busy}
                onClick={() => cancelConfirmation(confirmation)}
              >
                {t("users.cancel")}
              </Button>
              <Button
                type="primary"
                danger={confirmation.danger}
                loading={busy}
                disabled={reviewBlocked || busy}
                onClick={() => submitConfirmation(confirmation)}
              >
                {t(confirmation.title)}
              </Button>
            </Space>
          }
        >
          {workflowNotice}
          {reviewBlocked && !busy && (
            <Alert
              type="warning"
              showIcon
              title={t("users.reviewChanged")}
              description={t("users.reviewChangedHint")}
            />
          )}
          <Descriptions
            column={1}
            items={[
              {
                key: "node",
                label: t("users.reviewNode"),
                children: (
                  <Space orientation="vertical" size={0} className="full-width">
                    <Typography.Text strong className="managed-identifier">
                      {confirmation.node.kind === "target"
                        ? confirmation.node.name
                        : t("users.reviewLocalNode")}
                    </Typography.Text>
                    {confirmation.node.kind === "target" && (
                      <Typography.Text code className="managed-identifier">
                        {confirmation.node.id}
                      </Typography.Text>
                    )}
                  </Space>
                ),
              },
              ...(confirmation.node.origin
                ? [
                    {
                      key: "origin",
                      label: t("users.reviewOrigin"),
                      children: (
                        <Typography.Text className="managed-identifier">
                          {confirmation.node.origin}
                        </Typography.Text>
                      ),
                    },
                  ]
                : []),
              {
                key: "user",
                label: t("users.reviewUser"),
                children: (
                  <Space orientation="vertical" size={0} className="full-width">
                    <Typography.Text strong className="managed-identifier">
                      {confirmation.user.name}
                    </Typography.Text>
                    <Typography.Text code className="managed-identifier">
                      {confirmation.user.id}
                    </Typography.Text>
                  </Space>
                ),
              },
              ...(confirmation.credential
                ? [
                    {
                      key: "credential",
                      label: t("users.reviewCredential"),
                      children: (
                        <Space
                          orientation="vertical"
                          size={0}
                          className="full-width"
                        >
                          <Typography.Text code className="managed-identifier">
                            {confirmation.credential.login}
                          </Typography.Text>
                          <Typography.Text code className="managed-identifier">
                            {confirmation.credential.id}
                          </Typography.Text>
                        </Space>
                      ),
                    },
                  ]
                : []),
            ]}
          />
          <Typography.Paragraph>{t(confirmation.detail)}</Typography.Paragraph>
          <Collapse
            size="small"
            items={[
              {
                key: "details",
                label: t("users.operationDetails"),
                children: (
                  <Descriptions
                    column={1}
                    items={[
                      {
                        key: "revision",
                        label: t("users.reviewRevision"),
                        children: confirmation.revision,
                      },
                      ...(confirmation.scope.targetRevision
                        ? [
                            {
                              key: "target",
                              label: t("control.configRevision"),
                              children: confirmation.scope.targetRevision,
                            },
                          ]
                        : []),
                      ...(confirmation.scope.controllerEpoch
                        ? [
                            {
                              key: "epoch",
                              label: t("control.epoch"),
                              children: confirmation.scope.controllerEpoch,
                            },
                          ]
                        : []),
                    ]}
                  />
                ),
              },
            ]}
          />
        </Modal>
      )}
      {secret && secret.epoch === epoch && !state.busy && secret.user && (
        <ConnectionModal
          key={`${secret.credential.id}:${secret.epoch}`}
          user={secret.user}
          credential={secret.credential}
          peer={targetId}
          initialSecret={secret.value}
          close={() => setSecret(null)}
          onBusy={setRoutingBusy}
          readBlocked={view.loading}
        />
      )}
      {secret && secret.epoch === epoch && !state.busy && !secret.user && (
        <Modal
          open
          title={t("users.secretTitle")}
          footer={
            <Button type="primary" onClick={() => setSecret(null)}>
              {t("users.secretClose")}
            </Button>
          }
          onCancel={() => setSecret(null)}
          maskClosable={false}
          destroyOnHidden
        >
          <Alert type="warning" showIcon title={t("users.secretWarning")} />
          <Descriptions
            column={1}
            className="managed-secret"
            items={[
              {
                key: "login",
                label: t("users.login"),
                children: (
                  <Typography.Text code className="managed-identifier">
                    {secret.login}
                  </Typography.Text>
                ),
              },
              {
                key: "secret",
                label: t("users.secret"),
                children: (
                  <Typography.Text code className="managed-identifier">
                    {secret.value}
                  </Typography.Text>
                ),
              },
            ]}
          />
        </Modal>
      )}
    </PageContainer>
  );
}

function ScopedUsersPage({ targetId }: { targetId: string | null }) {
  const { controller } = useManagement();
  const location = useLocation();
  // Umi's Router omits navigationType, so Router's hook reports POP on pushes.
  const navigationType = history.action;
  const selectScope = useScopeNavigation();
  const epoch = controller.generation();
  const [handoff, setHandoff] = useState<UserHandoff | null>(null);
  // Consume only after a location commits. POP and unrelated navigation cannot
  // carry a user selection into another scope, and history cannot replay it.
  useEffect(() => {
    if (
      handoff &&
      (handoff.epoch !== epoch || location.key !== handoff.sourceKey)
    )
      setHandoff((current) => (current === handoff ? null : current));
  }, [handoff, epoch, location.key]);
  const initialLocation =
    handoff &&
    handoff.epoch === epoch &&
    handoff.value.targetId === targetId &&
    location.key !== handoff.sourceKey &&
    location.pathname + location.search === handoff.href &&
    navigationType === "PUSH"
      ? handoff.value
      : null;
  return (
    <ManagementGate>
      <Users
        key={targetId ?? "local"}
        targetId={targetId}
        initialLocation={initialLocation}
        changeScope={(target) => selectScope(scopeHref("/users", target))}
        locateElsewhere={(value) => {
          const href = scopeHref("/users", value.targetId);
          const intent = {
            value,
            epoch: controller.generation(),
            sourceKey: location.key,
            href,
          };
          setHandoff(intent);
          const discard = () =>
            setHandoff((current) => (current === intent ? null : current));
          try {
            return Promise.resolve(selectScope(href)).catch((failure) => {
              discard();
              throw failure;
            });
          } catch (failure) {
            discard();
            throw failure;
          }
        }}
      />
    </ManagementGate>
  );
}

export default function UsersPage() {
  const { t } = useMessages();
  const location = useLocation();
  let targetId: string | null;
  try {
    targetId = scopeLocation(location);
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
    <ScopedUsersPage targetId={targetId} />
  );
}
