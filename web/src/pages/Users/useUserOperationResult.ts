import { useCallback, useRef, useState } from "react";
import type { ApiError } from "../../api/client";
import type { PolicyStatus } from "../../api/proxy";
import type { Job, Owner, RemotePolicy, Target } from "../../api/targets";
import type { UserChange, UserOperation } from "../../api/userOperations";
import type { MessageKey } from "../../hooks/useMessages";
import type { Confirmation } from "./Credentials";

export interface OperationContext {
  title: MessageKey;
  subject: Confirmation["subject"] | null;
  revision: string;
  secretExpected?: boolean;
  userChange?: UserChange;
}
export interface OperationScope {
  nodeId: string | null;
  targetRevision: string | null;
  controllerNodeId: string | null;
  controllerEpoch: string | null;
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

export function operationScope(
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
export function sameScope(
  left: OperationScope,
  right: OperationScope,
): boolean {
  return (
    left.nodeId === right.nodeId &&
    left.targetRevision === right.targetRevision &&
    left.controllerNodeId === right.controllerNodeId &&
    left.controllerEpoch === right.controllerEpoch
  );
}
export function sameTicket(left: Job, right: Job | null | undefined): boolean {
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
export function terminal(ticket: Job): boolean {
  return ticket.state !== "pending" && ticket.state !== "blocked";
}
/** Only route/body guards prove that a handler never admitted this write. */
export function rejectedBeforeMutation(error: ApiError): boolean {
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

interface Observation {
  policy: PolicyStatus;
  target: Target | null;
  remote: RemotePolicy | null;
  owner: Owner | null;
  job: Job | null;
}

/** Correlate an admitted operation with later observations without replaying it.
 * The page resets this session-bound state alongside its editors and requests.
 * Keep the ref synchronous: a response can arrive before React commits a render. */
export function useUserOperationResult() {
  const [attempt, setAttempt] = useState<OperationAttempt | null>(null);
  const attemptRef = useRef<OperationAttempt | null>(null);
  const rememberAttempt = useCallback((value: OperationAttempt | null) => {
    attemptRef.current = value;
    setAttempt(value);
  }, []);
  const observeListing = useCallback(
    (result: Observation) => {
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
    },
    [rememberAttempt],
  );
  const observeTicket = useCallback(
    (job: Job | null, observedScope: OperationScope) => {
      const current = attemptRef.current;
      if (
        current?.ticket &&
        sameTicket(current.ticket, job) &&
        sameScope(current.scope, observedScope)
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
    },
    [rememberAttempt],
  );
  const observeLocalOperation = useCallback(
    (
      operation: UserOperation,
      targetId: string | null,
      observedScope: OperationScope,
    ) => {
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
        (known.action !== "create_user" &&
          known.user_id !== operation.user_id) ||
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
        scopeChanged: !sameScope(current.scope, observedScope),
      });
    },
    [rememberAttempt],
  );
  return {
    attempt,
    attemptRef,
    rememberAttempt,
    observeListing,
    observeTicket,
    observeLocalOperation,
  };
}
