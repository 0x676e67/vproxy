import {
  apiError,
  authenticationRequired,
  ApiError,
  type ManagementClient,
  type SessionView,
} from "../api/client";
import {
  passwordChangeDisposition,
  validCurrentPassword,
  validNewPassword,
  type PasswordChangeNotice,
} from "../api/password";
import { NodeChanges } from "./node-changes";
import { RoutingChanges } from "./routing-changes";
import { AlertAcknowledgements } from "./alert-acknowledgements";
import type { JournalFactory } from "./review-journal";

/** Client time schedules a server check, never an authentication decision. */
export function sessionRecheckDelay(
  expiresAt: number,
  now = Date.now(),
): number {
  const remainingSeconds = expiresAt - now / 1000;
  // A fast/skewed clock must not create an immediate session-check loop.
  return Math.min(8 * 60 * 60, Math.max(60, remainingSeconds)) * 1000;
}

export interface SessionState {
  readonly phase: "checking" | "anonymous" | "authenticated" | "error";
  readonly session: SessionView | null;
  readonly busy: boolean;
  readonly error: ApiError | null;
  readonly passwordChangeNotice?: PasswordChangeNotice;
}

/**
 * One in-memory owner for browser authentication. Every new operation cancels
 * its predecessor; an abort-ignoring transport still cannot commit stale data.
 */
export class SessionController {
  // Authentication stays in memory. Only explicitly selected non-secret change
  // notes use the production browser journal; unit clients may inject no journal.
  readonly nodeChanges: NodeChanges;
  // Resource tabs and pool presets share one non-secret write/review scope.
  readonly routingChanges: RoutingChanges;
  readonly alertAcknowledgements: AlertAcknowledgements;
  private state: SessionState = {
    phase: "checking",
    session: null,
    busy: false,
    error: null,
  };
  private readonly listeners = new Set<() => void>();
  private operation = 0;
  private pending: AbortController | null = null;
  private readonly resources = new Set<AbortController>();

  constructor(
    readonly client: ManagementClient,
    journal?: JournalFactory,
  ) {
    this.nodeChanges = new NodeChanges(journal);
    this.routingChanges = new RoutingChanges(journal);
    this.alertAcknowledgements = new AlertAcknowledgements(journal);
  }

  readonly snapshot = (): SessionState => this.state;
  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private update(state: SessionState): void {
    this.state = state;
    this.listeners.forEach((listener) => listener());
  }

  cancel(): void {
    this.operation += 1;
    this.pending?.abort();
    this.pending = null;
    this.resources.forEach((request) => request.abort());
    this.resources.clear();
  }

  /** A secret/result belongs to this generation, not merely the same username. */
  readonly generation = (): number => this.operation;

  /** Every protected read/write is cancelled by check/login/logout. The final
   * generation check also protects against transports that ignore cancellation. */
  async resource<T>(
    expected: SessionView,
    work: (
      client: ManagementClient,
      csrf: string,
      signal: AbortSignal,
    ) => Promise<T>,
    external?: AbortSignal,
  ): Promise<T> {
    const id = this.operation;
    const abortError = () => new DOMException("Aborted", "AbortError");
    if (
      this.state.phase !== "authenticated" ||
      this.state.busy ||
      this.state.session !== expected ||
      external?.aborted
    )
      throw abortError();
    const pending = new AbortController();
    const abort = () => pending.abort();
    this.resources.add(pending);
    external?.addEventListener("abort", abort, { once: true });
    try {
      const result = await work(
        this.client,
        expected.csrf_token,
        pending.signal,
      );
      if (
        id !== this.operation ||
        this.state.session !== expected ||
        pending.signal.aborted
      )
        throw abortError();
      return result;
    } catch (error) {
      if (
        id !== this.operation ||
        this.state.session !== expected ||
        pending.signal.aborted
      )
        throw abortError();
      if (authenticationRequired(error)) this.authenticationLost(expected);
      throw apiError(error);
    } finally {
      // A composite read can reject before its sibling settles. Keep no work
      // alive after removing this scope from the session's cancellation set.
      pending.abort();
      external?.removeEventListener("abort", abort);
      this.resources.delete(pending);
    }
  }

  private begin(): { id: number; signal: AbortSignal } {
    this.cancel();
    this.pending = new AbortController();
    return { id: this.operation, signal: this.pending.signal };
  }

  async check(): Promise<void> {
    const { id, signal } = this.begin();
    this.update({ phase: "checking", session: null, busy: false, error: null });
    try {
      const session = await this.client.session(signal);
      if (id !== this.operation) return;
      this.update({
        phase: "authenticated",
        session,
        busy: false,
        error: null,
      });
    } catch (error) {
      if (id !== this.operation) return;
      this.update({
        phase: authenticationRequired(error) ? "anonymous" : "error",
        session: null,
        busy: false,
        error: authenticationRequired(error) ? null : apiError(error),
      });
    }
  }

  async login(username: string, password: string): Promise<boolean> {
    const passwordChangeNotice = this.state.passwordChangeNotice;
    const { id, signal } = this.begin();
    this.update({
      phase: "anonymous",
      session: null,
      busy: true,
      error: null,
      passwordChangeNotice,
    });
    try {
      const session = await this.client.login(username, password, signal);
      if (id !== this.operation) return false;
      this.update({
        phase: "authenticated",
        session,
        busy: false,
        error: null,
      });
      return true;
    } catch (error) {
      if (id === this.operation) {
        this.update({
          phase: "anonymous",
          session: null,
          busy: false,
          error: apiError(error),
          passwordChangeNotice,
        });
      }
      return false;
    }
  }

  /** Failure keeps the current view: a lost response is not proven revocation. */
  async logout(): Promise<void> {
    const session = this.state.session;
    if (!session) return;
    const { id, signal } = this.begin();
    this.update({ ...this.state, busy: true, error: null });
    try {
      await this.client.logout(session.csrf_token, signal);
      if (id !== this.operation) return;
      this.update({
        phase: "anonymous",
        session: null,
        busy: false,
        error: null,
      });
    } catch (error) {
      if (id !== this.operation) return;
      if (authenticationRequired(error)) {
        this.update({
          phase: "anonymous",
          session: null,
          busy: false,
          error: null,
        });
      } else {
        this.update({
          phase: "authenticated",
          session,
          busy: false,
          error: apiError(error),
        });
      }
    }
  }

  /** One non-retried mutation, owned by this exact session generation. Lost
   * responses discard the local view, not a claim that server revocation worked. */
  async changePassword(
    expected: SessionView,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    if (
      this.state.session !== expected ||
      this.state.phase !== "authenticated" ||
      this.state.busy
    )
      throw new DOMException("Aborted", "AbortError");
    if (
      !validCurrentPassword(currentPassword) ||
      !validNewPassword(newPassword)
    )
      throw new ApiError("server", "invalid_password_input", 400);
    const { id, signal } = this.begin();
    this.update({
      phase: "authenticated",
      session: expected,
      busy: true,
      error: null,
    });
    try {
      await this.client.changePassword(
        currentPassword,
        newPassword,
        expected.csrf_token,
        signal,
      );
      if (id !== this.operation) return;
      this.update({
        phase: "anonymous",
        session: null,
        busy: false,
        error: null,
        passwordChangeNotice: "changed",
      });
    } catch (error) {
      if (id !== this.operation) return;
      const failure = apiError(error);
      const disposition = passwordChangeDisposition(failure);
      if (disposition === "retain") {
        this.update({
          phase: "authenticated",
          session: expected,
          busy: false,
          error: null,
        });
        throw failure;
      }
      this.update({
        phase: "anonymous",
        session: null,
        busy: false,
        error: null,
        passwordChangeNotice: disposition,
      });
    }
  }

  /** A previous node request must not expire a newly rotated session. */
  authenticationLost(expected: SessionView): void {
    if (this.state.session !== expected) return;
    this.cancel();
    this.update({
      phase: "anonymous",
      session: null,
      busy: false,
      error: null,
    });
  }
}
