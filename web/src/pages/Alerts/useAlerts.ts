import { useCallback, useEffect, useRef, useState } from "react";
import { apiError, type ApiError, type SessionView } from "../../api/client";
import type { AlertOptions, AlertPage } from "../../api/alerts";
import type { NodeAlertPage } from "../../api/nodeAlerts";
import { useManagement } from "../../auth/context";

export const ALERT_POLL_MS = 10_000;
interface View {
  page: AlertPage | NodeAlertPage | null;
  error: ApiError | null;
  loading: boolean;
  received: number | null;
  receivedMonotonic: number | null;
  session: SessionView | null;
  epoch: number;
  peer: string | null;
  observerNode: string | null;
  interrupted: boolean;
}

/** Each visible read finishes before scheduling another. Hiding the page and
 * session changes also invalidate transports that ignore AbortSignal. */
export function useAlerts(options: AlertOptions, peer: string | null = null) {
  const { controller, state } = useManagement();
  const session = state.session;
  const epoch = controller.generation();
  const [refresh, setRefresh] = useState(0);
  const issued = useRef(0);
  const requested = useRef<{
    session: SessionView | null;
    epoch: number;
  } | null>(null);
  const localIdentity = useRef<{
    session: SessionView;
    epoch: number;
    node: string;
  } | null>(null);
  const [paused, setPaused] = useState(
    () => document.visibilityState === "hidden",
  );
  const [view, setView] = useState<View>({
    page: null,
    error: null,
    loading: false,
    received: null,
    receivedMonotonic: null,
    session: null,
    epoch,
    peer,
    observerNode: null,
    interrupted: false,
  });
  useEffect(() => {
    if (peer !== null && refresh === issued.current)
      setView((previous) =>
        previous.loading
          ? { ...previous, loading: false, interrupted: true }
          : previous,
      );
    let disposed = false;
    let serial = 0;
    let pending: AbortController | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let changed = false;
    const visible = () => document.visibilityState !== "hidden";
    const stop = () => {
      serial++;
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
      pending?.abort();
      pending = null;
    };
    const current = (id: number, request: AbortController) =>
      !disposed &&
      !request.signal.aborted &&
      id === serial &&
      controller.generation() === epoch &&
      controller.snapshot().session === session;
    const read = async () => {
      if (
        disposed ||
        pending ||
        changed ||
        !visible() ||
        !session ||
        state.busy ||
        state.phase !== "authenticated"
      )
        return;
      if (
        peer !== null &&
        (refresh === issued.current ||
          requested.current?.session !== session ||
          requested.current.epoch !== epoch)
      )
        return;
      if (peer !== null) issued.current = refresh;
      const request = new AbortController();
      pending = request;
      const id = ++serial;
      setView((previous) => ({
        ...(previous.session === session &&
        previous.epoch === epoch &&
        previous.peer === peer
          ? previous
          : {
              page: null,
              received: null,
              receivedMonotonic: null,
              observerNode: null,
            }),
        loading: true,
        error:
          previous.session === session &&
          previous.epoch === epoch &&
          previous.peer === peer
            ? previous.error
            : null,
        session,
        epoch,
        peer,
        interrupted: false,
      }));
      try {
        const result = await controller.resource(
          session,
          async (client, _csrf, signal) => {
            if (peer === null) {
              // Source kinds may also belong to a foreign node. Cache only the
              // current session's observer identity before constructing links.
              const node =
                localIdentity.current?.session === session &&
                localIdentity.current.epoch === epoch
                  ? localIdentity.current.node
                  : (await client.node(signal)).node_id;
              if (current(id, request))
                localIdentity.current = { session, epoch, node };
              return {
                page: await client.alerts(options, signal),
                observerNode: node,
              };
            }
            // Resolve only the selected local registry entry before contacting it.
            await client.target(peer, signal);
            return {
              page: await client.targetOperationsAlerts(peer, options, signal),
              observerNode: peer,
            };
          },
          request.signal,
        );
        if (current(id, request))
          setView({
            page: result.page,
            observerNode: result.observerNode,
            loading: false,
            error: null,
            received: Date.now(),
            receivedMonotonic: performance.now(),
            session,
            epoch,
            peer,
            interrupted: false,
          });
      } catch (failure) {
        if (current(id, request)) {
          const error = apiError(failure);
          changed = error.status === 409 && error.code === "alerts_changed";
          setView((previous) => ({ ...previous, loading: false, error }));
        }
      } finally {
        if (pending === request) pending = null;
        if (peer === null && current(id, request) && visible() && !changed)
          timer = setTimeout(() => {
            timer = undefined;
            void read();
          }, ALERT_POLL_MS);
      }
    };
    const visibility = () => {
      setPaused(!visible());
      if (visible()) {
        if (peer === null) void read();
      } else {
        const interrupted = peer !== null && pending !== null;
        stop();
        setView((previous) => ({
          ...previous,
          loading: false,
          interrupted: previous.interrupted || interrupted,
        }));
      }
    };
    document.addEventListener("visibilitychange", visibility);
    setPaused(!visible());
    void read();
    return () => {
      disposed = true;
      stop();
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [
    controller,
    session,
    epoch,
    state.busy,
    state.phase,
    options,
    refresh,
    peer,
  ]);
  const reload = useCallback(() => {
    requested.current = { session, epoch };
    setRefresh((value) => value + 1);
  }, [session, epoch]);
  const belongs =
    view.session === session && view.epoch === epoch && view.peer === peer;
  return {
    page: belongs ? view.page : null,
    error: belongs ? view.error : null,
    loading: belongs && view.loading,
    received: belongs ? view.received : null,
    receivedMonotonic: belongs ? view.receivedMonotonic : null,
    interrupted: belongs && view.interrupted,
    observerNode: belongs ? view.observerNode : null,
    paused,
    blocked: state.busy || state.phase !== "authenticated",
    reload,
  };
}
