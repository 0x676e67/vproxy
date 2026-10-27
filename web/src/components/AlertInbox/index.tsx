import { BellOutlined } from "@ant-design/icons";
import { Link } from "@umijs/max";
import { Badge } from "antd";
import { useEffect, useState, useSyncExternalStore } from "react";
import type { AlertSummary } from "../../api/alertEvents";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";
import { alertHistoryHref } from "../../routing/scope";

export const ALERT_SUMMARY_POLL_MS = 30_000;
/** One visible, controller-local summary poller. Failures are unknown counts,
 * never zero problems, and no remote inventory or service is contacted. */
export default function AlertInbox() {
  const { controller, state } = useManagement(),
    { t } = useMessages();
  const epoch = controller.generation(),
    session = state.session;
  const notes = useSyncExternalStore(
    controller.alertAcknowledgements.subscribe,
    controller.alertAcknowledgements.snapshot,
  );
  const [view, setView] = useState<{
    epoch: number;
    session: typeof session;
    summary: AlertSummary | null;
  } | null>(null);
  useEffect(() => {
    if (!session || state.phase !== "authenticated" || state.busy) return;
    let disposed = false,
      pending: AbortController | null = null,
      timer: ReturnType<typeof setTimeout> | undefined;
    const visible = () => document.visibilityState !== "hidden";
    const stop = () => {
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
      pending?.abort();
      pending = null;
    };
    const read = async () => {
      if (disposed || !visible() || pending) return;
      const request = new AbortController();
      pending = request;
      const belongs = () =>
        !disposed &&
        !request.signal.aborted &&
        controller.generation() === epoch &&
        controller.snapshot().session === session;
      try {
        const summary = await controller.resource(
          session,
          (client, _csrf, signal) => client.alertSummary(signal),
          request.signal,
        );
        if (belongs()) setView({ epoch, session, summary });
      } catch {
        if (belongs()) setView({ epoch, session, summary: null });
      } finally {
        if (pending === request) pending = null;
        if (belongs() && visible())
          timer = setTimeout(() => {
            timer = undefined;
            void read();
          }, ALERT_SUMMARY_POLL_MS);
      }
    };
    const visibility = () => {
      if (visible()) void read();
      else {
        stop();
        setView({ epoch, session, summary: null });
      }
    };
    document.addEventListener("visibilitychange", visibility);
    void read();
    return () => {
      disposed = true;
      stop();
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [controller, epoch, session, state.phase, state.busy, notes]);
  if (!session || state.phase !== "authenticated") return null;
  const summary =
    view?.epoch === epoch && view.session === session && !state.busy
      ? view.summary
      : null;
  const label = summary
    ? t("alertEvents.badge", { count: summary.unacknowledged_count })
    : t("alertEvents.badgeUnknown");
  return (
    <Link
      to={alertHistoryHref()}
      className="management-header-action"
      aria-label={label}
      title={`${label}. ${t("alertEvents.badgeHint")}`}
    >
      <Badge
        count={summary ? summary.unacknowledged_count : "?"}
        overflowCount={99}
      >
        <span className="management-header-icon">
          <BellOutlined aria-hidden />
        </span>
      </Badge>
    </Link>
  );
}
