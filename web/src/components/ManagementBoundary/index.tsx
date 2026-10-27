import { Button, Result } from "antd";
import { Component, type ReactNode } from "react";
import { useMessages } from "../../hooks/useMessages";

function Unavailable() {
  const { t } = useMessages();
  return (
    <div className="management-state" role="alert">
      <Result
        status="error"
        title={t("app.pageUnavailable")}
        subTitle={t("app.pageReloadNotice")}
        extra={
          <Button type="primary" onClick={() => window.location.reload()}>
            {t("app.reloadPage")}
          </Button>
        }
      />
    </div>
  );
}

/** Catch descendant render and lazy-load failures without retaining their data.
 * The session/journal provider stays mounted above this boundary. Only an
 * explicit page reload retries loading; rerenders never remount failed work.
 * API, event-handler and background failures keep their existing error paths.
 */
export default class ManagementBoundary extends Component<
  { children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    return this.state.failed ? <Unavailable /> : this.props.children;
  }
}
