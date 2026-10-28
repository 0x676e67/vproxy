import { lazy, Suspense, type ReactNode } from "react";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";
import LanguageSwitch from "../LanguageSwitch";
import ThemeSwitch from "../ThemeSwitch";

// Lazy loading keeps ProForm out of the initial shell chunk.
const ManagementGate = lazy(() => import("../ManagementGate"));

/** Keep navigation unmounted until the session is confirmed, without redirects. */
export default function ManagementShell({ children }: { children: ReactNode }) {
  const { state } = useManagement();
  const { t } = useMessages();
  if (state.phase === "authenticated") return children;

  return (
    <div className="management-auth-shell">
      <header className="management-auth-shell-actions">
        <ThemeSwitch />
        <LanguageSwitch />
      </header>
      <main className="management-auth-shell-content">
        <Suspense
          fallback={
            <div className="management-state" role="status">
              {t("auth.checking")}
            </div>
          }
        >
          <ManagementGate>{null}</ManagementGate>
        </Suspense>
      </main>
    </div>
  );
}
