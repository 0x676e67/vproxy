import {
  createContext,
  useContext,
  useEffect,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import { ManagementClient } from "../api/client";
import { SessionController, sessionRecheckDelay } from "./session";
import { browserJournal } from "./review-journal";

const Context = createContext<SessionController | null>(null);

export function ManagementProvider({ children }: { children: ReactNode }) {
  const [controller] = useState(
    () => new SessionController(new ManagementClient(), browserJournal),
  );
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  useEffect(() => {
    void controller.check();
    // StrictMode may mount the effect again: cancellation is not permanent disposal.
    return () => controller.cancel();
  }, [controller]);
  useEffect(() => {
    const expected = state.session;
    if (state.phase !== "authenticated" || state.busy || !expected) return;
    const timer = setTimeout(() => {
      if (controller.snapshot().session === expected) void controller.check();
    }, sessionRecheckDelay(expected.expires_at));
    return () => clearTimeout(timer);
  }, [controller, state.phase, state.session, state.busy]);
  return <Context.Provider value={controller}>{children}</Context.Provider>;
}

export function useManagement() {
  const controller = useContext(Context);
  if (!controller) throw new Error("Management provider is missing");
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  return { controller, state };
}
