import { useIntl } from "@umijs/max";
import type messages from "../locales/zh-CN";

export type MessageKey = keyof typeof messages;

/** Shared typed messages keep authentication independent of node components. */
export function useMessages() {
  const intl = useIntl();
  const t = (id: MessageKey, values?: Record<string, string | number>) =>
    intl.formatMessage({ id }, values);
  return { intl, t };
}
