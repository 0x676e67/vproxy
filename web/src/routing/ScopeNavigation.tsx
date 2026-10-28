import { Link, useIntl, useLocation, useNavigate } from "@umijs/max";
import { useNavigationType } from "react-router-dom";
import { useLayoutEffect, useRef, type ReactNode } from "react";
import { checkedScopeHref, menuScopeHref } from "./scope";

/** New pages start at their heading; query changes and browser Back/Forward
 * retain their own position instead of being treated as a new menu visit. */
export function PageScrollReset({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  const action = useNavigationType();
  const previous = useRef(pathname);
  useLayoutEffect(() => {
    if (previous.current !== pathname && action !== "POP")
      window.scrollTo({ top: 0, left: 0, behavior: "instant" });
    previous.current = pathname;
  }, [pathname, action]);
  return children;
}

/** Use the Router already owned by ProLayout; never create a second context. */
export function ScopeMenuLink({
  path,
  children,
  onNavigate,
  label,
  messageId,
}: {
  path: string | undefined;
  children: ReactNode;
  onNavigate?: () => void;
  label?: string;
  messageId?: string;
}) {
  const intl = useIntl();
  const location = useLocation();
  const href = menuScopeHref(path, location);
  return href === null ? (
    <span aria-disabled="true">{children}</span>
  ) : (
    <Link
      to={href}
      aria-label={
        messageId
          ? intl.formatMessage({ id: messageId, defaultMessage: label })
          : label
      }
      onClick={(event) => {
        if (
          event.button === 0 &&
          !event.metaKey &&
          !event.ctrlKey &&
          !event.shiftKey &&
          !event.altKey
        )
          onNavigate?.();
      }}
    >
      {children}
    </Link>
  );
}

/** Pickers commit to history; back/forward and copied links use the same parser.
 * Only reviewed fixed routes and allowlisted queries can reach navigate.
 */
export function useScopeNavigation() {
  const navigate = useNavigate();
  const location = useLocation();
  return (href: string) => {
    const checked = checkedScopeHref(href);
    if (checked !== location.pathname + location.search)
      return navigate(checked);
  };
}
