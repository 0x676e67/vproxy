import { Link, useLocation, useNavigate } from "@umijs/max";
import type { ReactNode } from "react";
import { checkedScopeHref, menuScopeHref } from "./scope";

/** Use the Router already owned by ProLayout; never create a second context. */
export function ScopeMenuLink({
  path,
  children,
}: {
  path: string | undefined;
  children: ReactNode;
}) {
  const location = useLocation();
  const href = menuScopeHref(path, location);
  return href === null ? (
    <span aria-disabled="true">{children}</span>
  ) : (
    <Link to={href}>{children}</Link>
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
