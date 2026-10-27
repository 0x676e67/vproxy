import { Link } from "@umijs/max";
import { Button, Result } from "antd";
import { useMessages } from "../hooks/useMessages";

/** No management workspace mounts for an invalid or ambiguous URL scope. */
export default function ScopeError() {
  const { t } = useMessages();
  return (
    <Result
      status="error"
      title={t("control.invalidScope")}
      subTitle={t("control.invalidScopeHint")}
      extra={
        <Link to="/nodes">
          <Button>{t("menu.nodes")}</Button>
        </Link>
      }
    />
  );
}
