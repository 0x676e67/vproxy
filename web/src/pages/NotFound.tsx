import { Link, useIntl } from "@umijs/max";
import { Button, Result } from "antd";

export default function NotFound() {
  const intl = useIntl();
  return (
    <Result
      status="404"
      title={intl.formatMessage({ id: "notFound.title" })}
      subTitle={intl.formatMessage({ id: "notFound.description" })}
      extra={
        <Link to="/nodes">
          <Button type="primary">
            {intl.formatMessage({ id: "notFound.back" })}
          </Button>
        </Link>
      }
    />
  );
}
