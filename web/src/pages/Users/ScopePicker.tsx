import { Alert, Button, Select, Space, Typography } from "antd";
import { useEffect, useRef, useState } from "react";
import { apiError, type ApiError } from "../../api/client";
import { errorMessage } from "../../api/messages";
import type { Target, TargetPage } from "../../api/targets";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";

/** Fetch one local registry page, never every remote node or a per-card poll. */
export default function ScopePicker({
  value,
  onChange,
  disabled,
  selected,
}: {
  value: string | null;
  onChange: (id: string | null) => void;
  disabled: boolean;
  selected: Target | null;
}) {
  const { t } = useMessages();
  const { controller, state } = useManagement();
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const [page, setPage] = useState<TargetPage | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const sequence = useRef(0);
  const cursor = cursors.at(-1);
  const epoch = controller.generation();
  useEffect(() => {
    const session = state.session;
    if (!session || state.busy) return;
    const request = new AbortController();
    const id = ++sequence.current;
    setLoading(true);
    setError(null);
    void controller
      .resource(
        session,
        (client, _csrf, signal) =>
          client.targets({ after: cursor, limit: 25 }, signal),
        request.signal,
      )
      .then((result) => {
        if (
          !request.signal.aborted &&
          id === sequence.current &&
          epoch === controller.generation()
        )
          setPage(result);
      })
      .catch((error) => {
        if (
          !request.signal.aborted &&
          id === sequence.current &&
          epoch === controller.generation()
        ) {
          setError(apiError(error));
          setPage(null);
        }
      })
      .finally(() => {
        if (!request.signal.aborted && id === sequence.current)
          setLoading(false);
      });
    return () => {
      sequence.current++;
      request.abort();
    };
  }, [controller, state.session, state.busy, epoch, cursor, refresh]);
  const targets = page?.items ?? [];
  const options = [
    { value: "local", label: t("control.localScope") },
    ...targets.map((target) => ({
      value: target.node_id,
      label: `${target.name} · ${target.node_id}`,
    })),
  ];
  if (value && !targets.some((item) => item.node_id === value))
    options.push({
      value,
      label: selected?.name ? `${selected.name} · ${value}` : value,
    });
  return (
    <Space orientation="vertical" className="full-width">
      <div className="management-scope-bar">
        <Typography.Text strong>{t("control.scope")}</Typography.Text>
        <Select
          className="managed-scope"
          aria-label={t("control.scope")}
          value={value ?? "local"}
          options={options}
          loading={loading}
          disabled={disabled}
          onChange={(id) => onChange(id === "local" ? null : id)}
        />
        {(cursors.length > 1 || page?.next_cursor) && (
          <Space wrap>
            <Button
              disabled={loading || disabled || cursors.length <= 1}
              onClick={() => setCursors((value) => value.slice(0, -1))}
            >
              {t("users.previous")}
            </Button>
            <Button
              disabled={loading || disabled || !page?.next_cursor}
              onClick={() =>
                setCursors((value) => [...value, page!.next_cursor!])
              }
            >
              {t("users.next")}
            </Button>
          </Space>
        )}
      </div>
      {error && (
        <Alert
          type="warning"
          title={t(errorMessage(error))}
          action={
            <Button onClick={() => setRefresh((value) => value + 1)}>
              {t("api.retry")}
            </Button>
          }
        />
      )}
    </Space>
  );
}
