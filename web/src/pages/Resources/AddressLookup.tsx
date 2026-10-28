import { ProCard } from "@ant-design/pro-components";
import {
  Alert,
  Button,
  Descriptions,
  Input,
  Space,
  Tag,
  Typography,
} from "antd";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { apiError, type ApiError, type SessionView } from "../../api/client";
import { errorMessage } from "../../api/messages";
import { canonicalId } from "../../api/proxy";
import type { AddressView } from "../../api/routing";
import type { Target } from "../../api/targets";
import { useManagement } from "../../auth/context";
import { useMessages } from "../../hooks/useMessages";

export function AddressFinder({
  address,
  blocked,
  onFind,
}: {
  address: string | null;
  blocked: boolean;
  onFind: (id: string) => void;
}) {
  const { t } = useMessages();
  const inputId = useId();
  const [draft, setDraft] = useState(address ?? "");
  const [invalid, setInvalid] = useState(false);
  useEffect(() => {
    setDraft(address ?? "");
    setInvalid(false);
  }, [address]);
  return (
    <form
      aria-label={t("resources.lookupTitle")}
      onSubmit={(event) => {
        event.preventDefault();
        if (blocked) return;
        if (!canonicalId(draft)) {
          setInvalid(true);
          return;
        }
        setInvalid(false);
        onFind(draft);
      }}
    >
      <Space orientation="vertical" size={8} className="full-width">
        <label htmlFor={inputId}>{t("resources.lookupId")}</label>
        <div className="management-filter-bar management-address-search">
          <Input
            id={inputId}
            value={draft}
            maxLength={128}
            autoComplete="off"
            spellCheck={false}
            disabled={blocked}
            aria-invalid={invalid}
            aria-describedby={invalid ? `${inputId}-error` : undefined}
            className="managed-identifier"
            onChange={(event) => {
              setDraft(event.target.value);
              setInvalid(false);
            }}
          />
          <Button htmlType="submit" disabled={blocked}>
            {t("resources.lookupSubmit")}
          </Button>
        </div>
        {invalid && (
          <Typography.Text id={`${inputId}-error`} type="danger" role="alert">
            {t("resources.idRule")}
          </Typography.Text>
        )}
      </Space>
    </form>
  );
}

interface View {
  result: AddressView | null;
  error: ApiError | null;
  stage: "target" | "address";
  loading: boolean;
  cancelled: boolean;
  session: SessionView | null;
  epoch: number;
}

/** One exact directory read. Its result never enters the mutation context. */
export default function AddressLookup({
  peer,
  id,
  onTarget,
  onLoading,
  browse,
}: {
  peer: string | null;
  id: string;
  onTarget: (target: Target | null) => void;
  onLoading: (loading: boolean) => void;
  browse: () => void;
}) {
  const { t } = useMessages();
  const { controller, state } = useManagement();
  const session = state.session;
  const epoch = controller.generation();
  const pending = useRef<AbortController | null>(null);
  const serial = useRef(0);
  const [view, setView] = useState<View>({
    result: null,
    error: null,
    stage: peer === null ? "address" : "target",
    loading: true,
    cancelled: false,
    session,
    epoch,
  });
  const load = useCallback(() => {
    if (
      !session ||
      state.busy ||
      state.phase !== "authenticated" ||
      pending.current
    )
      return;
    const request = new AbortController();
    pending.current = request;
    const sequence = ++serial.current;
    let stage: View["stage"] = peer === null ? "address" : "target";
    const current = () =>
      !request.signal.aborted &&
      sequence === serial.current &&
      controller.generation() === epoch &&
      controller.snapshot().session === session;
    setView({
      result: null,
      error: null,
      stage,
      loading: true,
      cancelled: false,
      session,
      epoch,
    });
    void controller
      .resource(
        session,
        async (client, _csrf, signal) => {
          if (peer === null) return client.routingAddress(id, signal);
          const target = await client.target(peer, signal);
          if (!current()) throw new DOMException("Aborted", "AbortError");
          onTarget(target);
          stage = "address";
          return client.targetRoutingAddress(peer, id, signal);
        },
        request.signal,
      )
      .then((result) => {
        if (current()) {
          pending.current = null;
          setView({
            result,
            error: null,
            stage: "address",
            loading: false,
            cancelled: false,
            session,
            epoch,
          });
        }
      })
      .catch((error) => {
        if (current()) {
          pending.current = null;
          setView({
            result: null,
            error: apiError(error),
            stage,
            loading: false,
            cancelled: false,
            session,
            epoch,
          });
        }
      })
      .finally(() => {
        if (pending.current === request) pending.current = null;
      });
  }, [controller, session, state.busy, state.phase, epoch, peer, id, onTarget]);
  useEffect(() => {
    load();
    return () => {
      serial.current++;
      pending.current?.abort();
      pending.current = null;
    };
  }, [load]);
  const belongs =
    view.session === session && view.epoch === epoch && !state.busy;
  const result = belongs ? view.result : null;
  const error = belongs ? view.error : null;
  const loading = belongs && view.loading;
  useEffect(() => {
    onLoading(loading);
    return () => onLoading(false);
  }, [onLoading, loading]);
  const blocked = state.busy || state.phase !== "authenticated";
  const item = result?.address;
  return (
    <ProCard title={t("resources.addresses")} variant="outlined">
      <Space orientation="vertical" size={16} className="full-width">
        <Typography.Text code copyable className="managed-identifier">
          {id}
        </Typography.Text>
        <Alert
          type="info"
          showIcon
          title={t("resources.lookupReadOnly")}
          description={t("resources.healthHint")}
        />
        {loading && (
          <Typography.Text role="status">
            {t("resources.lookupReading")}
          </Typography.Text>
        )}
        {belongs && view.cancelled && (
          <Alert type="info" showIcon title={t("resources.lookupCancelled")} />
        )}
        {error && (
          <Alert
            type="warning"
            showIcon
            title={t(
              view.stage === "target"
                ? "resources.lookupTargetFailed"
                : error.code === "address_lookup_unsupported"
                  ? "resources.lookupUnsupported"
                  : error.status === 404 && error.code === "resource_not_found"
                    ? "resources.lookupNotFound"
                    : "resources.lookupFailed",
            )}
            description={
              view.stage === "target" ? t(errorMessage(error)) : undefined
            }
          />
        )}
        {result && item && (
          <Descriptions
            column={{ xs: 1, sm: 2 }}
            styles={{ content: { overflowWrap: "anywhere" } }}
            items={[
              {
                key: "node",
                label: t("control.scope"),
                children: peer ?? t("control.localScope"),
              },
              { key: "name", label: t("resources.name"), children: item.name },
              {
                key: "ip",
                label: t("resources.ip"),
                children: (
                  <Typography.Text code copyable>
                    {item.ip}
                  </Typography.Text>
                ),
              },
              {
                key: "prefix",
                label: t("resources.prefixId"),
                children: item.prefix_id ?? "—",
              },
              {
                key: "state",
                label: t("users.state"),
                children: <Tag>{t(`resources.${item.state}`)}</Tag>,
              },
              {
                key: "revision",
                label: t("resources.revision"),
                children: item.revision,
              },
              {
                key: "catalog",
                label: t("resources.globalRevision"),
                children: result.revision,
              },
            ]}
          />
        )}
        <Space wrap>
          <Button
            onClick={load}
            loading={loading}
            disabled={blocked || loading}
          >
            {t("users.refresh")}
          </Button>
          {loading && (
            <Button
              disabled={blocked}
              onClick={() => {
                serial.current++;
                pending.current?.abort();
                pending.current = null;
                setView((current) => ({
                  ...current,
                  result: null,
                  error: null,
                  loading: false,
                  cancelled: true,
                }));
              }}
            >
              {t("users.cancel")}
            </Button>
          )}
          <Button onClick={browse} disabled={blocked}>
            {t("resources.lookupBrowse")}
          </Button>
        </Space>
      </Space>
    </ProCard>
  );
}
