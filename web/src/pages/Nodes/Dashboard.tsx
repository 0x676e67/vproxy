import { PageContainer, ProCard } from "@ant-design/pro-components";
import { CloseCircleFilled, ReloadOutlined } from "@ant-design/icons";
import {
  Alert,
  Button,
  Empty,
  Input,
  Segmented,
  Space,
  Statistic,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { lazy, Suspense, useMemo, useState } from "react";
import {
  filterNodes,
  type ManagedNode,
  needsAttention,
  observedConnections,
} from "../../data/nodes";
import { useNodeLabels } from "./labels";
import NodeCard, { type DetailTab } from "./NodeCard";
import NodeDetails from "./NodeDetails";
import NodeTables from "./NodeTables";

type Filter = "all" | "attention" | "disconnected";

const AddNodeButton = __VPROXY_DEMO__
  ? lazy(() => import("./AddNodeButton"))
  : null;

export default function NodeDashboard({
  nodes,
  onAdd,
  onRefresh,
  refreshing = false,
}: {
  nodes: ManagedNode[];
  onAdd?: (node: ManagedNode) => void;
  onRefresh?: () => void;
  refreshing?: boolean;
}) {
  const { t, number } = useNodeLabels();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [view, setView] = useState<DetailTab>("overview");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detailTab, setDetailTab] = useState<DetailTab>("overview");
  const visible = filterNodes(nodes, query, filter);
  const namesById = useMemo(
    () => new Map(nodes.map((node) => [node.id, node.name])),
    [nodes],
  );
  const parentName = (node: ManagedNode | undefined) =>
    node?.parentId ? (namesById.get(node.parentId) ?? node.parentId) : null;
  const connections = observedConnections(nodes);
  const selected = nodes.find((node) => node.id === selectedId);
  const openDetails = (node: ManagedNode, tab: DetailTab) => {
    setSelectedId(node.id);
    setDetailTab(tab);
  };

  return (
    <PageContainer
      title={
        <Typography.Title level={2} className="page-title">
          {t("nodes.title")}
        </Typography.Title>
      }
      content={t(__VPROXY_DEMO__ ? "nodes.description" : "nodes.liveSummary")}
      tags={
        __VPROXY_DEMO__ ? <Tag color="blue">{t("app.sample")}</Tag> : undefined
      }
      extra={
        __VPROXY_DEMO__ && AddNodeButton && onAdd ? (
          <Suspense fallback={null}>
            <AddNodeButton
              nodes={nodes}
              onAdd={(node) => {
                // A local sample does not create an applied parent-child relationship.
                onAdd(node);
                // Reveal the new sample without stacking a drawer over the submitting modal.
                setQuery(node.id);
                setFilter("all");
                setView("overview");
              }}
            />
          </Suspense>
        ) : (
          <Button
            icon={<ReloadOutlined />}
            loading={refreshing}
            onClick={onRefresh}
          >
            {t("nodes.refresh")}
          </Button>
        )
      }
      tabActiveKey={view}
      onTabChange={(key) => setView(key as DetailTab)}
      tabList={[
        { key: "overview", tab: t("nodes.overview") },
        { key: "health", tab: t("nodes.health") },
        { key: "configuration", tab: t("nodes.configuration") },
      ]}
    >
      <Space orientation="vertical" size={20} className="full-width">
        <Alert
          type="info"
          showIcon
          title={t(__VPROXY_DEMO__ ? "app.sampleNotice" : "nodes.liveNotice")}
          description={t(
            __VPROXY_DEMO__ ? "app.sampleDescription" : "nodes.liveDescription",
          )}
        />
        <ProCard variant="outlined" className="summary-card">
          <div className="node-summary">
            <Statistic
              title={t("nodes.registered")}
              value={nodes.filter((node) => node.control !== "pending").length}
            />
            <Statistic
              title={t(
                __VPROXY_DEMO__
                  ? "nodes.connectedCount"
                  : "nodes.apiReadSuccessCount",
              )}
              value={
                nodes.filter((node) => node.control === "connected").length
              }
            />
            <Statistic
              title={t("nodes.attentionCount")}
              value={nodes.filter(needsAttention).length}
            />
            <Tooltip title={t("nodes.observedOnly")}>
              <Statistic
                title={t("nodes.connectionsTotal")}
                value={connections ?? "—"}
                formatter={(value) =>
                  typeof value === "number" ? number(value) : value
                }
              />
            </Tooltip>
          </div>
        </ProCard>
        <div className="node-toolbar">
          <Segmented<Filter>
            aria-label={t("nodes.filter")}
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: t("nodes.all") },
              { value: "attention", label: t("nodes.attention") },
              { value: "disconnected", label: t("nodes.disconnectedFilter") },
            ]}
          />
          <div className="node-search">
            <Typography.Text type="secondary">
              {t("nodes.count", { count: visible.length })}
            </Typography.Text>
            <Input
              allowClear={{
                clearIcon: (
                  <CloseCircleFilled aria-label={t("nodes.clearSearch")} />
                ),
              }}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={t("nodes.search")}
              aria-label={t("nodes.search")}
              maxLength={80}
            />
          </div>
        </div>
        {view === "overview" ? (
          visible.length > 0 ? (
            <div className="node-grid">
              {visible.map((node) => (
                <NodeCard
                  key={node.id}
                  node={node}
                  parentName={parentName(node)}
                  onOpen={openDetails}
                />
              ))}
            </div>
          ) : (
            <ProCard variant="outlined">
              <Empty
                description={
                  <>
                    <div>{t("nodes.empty")}</div>
                    <Typography.Text type="secondary">
                      {t("nodes.emptyHint")}
                    </Typography.Text>
                  </>
                }
              />
            </ProCard>
          )
        ) : (
          <NodeTables nodes={visible} mode={view} onOpen={openDetails} />
        )}
      </Space>
      <NodeDetails
        node={selected}
        parentName={parentName(selected)}
        tab={detailTab}
        onTab={setDetailTab}
        onClose={() => setSelectedId(null)}
      />
    </PageContainer>
  );
}
