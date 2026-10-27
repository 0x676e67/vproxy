export default {
  "runtime.title": "在线连接排空",
  "runtime.read": "读取当前转发状态",
  "runtime.lookup": "读取原排空请求结果",
  "runtime.start": "停止监听并排空连接",
  "runtime.confirm": "确认不可逆排空",
  "runtime.cancel": "取消",
  "runtime.scope":
    "停止代理监听，等待已有连接自然结束，管理服务保持在线。此运行实例无法恢复监听，需要显式重启。",
  "runtime.wait":
    "长时间 UDP 关联、隧道或 keepalive 连接可能一直等待。本页不会强制停止，也不会重发 POST。",
  "runtime.boundary":
    "排空完成表示本机转发驱动及其拥有者已结束，不证明对端收到数据、远端缓冲区为空或流量已结清。租约计数为零也不能证明完成。",
  "runtime.pausedRequired": "请先保存暂停新代理任务的设置，再执行排空。",
  "runtime.restart":
    "此实例已离开服务状态。恢复监听需要显式重启转发；修改已保存准入设置无法恢复这些监听。",
  "runtime.resumeBlocked":
    "尚未确认可继续服务的实例，不能恢复准入。请检查转发状态；已排空实例需要显式重启。",
  "runtime.unavailable": "此节点没有可用的转发实例。",
  "runtime.unsupported": "此节点不支持运行态观测。",
  "runtime.originalUnknown":
    "未找到原运行实例或请求，原结果仍然未知。新实例或当前状态不能认领这个结果，请勿再次提交。",
  "runtime.retained": "已保留原排空请求，请打开对应节点卡片审阅。",
  "runtime.pending": "正在提交本次排空请求……",
  "runtime.unknown":
    "请保留原请求以便审阅。202 只表示已接受，不表示排空完成。请精确查询原请求；刷新当前状态不能证明原结果。",
  "runtime.accepted": "原请求已接受，请读取原结果检查进度。",
  "runtime.original": "原运行实例与请求的观测",
  "runtime.current": "仅为当前状态观测",
  "runtime.runtimeId": "运行实例 ID",
  "runtime.requestId": "原请求 ID",
  "runtime.phase": "转发阶段",
  "runtime.active": "观测准入租约数",
  "runtime.serving": "正在服务",
  "runtime.draining": "正在排空",
  "runtime.drained": "本机排空完成",
  "runtime.interrupted": "排空已中断",
  "runtime.failed": "排空失败",
  "runtime.ownerBlocked":
    "此目标当前不能由本控制器修改，请先重新读取目标与归属状态。",
} as const;
