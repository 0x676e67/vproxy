export default {
  "menu.resources": "IP 资源",
  "resources.title": "IP 资源",
  "resources.description": "管理所选节点的有限出口地址与共享地址池。",
  "resources.localOnly": "仅限本机节点",
  "resources.remoteScope": "所选目标的资源",
  "resources.remoteScopeHint":
    "登记不等于控制授权，子节点必须明确授予本控制节点 owner。读取失败或版本不支持时，不会回退操作本机资源。",
  "resources.remoteWriteHint":
    "写入需要 IPAM v2、子节点当前 owner 授权、目标处于启用状态且没有未决命令；检查回执后需刷新当前策略。",
  "resources.remoteIntentHint":
    "已保存的意图仍可能执行，不要换新命令重复创建。请查看持久任务并刷新当前策略；资源 ID 可从任务恢复，但不会重建历史实体。",
  "resources.upgradeTarget":
    "目标不支持 IPAM v2，请先升级；本页保持只读，不会回退操作本机资源。",
  "resources.inventoryHint":
    "登记不会配置网卡或路由，也不证明地址所有权或健康；具体源地址必须已能在本机使用。",
  "resources.prefixes": "前缀",
  "resources.addresses": "地址",
  "resources.lookupTitle": "按 ID 查找地址",
  "resources.lookupId": "地址资源 ID",
  "resources.lookupSubmit": "查找地址",
  "resources.lookupOpen": "查看该地址",
  "resources.lookupBrowse": "查看地址列表",
  "resources.lookupReading": "正在读取该地址的目录记录…",
  "resources.lookupCancelled": "已取消读取，当前不显示地址记录。",
  "resources.lookupTargetFailed": "无法核实所选节点，尚未读取地址。",
  "resources.lookupUnsupported": "该节点不支持按 ID 读取地址。",
  "resources.lookupNotFound": "所选节点未返回该 ID 的地址记录。",
  "resources.lookupFailed": "地址读取失败，请重新读取以确认当前记录。",
  "resources.lookupReadOnly":
    "地址目录记录，仅供查看；如需修改，请进入地址列表重新读取。",
  "resources.pools": "共享地址池",
  "resources.name": "名称",
  "resources.id": "资源 ID",
  "resources.cidr": "规范 CIDR",
  "resources.ip": "源 IP",
  "resources.prefixId": "前缀 ID（可选）",
  "resources.family": "地址族",
  "resources.members": "成员",
  "resources.memberCount": "已登记成员数",
  "resources.revision": "资源版本",
  "resources.globalRevision": "全局策略版本",
  "resources.health": "健康状况",
  "resources.healthHint":
    "资源清单不是健康快照，具体证据请查看健康观测；“启用”仅表示可参与选择，不代表网络可达。",
  "resources.register": "登记",
  "resources.details": "详情",
  "resources.retire": "永久退役",
  "resources.drain": "排空",
  "resources.resume": "恢复选择",
  "resources.active": "启用",
  "resources.draining": "排空中",
  "resources.retired": "已退役",
  "resources.registered": "已登记",
  "resources.retireHint":
    "退役不可恢复并保留资源身份，只停止有限 exit / pool 的新选择，不中断现有流或修改主机路由；旧版 CIDR 路由仍可能派生到同一 IP。前缀中的地址必须全部先退役。",
  "resources.drainHint":
    "排空可逆，只停止有限 exit / pool 的新选择；不会修改主机 IP / 路由，也不会从旧版 CIDR 路由中排除同一 IP。现有流保留原出口，恢复选择不代表已验证健康。",
  "resources.prefixHint":
    "使用 192.0.2.0/24 或 2001:db8::/64 等规范网络；前缀仅记录资源，不会展开枚举所有地址。",
  "resources.addressHint":
    "登记单个具体 IP；填写前缀后，服务器会核验其归属。可从前缀详情复制资源 ID。",
  "resources.poolHint":
    "地址池是有限、共享且同地址族的集合，只使用显式登记的成员；不提供独享分配或全球健康保证。",
  "resources.cidrRule": "请输入带前缀长度的 IP 网络，规范格式由服务器核验。",
  "resources.ipRule": "请输入单个 IPv4 或 IPv6 地址，不含端口或作用域标识。",
  "resources.idRule": "请输入规范的 22 位资源 ID，不能使用原始 IP。",
  "resources.addMember": "添加地址",
  "resources.removeMember": "移除成员",
  "resources.memberHint":
    "成员必须是同地址族的地址 ID；本页按游标分页，不会加载整个池。",
  "resources.removeHint": "从共享池中移除此地址，对新流生效，不会断开现有流。",
  "resources.selector": "用户名选择器后缀",
  "resources.selectorHint":
    "在机器登录名后只追加一个 -exit-<token> 或 -pool-<token>；token 是稳定 ID 的 16 字节所对应的 32 位小写十六进制，不是原始 IP，也不能叠加 session 选择器。",
  "resources.saved":
    "已保存全局版本 {revision}。变更仅影响新流；保存不代表健康，也不保证代理正在运行。",
  "resources.permissionTitle": "路由授权 — {name}",
  "resources.permission": "路由授权",
  "resources.permissionHint":
    "仅授权所选节点明确登记的地址和池；读取失败或未知时不会自动开放路由。变更仅对新流生效，不更改现有连接。",
  "resources.legacyAllowed": "允许旧版 / 默认路由",
  "resources.legacyHint":
    "允许本机原有 CIDR、session、range 路由，即使有限资源已排空或退役，仍可能派生到同一 IP。需要严格限定显式资源的用户必须关闭此权限；它不会授权其他用户的显式资源。",
  "resources.exitsGrant": "允许的地址 ID",
  "resources.poolsGrant": "允许的池 ID",
  "resources.grantsHint":
    "每项最多 32 个不重复的规范 ID，可从 IP 资源复制；不能填写选择器 token 或原始 IP。",
  "resources.grantRule": "每项最多填写 32 个不重复的规范资源 ID。",
  "resources.denyAllHint":
    "当前已关闭旧版 / 默认路由，也未授权地址或地址池；这会拒绝该用户所有新的路由请求，现有流仍继续使用原出口。",
  "resources.permissionUnknown":
    "路由权限未知，请成功刷新后再编辑；不会默认授予兼容路由。",
  "resources.remoteUnsupported":
    "C3 v1 的 IP 资源权限仅支持本机，请到目标节点自身管理。",
  "resources.observations": "健康观测",
  "resources.observationHint":
    "成功仅代表表中这次本地绑定或指定数值 TCP 目标建连成功；仅绑定不能证明公网、UDP、QUIC 或整个前缀健康。缺失或过期的观测保持未知，检查不会修改路由策略。",
  "resources.snapshotHint":
    "这是手动读取的快照，不是实时健康状态；读取不会触发探测。年龄由节点在读取时报告，是否过期需重新读取。节点每次启动都会生成新的启动 ID，不沿用旧观测。",
  "resources.readLatestSnapshot": "读取最新快照",
  "resources.guidanceTitle": "检查建议",
  "resources.guidance.bindSuccess":
    "本次只确认源 IP 能在本地绑定，未测试公网、UDP 或 QUIC 连通。",
  "resources.guidance.tcpSuccess":
    "本次只确认源 IP 能连到表中的 TCP 目标，未测试其他目标、UDP 或 QUIC。",
  "resources.guidance.unknown":
    "尚无有效结果。先读取最新快照，并查看观测器与目录提示；不要据此判定地址故障。",
  "resources.guidance.address_unavailable":
    "在所选节点核对源 IP 配置与绑定条件。",
  "resources.guidance.connection_refused":
    "核对源 IP 的网络条件；TCP 检查还需核对表中目标的端口、服务与访问规则。本次结果不能定位拒绝发生在哪一端。",
  "resources.guidance.timed_out":
    "核对源 IP 的网络路径与访问规则；TCP 检查还需核对表中目标。超时本身不能确定原因。",
  "resources.guidance.permission_denied":
    "在所选节点核对服务账号与相关网络权限；不要绕过安全校验。",
  "resources.guidance.network_unreachable":
    "在所选节点核对源 IP 与路由；TCP 检查还需核对通往表中目标的路径，不代表其他目标也不可达。",
  "resources.guidance.failed":
    "先读取最新快照；若持续失败，再检查所选节点的服务日志，目前不能确认具体原因。",
  "resources.guidance.family_mismatch":
    "核对源 IP 的地址族；TCP 检查的探测目标需与源 IP 同属 IPv4 或 IPv6。",
  "resources.guidance.cancelled": "取消不能说明地址故障，请读取最新快照。",
  "resources.healthUnavailable":
    "本机健康观测器不可用，不能据此判断网络可达性。",
  "resources.catalogError":
    "最近一次目录读取失败，新探测已暂停；目录时间与年龄仍指最后一次成功读取，不是失败尝试时间。",
  "resources.catalogNotLoaded": "观测器尚未加载资源目录，缺失的观测仍为未知。",
  "resources.restartHint":
    "节点观测进程已重启，快照属于新的启动 ID，不会沿用旧观测。",
  "resources.bootId": "观测器启动 ID",
  "resources.sequence": "观测事件序号",
  "resources.catalogLoaded": "目录已加载",
  "resources.catalogObserved": "最后成功读取目录时间",
  "resources.catalogAge": "读取时目录年龄（ms）",
  "resources.inFlight": "正在执行的检查",
  "resources.retrieved": "快照读取时间",
  "resources.snapshotTitle": "快照 — 读取于 {time}（非实时）",
  "resources.pageSize": "每页地址数",
  "resources.check": "检查类型",
  "resources.bind": "本地绑定",
  "resources.tcp": "TCP 建连",
  "resources.target": "数值目标地址",
  "resources.observed": "观测时间",
  "resources.age": "读取时样本年龄（ms）",
  "resources.latency": "耗时（ms）",
  "resources.unknown": "未知",
  "resources.success": "本次检查成功",
  "resources.address_unavailable": "源地址不可用",
  "resources.connection_refused": "目标拒绝建连",
  "resources.timed_out": "检查超时",
  "resources.permission_denied": "本地权限不足",
  "resources.network_unreachable": "网络不可达",
  "resources.failed": "检查失败",
  "resources.family_mismatch": "地址族不匹配",
  "resources.cancelled": "检查已取消",
  "resources.changePending": "正在提交资源变更",
  "resources.changePendingHint":
    "正在等待回复。离开页面或检查会话不能撤销已保存的变更。",
  "resources.changeWaitingHint":
    "任务已受理。请先核对原任务及当前资源，再开始新的变更。",
  "resources.changeRejectedHint":
    "请求在写入前被拒绝。读取当前状态后，可明确开始新操作。",
  "resources.changeObservationHint":
    "这是当前状态，不会自动确认或重发旧请求。同名资源不能证明是这次创建的结果。",
  "resources.changeNotReady": "当前状态尚不允许新的变更。",
  "resources.changeTicketChanged":
    "当前任务与保留的原任务不同，不能据此确认上次结果。",
  "resources.readChangeState": "读取当前资源状态",
  "resources.changeNewResource": "新资源，ID 尚未确认",
  "resources.changeMemberId": "成员地址 ID",
  "resources.changeMemoryHint":
    "浏览器保留一份不含秘密的核对记录，但不能找回丢失的回复或密码，也不会授权重发请求。",
  "resources.changeRestored": "资源变更需要核对",
  "resources.changeRestoredHint":
    "已恢复浏览器记录。开始新变更前，请先读取当前状态。其中的任务 ID 仅供参考，不能据此重试或终止任务。",
  "resources.changeCapacity": "待核对的节点已达上限，请先处理现有变更。",
};
