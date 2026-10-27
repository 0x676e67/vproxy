export default {
  "acme.title": "管理 HTTPS",
  "acme.refresh": "刷新状态",
  "acme.scope":
    "本机进程快照，刷新只读取状态。证书可用不代表浏览器信任或公网可达。",
  "acme.manual": "本进程使用手工配置的证书，未开启自动申请和续期。",
  "acme.stagingWarning": "测试环境签发的证书不受浏览器信任。",
  "acme.environment.staging": "测试环境",
  "acme.environment.production": "生产环境",
  "acme.activity.waiting": "等待下次尝试",
  "acme.activity.working": "正在签发或恢复身份",
  "acme.activity.stopped": "自动证书任务已停止",
  "acme.lastFailure": "上次尝试",
  "acme.failure.attempt_unavailable":
    "上次尝试未正常完成，当前仍可能有可用证书。",
  "acme.failure.review_required": "上次证书处理需要人工检查，请查看本机日志。",
  "acme.certificate": "当前证书",
  "acme.available": "服务器观察时可用",
  "acme.unavailable": "服务器观察时没有可用证书",
  "acme.notActivated": "本进程尚未激活身份",
  "acme.validFrom": "生效时间",
  "acme.validUntil": "到期时间",
  "acme.challenge": "验证方式",
  "acme.nextAttempt": "下次尝试",
  "acme.noSchedule": "当前没有等待执行的计划",
  "acme.due": "已到计划时间，等待后台执行",
  "acme.observed": "读取时的服务器时间",
  "acme.dateRange": "超出日期显示范围",
  "acme.unsupported": "此服务器尚未提供证书状态。",
  "control.scope": "管理范围",
  "control.invalidScope": "管理范围无效",
  "control.invalidScopeHint":
    "链接中的节点或筛选条件无效，或存在重复参数；未请求任何节点数据。请返回节点页，明确选择需要管理的节点。",
  "control.localScope": "本机 · 本地策略",
  "control.remoteScope": "远端节点策略",
  "control.nodesDescription":
    "管理本机和明确登记的目标节点。每个节点独立保存代理策略并运行代理服务。",
  "control.changePending": "正在保存节点配置",
  "control.changePendingHint": "请勿重复提交。离开此页不会撤销已经发出的请求。",
  "control.changeRejectedHint":
    "请求在变更受理前被拒绝。请先读取当前配置，再开始新操作。",
  "control.changeNode": "管理节点",
  "control.changeAction": "已提交的操作",
  "control.changeExpectedRevision": "提交前的目标版本",
  "control.changeExpectedEpoch": "提交前的授权代次",
  "control.changeNewTarget": "新目标节点",
  "control.changeObservationHint":
    "这是另行读取的当前本机配置，不能确认上次请求是否成功，也不证明远端可达。",
  "control.changeMissing": "当前无法查到此目标，但这不证明上次请求从未执行。",
  "control.changeReviewHint":
    "请核对指定目标与控制归属。继续只会关闭旧表单、允许开始新操作，不会重发上次请求或确认其结果。",
  "control.readChangeState": "读取当前节点配置",
  "control.continueChange": "已核对，开始新操作",
  "control.changeMemoryHint":
    "非秘密核对记录会保留在此浏览器中，刷新或同一账户重新登录后仍可查看。它不是服务器回执或重放凭据；清理浏览器数据会移除记录，开始新变更前仍须核对当前配置。",
  "control.changeCapacity":
    "保留的节点变更记录已达上限，旧记录不会被丢弃。请先用原账户在对应节点核对记录，再开始新变更。",
  "control.changeStorageBlocked": "已暂停变更 · 请检查浏览器核对记录存储",
  "control.changeStorage.unsupported":
    "此浏览器无法跨标签页协调已保存的核对记录。仍可读取，但不能提交变更；请使用支持 Web Locks 和本地存储的浏览器。",
  "control.changeStorage.unavailable":
    "浏览器未能保存或移除核对记录。新变更必须先保存记录才会发出；已经发出的请求仍可能执行。仍可读取，请保留现有浏览器数据并检查存储设置。",
  "control.changeStorage.invalid":
    "保存的核对元数据无效或已被替换，变更已禁用。不会重放记录或将其视为回执；请读取当前状态，并保留浏览器数据供检查。",
  "control.changeStorage.capacity":
    "浏览器核对记录已达上限，未确认的记录不会自动删除。请使用原账户在对应节点读取并明确核对已有记录，再开始新变更。",
  "control.changeIdentityPending":
    "仍保留未确认的节点变更记录，但当前本机身份尚未确认。请先刷新，暂不进行新变更。",
  "control.registryNotice": "节点登记、控制授权与代理运行是三种不同的事实。",
  "control.grantRequired":
    "先离线登记双方节点证书，再在子节点明确将策略控制权授予本控制节点的 ID。在此添加目标地址不会授予控制权限。",
  "control.enrollmentRequired":
    "节点 ID 与证书必须已在本机登记。此表单仅保存目标地址，不会信任新证书。",
  "control.addTarget": "添加目标节点",
  "control.editTarget": "配置目标地址",
  "control.nodeId": "已登记的节点 ID",
  "control.idRule": "请输入登记时生成的规范 22 字符节点 ID",
  "control.origin": "节点 mTLS 源地址",
  "control.originHint":
    "使用节点监听地址，而非后台或代理端口。只填写 HTTPS 源地址，不含路径、凭证、查询参数或末尾斜杠。",
  "control.originRule":
    "请输入规范 HTTPS 源地址，例如 https://node.example:9443",
  "control.serverIp": "服务器 IP（登记）",
  "control.serverIpHint":
    "可选填 IPv4/IPv6，留空清除。该值仅保存在本管理端用于展示，不参与连接、证书校验或代理路由，也不能证明公网可达性或代理出口 IP。",
  "control.serverIpRule":
    "请输入不带端口、方括号或网段前缀的 IPv4/IPv6 地址；未指定地址、广播和组播地址不可用。",
  "control.serverIpUnregistered": "未登记",
  "control.egressIp": "代理出口 IP",
  "control.egressUnknown": "动态选择 · 尚未观测",
  "control.egressHint":
    "出口由代理策略、IP 池和会话选择；卡片未执行公网出口探测。服务器登记和本地绑定健康不代表公网出口观测。",
  "control.manageIps": "管理 IP 资源",
  "control.deliveryEnabled": "启用投递配置",
  "control.localOwner": "本机策略控制归属",
  "control.nodeDetails": "节点详情与配置",
  "control.controller": "获授权的控制节点",
  "control.epoch": "控制授权代次",
  "control.ownerHint":
    "授予远端控制权后，本机策略编辑将被阻止。变更归属会推进授权代次，使旧命令序列失效；已有用户和凭证保持不变。",
  "control.grant": "授予控制权",
  "control.grantHint":
    "将策略管理权限授予一个已登记且启用的节点。即使再次授予同一节点也会推进代次，请核对其稳定节点 ID。",
  "control.takeover": "收回本地控制权",
  "control.takeoverHint":
    "撤销当前控制归属并推进代次，旧远控命令将不能继续生效。此操作不会删除用户或终止已有代理连接。",
  "control.locallyManaged": "本机策略已授予远端控制节点，本地编辑已禁用。",
  "control.includeRetired": "包含已退役的目标",
  "control.searchNodes": "查找已登记节点",
  "control.searchInvalid": "搜索内容过长或包含控制字符。",
  "control.searchEmpty": "没有匹配的已登记节点",
  "control.configured": "投递配置已启用",
  "control.paused": "投递已暂停",
  "control.retired": "已退役",
  "control.rollback": "检测到回退 · 已阻止投递",
  "control.pause": "暂停投递",
  "control.resume": "恢复投递",
  "control.reactivate": "重新启用投递",
  "control.reactivateHint":
    "重新启用此目标，保留未确认的原命令及所有观察下限，待处理意图可能恢复投递。此操作不会恢复永久吊销的证书，也不会绕过授权代次或回退检查。",
  "control.retire": "退役目标节点",
  "control.pauseHint":
    "调整后续投递的准入。已在途的命令仍可能执行；暂停不等于取消或回滚，未确认的意图会保留。",
  "control.retireHint":
    "退役本机保存的目标配置并暂停后续投递，保留未确认的意图及所有观察下限。此操作不会取消目标已接受的操作，也不会停止其独立运行的代理。",
  "control.tlsUnavailable":
    "未配置出站节点 TLS。本地目标配置仍可管理，但远端读取与命令投递不可用。",
  "control.configRevision": "目标配置版本",
  "control.observedEpoch": "上次观察到的授权代次",
  "control.observedPolicy": "上次观察到的已保存策略",
  "control.healthUnknown":
    "IP 健康与流量可在资源、流量专页按需读取；此卡片不加载这些指标。",
  "control.targetUnknown":
    "登记配置不代表节点可达或健康。进入用户管理后才会执行受验证的远端读取。",
  "control.manageUsers": "管理代理用户",
  "control.command": "最近一条持久命令",
  "control.readTicket": "读取本地票据",
  "control.readCreatedUser": "查找已创建用户",
  "control.readCreatedUserHint":
    "核对该任务保留的回执，再按确切用户 ID 读取。不会重发命令或恢复密码；回执过期也不代表命令未执行。",
  "control.receiptExpired":
    "回执已不再保留，命令仍可能已执行，请勿自动重新创建。",
  "control.jobUnread": "命令票据信息尚未取得。",
  "control.noJob": "该目标尚无命令票据记录。",
  "control.jobId": "稳定任务 ID",
  "control.sequence": "命令序号",
  "control.attempts": "已记录的重试次数",
  "control.ticketHint":
    "票据是历史元数据，不是健康观察。已保存不等于已应用。刷新只读取目标回执，不会执行变更。",
  "control.refresh": "刷新目标回执",
  "control.retry": "重试同一命令",
  "control.supersede": "结束已失效的旧命令",
  "control.retryHint":
    "请先核对目标状态，再续送原命令 ID 和原始内容。不会创建另一项操作，也不会再次返回密码。",
  "control.supersedeHint":
    "只有受验证的观察证明旧命令序号已被消费，或授权代次已变更，才能结束这项不确定记录。此操作不证明命令已应用；证据不足时服务器会拒绝。",
  "control.intentSaved": "意图已保存 · 仍可能执行",
  "control.reviewBeforeEdit":
    "请先核对命令票据，并刷新受验证的远端策略，再进行下一项变更。",
  "control.secretUnavailable":
    "该意图已保存，之后仍可能执行。本次没有交付密码，回执也不含密码。先确认回执，再到所选当前凭证的连接配置读取已保存密码；没有副本时再主动轮换。不要自动提交替代变更。",
  "control.receiptReceived": "已收到目标回执",
  "control.receiptHint":
    "请核对回执状态：已保存、已应用与拒绝含义不同。重试或回执读取不会返回密码。",
  "control.rejected": "目标已记录终态拒绝",
  "control.denied":
    "节点归属、登记授权或目标配置已不允许此次操作，请核对最新状态。",
  "control.unavailable":
    "节点控制不可用。请检查目标地址、节点 TLS 与持久票据，再决定是否明确重试。",
  "control.timeout": "节点响应超时，但命令仍可能已提交。请先查看持久票据。",
  "control.job.pending": "待确认 · 结果未知",
  "control.job.blocked": "已阻止 · 需人工核对",
  "control.job.saved": "目标已保存 · 尚未确认应用",
  "control.job.applied": "已应用回执 · 历史记录",
  "control.job.rejected": "终态拒绝",
  "control.job.superseded": "旧命令已结束",
};
