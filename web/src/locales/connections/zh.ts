export default {
  "connections.backToCredentials": "返回凭证列表",
  "connections.settings": "连接设置",
  "connections.preview": "连接预览",
  "connections.previewHint": "选择代理入口后生成连接。",
  "connections.copyPassword": "复制密码",
  "connections.proxyUrl": "代理 URL",
  "connections.examplesPasswordHint":
    "示例含密码，请勿分享。生成代码不代表连接测试通过。",
  "connections.curlReadyHint":
    "使用 PowerShell 7（Windows 上运行 curl.exe）或 POSIX 终端。密码可能留在命令历史中，也可能被本机进程读取。",
  "connections.pythonReadyHint":
    "依赖：{dependency}。将示例保存为私有脚本后用 Python 运行，不会自动安装依赖。",
  "connections.stateChanged": "读到的代理状态不一致，请刷新核对。",
  "connections.openService": "打开代理服务（离开此窗口）",
  "connections.rememberEndpoint":
    "此浏览器会记住有效的连接地址、端口和协议，不保存密码。",
  "connections.rememberFailed":
    "无法在此浏览器保留连接设置，关闭前请自行保存地址。",
  "connections.open": "代理入口",
  "connections.editAddress": "编辑地址",
  "connections.listenerProtocol": "监听协议（只读）",
  "connections.startupAddress": "启动配置地址",
  "connections.selectionMode": "地址来源",
  "connections.mode.inherit": "跟随启动配置",
  "connections.mode.custom": "自定义地址",
  "connections.mode.hidden": "不发布入口",
  "connections.clientHost": "客户端访问主机",
  "connections.clientHostHint":
    "填写域名、IPv4 或 IPv6，不含协议、端口、路径或认证信息。",
  "connections.clientPort": "客户端访问端口",
  "connections.hostRule":
    "请输入有效的域名或可用单播 IP；不能填写 URL、监听通配地址或 IPv6 区域标识。",
  "connections.portRule": "请输入 1 至 65535 的十进制端口，不含前导零。",
  "connections.metadataOnly": "只修改入口地址",
  "connections.metadataOnlyHint":
    "入口地址会保存，重启后保留。监听、出口、证书、路由、端口映射和防火墙不变；保存不会测试连通性。",
  "connections.hiddenHint":
    "此操作只停止生成链接，不会停止代理、断开连接或撤销已分发的地址。",
  "connections.addressPreview": "保存后的地址",
  "connections.notPublished": "不发布地址",
  "connections.previewIncomplete": "填写有效主机和端口后预览",
  "connections.saveDeclaration": "保存入口",
  "connections.readLatest": "读取最新入口",
  "connections.metadataRevision": "入口版本",
  "connections.metadataSaved": "入口已保存",
  "connections.metadataTicketHint":
    "此任务只保存入口地址，不更新代理策略版本。",
  "connections.endpointDetails": "入口说明",
  "connections.connectivityNotTested": "尚未测试连通性",
  "connections.endpointCapacity":
    "覆盖项已达上限。请核对并清除历史覆盖，再修改入口。",
  "connections.declarationSaved": "入口已保存。",
  "connections.remoteSaved": "入口已保存。请读取最新入口。",
  "connections.declarationRejected":
    "入口保存被拒绝。请读取最新入口，再重新核对。",
  "connections.declarationQueued": "任务已记录，请检查结果，勿重复保存。",
  "connections.checkDeclaration": "检查任务",
  "connections.writeUnknown":
    "保存结果未知，请勿重发。先读取最新入口或检查已有任务；核对当前状态后，可明确开始新的修改。关闭窗口不会确认旧结果。",
  "connections.beginNewDeclaration": "开始新的修改",
  "connections.newDeclarationNotice":
    "上次保存结果仍未知。新修改将基于当前入口，不会重发旧请求。",
  "connections.managementUnsupported":
    "此节点仅可读取入口。请先升级软件或迁移管理数据库。",
  "connections.otherCommand":
    "该节点有待确认或阻塞任务。请先检查任务，再修改入口。",
  "connections.metadataTicket": "入口任务",
  "connections.blockedTicket":
    "任务已阻塞，请保留任务 ID 并联系管理员。此页只能检查结果，不能重试、替换任务或再次保存。",
  "connections.detached": "历史覆盖项",
  "connections.detachedHint":
    "以下设置不匹配当前监听器，不是可用入口。只能清除，不能转给其它监听器。",
  "connections.clearDetached": "清除旧设置",
  "connections.clearDetachedHint":
    "清除此旧设置？不会增删或重启监听器，后续匹配的监听器将跟随启动配置。",
  "connections.close": "关闭",
  "connections.reading": "正在读取该节点的代理入口…",
  "connections.endpointHint":
    "入口供代理客户端连接。管理地址、服务器 IP、监听地址和出口 IP 不会替代入口。",
  "connections.observedState": "本次代理状态",
  "connections.notTested": "仅生成配置 · 尚未测试连接",
  "connections.policyObservationHint":
    "策略与入口状态是分次观察的结果，可刷新重新读取。已保存或已应用不代表客户端 DNS、TLS、认证、目标连接或出口 IP 已验证。代理停止时仍可导出配置。",
  "connections.running": "本进程代理运行中",
  "connections.stopped": "本进程无受管代理运行",
  "connections.runningHint":
    "这里只显示本次读取的进程状态，不代表持续健康、客户端可达、认证或目标连接成功。读取最新入口可更新状态。",
  "connections.bind": "节点监听地址",
  "connections.publicAddress": "客户端入口",
  "connections.unconfigured": "未配置客户端入口",
  "connections.noListeners":
    "此节点未配置受管代理监听器。仅运行管理 API 不提供代理入口。",
  "connections.configuredHint": "请另行配置域名证书、端口映射和防火墙。",
  "connections.unconfiguredHint":
    "请由获授权的管理员填写入口，不会用监听地址或管理端口补齐。",
  "connections.withoutCredentials": "链接不含用户名和密码",
  "connections.credentialHint":
    "在该节点的用户凭证中打开连接配置，读取已保存密码并生成认证链接。旧凭证可能没有密码副本。",
  "connections.selectEndpoint": "选择代理入口",
  "connections.endpointChanged":
    "原入口已变化或不再可选。地址已保留，请重新选择入口。",
  "connections.manual": "手动输入入口",
  "connections.advancedRouting": "高级路由…",
  "connections.advancedRoutingHint":
    "只有需要派生地址时才使用。请明确选择规则；展开这里不会替你选择或更换路由。",
  "connections.derivedRoute": "派生路由规则",
  "connections.derivedValue": "派生标识（不含连字符）",
  "connections.ttlValue": "时间桶长度（秒）",
  "connections.exitValue": "已授权出口",
  "connections.poolValue": "已授权地址池",
  "connections.advancedDevice": "高级 TCP 预设",
  "connections.deviceOperationConflict":
    "已选 TCP 预设不适用于当前操作。请选择兼容的 TCP 操作，或明确将预设改为“不指定”；不会自动清除预设。",
  "connections.reviewDevice": "检查 TCP 预设",
  "connections.observationDetails": "策略版本与预设后端详情",
  "connections.readNames": "读取资源名称",
  "connections.resourcesLink": "查看完整 IP 资源（将离开此窗口）",
  "connections.nameNotRead": "名称未读取",
  "connections.namesHint":
    "按需读取每种资源前 50 条；未读取的授权 ID 仍可选。名称、IP、地址族和状态仅供识别，不代表健康、可达或实际出口；生成时仍会重新检查授权。",
  "connections.namesFailed":
    "名称未能按当前策略版本读取，仍显示授权 ID。可刷新授权后重试；不会使用其它节点或旧版本名称替代。",
  "connections.unsupported":
    "该远端节点不支持读取代理入口。请检查并升级目标节点；不会使用本机或其它节点的地址替代。仍可在凭证配置中手动输入已确认的入口。",
  "connections.copyAuthenticatedUrl": "复制代理 URL",
  "connections.clipboardWarning":
    "复制的密码可能被剪贴板历史、同步或其它应用读取。仅在可信设备使用，用后清除剪贴板。",
  "connections.copied": "已复制",
  "connections.copyFailed": "复制失败，请检查浏览器剪贴板权限后重试。",
  "connections.downloadAuthenticatedUrl": "下载代理 URL",
  "connections.downloadWarning":
    "文件含用户名和明文密码，请保存到私有目录，避免共享或同步。重复下载会生成更多副本，本界面无法确认保存位置或文件权限。",
  "connections.downloadRequested": "已请求浏览器下载，请检查文件是否已保存。",
  "connections.downloadFailed":
    "下载请求失败，请检查浏览器设置后重试，无需重新签发凭证。",
  "connections.masqueAuth":
    "MASQUE 使用 HTTPS URI 模板；认证信息需在支持 CONNECT-UDP 的客户端中单独配置，不会写入模板，也不生成 quic:// 链接。",
  "connections.exportUrl": "导出代理 URL",
  "connections.clientExamples": "开发者客户端示例",
  "connections.copyExample": "复制示例代码",
  "connections.examplesHint":
    "示例不包含密码，运行时在你自己的终端输入。目标固定为 https://example.com/，生成示例不代表连接测试成功。",
  "connections.examplesUnsupported":
    "这里的示例仅用于 HTTP/HTTPS CONNECT 和 SOCKS5 CONNECT。普通 HTTP 转发、SOCKS5 BIND、UDP ASSOCIATE 或 MASQUE 需要各自对应的客户端配置。",
  "connections.curlHint":
    "在 PowerShell 7 或 POSIX 交互终端运行（Windows 请使用 curl.exe），随后输入代理密码。命令行不含密码；SOCKS5 由代理端解析目标域名。旧版 PowerShell 的空参数传递不在此示例支持范围内。",
  "connections.pythonHint":
    "需要受支持且已修补的 Requests 与 urllib3（依赖：{dependency}）。请保存为脚本并在可隐藏密码输入的终端运行；不自动安装依赖。",
  "connections.examplesTls":
    "HTTPS 代理要求客户端正常信任代理证书，目标网站证书也会单独验证。私有 CA 需按客户端文档配置，不要关闭 TLS 验证。",
  "connections.unencryptedProxy":
    "HTTP/SOCKS5 不加密代理认证，目标网站的 HTTPS 也不能保护这段认证。请使用可信网络或 HTTPS 代理。",
  "connections.diagnostic": "在本机测试此连接",
  "connections.diagnosticHint":
    "下载已核对的连接配置，再在本机运行 vproxy。浏览器不会连接代理或执行命令。CLI 目标固定为 https://example.com/，会产生真实代理流量，可能计入用量。",
  "connections.diagnosticMetadata":
    "JSON 含代理入口、完整用户名及路由扩展，不含密码。请保存在可信目录，它能标识账号及选择的出口或池。",
  "connections.downloadDiagnostic": "下载连接测试配置（不含密码）",
  "connections.diagnosticExpired":
    "请重新生成已核对的预览后再下载。浏览器只允许在读取配置后一分钟内下载，这不是服务端权限期限，也不代表执行了连接测试。",
  "connections.diagnosticRequested":
    "已请求下载诊断配置，请核对保存的文件；尚未执行连接测试。",
  "connections.diagnosticFailed":
    "诊断配置下载请求失败，请检查浏览器设置，不要为重试下载而新建或轮换凭证。",
  "connections.diagnosticRun":
    "在可信终端中进入下载文件所在目录，执行下方命令，并在隐藏输入提示中填写现有代理密码。命令和配置都不含密码。",
  "connections.diagnosticCommand": "本机 vproxy 连接测试命令",
  "connections.diagnosticPlaintext":
    "此命令用 --allow-plaintext 明确允许明文代理认证。仅在可信网络且接受该风险时运行。目标网站的 HTTPS 不会加密客户端到代理的密码交换。",
  "connections.diagnosticCa":
    'HTTPS 代理使用私有 CA 时，可添加 --proxy-ca "./proxy-ca.pem"，指定经可信渠道取得的公共 CA 证书包。它仅用于代理这一层 TLS，不影响目标网站的信任根；TLS 校验保持开启。',
  "connections.diagnosticDns":
    "SOCKS5 由代理端解析固定目标的域名；HTTP/HTTPS 使用 CONNECT。此配置不测试普通 HTTP 转发、BIND、UDP ASSOCIATE 或 MASQUE。",
  "connections.diagnosticAutomation":
    "自动化可用 --password-stdin 从重定向的标准输入读取现有密码，不要把密码写入命令参数或环境变量。下载到配置不代表测试通过。",
  "connections.diagnosticUnsupported":
    "本机诊断仅支持 HTTP/HTTPS CONNECT 和 SOCKS5 CONNECT。请选择对应操作并重新生成预览后下载配置。",
};
