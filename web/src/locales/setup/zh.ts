export default {
  "setup.firstUse.title": "开始使用",
  "setup.firstUse.listener": "2. 启用代理服务",
  "setup.firstUse.unread": "状态未确认",
  "setup.firstUse.notTested": "尚未测试客户端连通。",
  "setup.firstUse.users": "1. 用户与凭证",
  "setup.firstUse.userHint":
    "选择或创建用户，再选择或创建该用户的凭证。已保存的密码可在连接配置中再次读取；旧凭证可能没有副本。",
  "setup.firstUse.ownerUnknown": "控制归属未确认，请刷新节点状态。",
  "setup.firstUse.delegated":
    "本机由其他节点控制。此处可查看，更改请到控制节点。",
  "setup.firstUse.manageUsers": "打开本机用户",
  "setup.firstUse.endpoints": "3. 复制代理链接",
  "setup.firstUse.endpointHint":
    "在用户的“凭证”中打开“连接配置”，读取或输入密码后复制链接。新节点默认使用主机出口，无需先添加 IP 资源。",
  "setup.firstUse.endpointUnavailable":
    "先刷新节点状态，再核对用户与连接配置。",
  "setup.title": "接入节点",
  "setup.continue": "接入与验证",
  "setup.prepare": "准备子节点",
  "setup.enroll": "登记双方身份",
  "setup.grant": "在子节点授予控制权",
  "setup.save": "保存目标地址",
  "setup.verify": "验证控制读取",
  "setup.stepNavigation": "选择接入步骤",
  "setup.stepLabel": "{current}/{total} · {title}",
  "setup.addressDetails": "地址与节点身份说明",
  "setup.progressHint": "仅为操作说明。继续查看不会登记证书或授予权限。",
  "setup.independent": "每个节点独立保存数据和策略，独立运行。",
  "setup.pkiRequired":
    "子节点请使用 API-only 的 management 构建，不含 web-ui。向导只显示本机操作说明，不执行命令、安装软件或更改证书信任。",
  "setup.controllerId": "本管理端的稳定节点 ID",
  "setup.adminOrigin": "管理员后台 HTTPS 源地址",
  "setup.adminOriginHint":
    "浏览器登录后台使用的地址，不是节点控制地址，也不是代理入口。",
  "setup.nodeOriginHint":
    "子节点独立 node 监听器的固定 HTTPS 源地址。本管理端必须能够访问它，且其中的 DNS/IP 必须匹配节点证书的 SAN。",
  "setup.proxyAddressHint":
    "各代理监听器可选的对外 host:port，用于生成客户端连接示例；不是后台地址，也不是节点控制目标。",
  "setup.prepareHint":
    "先检查现有数据目录，保留原身份、证书和已核验的启动配置，不要再次初始化或替换签发根。后台 HTTPS 与节点 mTLS 仍须分开配置；代理监听器可选。",
  "setup.preparationMode": "子节点安装方式",
  "setup.newChild": "新装子节点",
  "setup.existingChild": "已有节点",
  "setup.existingLocked":
    "目标已登记或保存结果未确认。请检查原子节点，不要创建另一个身份。",
  "setup.offlineAuthority":
    "沿用现有 setup 签发根，其 node CA 必须已被本管理端认可。",
  "setup.newOutputs":
    "输出须放在由你控制的父目录下，并使用新目录。失败或结果不确定时，先检查原输出再决定下一步，不覆盖或自动重放命令。",
  "setup.offlinePrepare": "1. 在子节点准备请求",
  "setup.offlinePrepareHint":
    "取得现有签发根的 public.json，通过可信渠道核对 SHA-256。终端会提示输入节点名称、管理员和隐藏密码。只把子节点生成的 public.json 交给签名机，私钥和 state 留在子节点。",
  "setup.offlineSign": "2. 在签名机签发",
  "setup.offlineSignHint":
    "签名前核对请求中的节点 ID 和两个 HTTPS 源地址。只将签发响应目录交回原子节点，两份 CA 私钥留在签名机。证书签名不会登记 peer 或授予控制权。",
  "setup.offlinePlan": "3. 在原子节点检查并启动",
  "setup.offlinePlanHint":
    "按预期访问范围明确填写两个监听地址，loopback 仅本机可达。计划须在原子节点生成，相关文件保留原路径。生成和检查计划不会开启监听，也不证明网络可达。",
  "setup.startHint":
    "check 通过后，按操作系统只运行其中一份脚本，并保持 API-only 节点运行以便双方 probe。脚本会复核输入，不会授信、修改防火墙或授权本管理端。",
  "setup.startPosix": "在 Linux / POSIX 启动",
  "setup.startWindows": "用 PowerShell 启动",
  "setup.offlinePathsHint":
    "新安装的子节点在后续登记和 probe 模板中使用下列路径。只向对端复制公有证书，不传输私钥或 state 目录。",
  "setup.childStatePath": "子节点数据目录",
  "setup.childCertificatePath": "子节点公开的 node 证书",
  "setup.childKeyPath": "子节点 node 私钥（留在本机）",
  "setup.childCaPath": "node CA 公有证书",
  "setup.optionalProxy": "可选：配置代理监听",
  "setup.optionalProxyHint":
    "终端引导只创建配置，不启动监听。加密代理需要已存在的证书文件。新代理启动计划检查通过后，启动或生成服务时使用 NEW_PROXY_LAUNCH_DIR，不要沿用之前仅管理 API 的计划。",
  "setup.optionalService": "可选：生成 Linux 服务文件",
  "setup.optionalServiceHint":
    "选择实际要运行的启动计划。这些命令只生成并检查用户服务文件，不安装、启用或启动服务。请核对输出的 unit，再另行安排安装。",
  "setup.commands": "命令模板与细节",
  "setup.placeholderHint":
    "模板仅供参考，不会在此执行。启动脚本按标注的操作系统选择，每个 <...> 都须替换为核对过的本机值，路径不是部署默认值。不要将私钥、CA 签名密钥、密码或代理凭证粘贴到此界面。",
  "setup.enrollHint": "通过可信渠道交换公有证书和稳定节点 ID。",
  "setup.privateKeysStayLocal":
    "每个节点的私钥留在该节点。仅有 CA 签名不代表获得控制权；双方都须登记对端的确切叶证书和预期 SAN。",
  "setup.registrationHint":
    "第一条登记命令在本管理端运行，第二条在子节点运行。模板用于新登记；已有 peer 的变更需通过 --expected-revision 提供实际 authorization_revision。不要为了通过 probe 随意替换或重新启用 peer。",
  "setup.probeHint":
    "双方分别配置的节点监听器运行后，从每个节点向另一方执行 probe，并通过可信渠道核对输出中的双方节点 ID。身份 probe 成功仍不代表获得策略控制权。",
  "setup.offlineGrant": "必须由子节点的本地操作者明确授予控制权。",
  "setup.stopHint":
    "先安排维护窗口，并自行停止该子节点的 manage serve。离线命令会拒绝运行中的实例，不会代为停止服务；停止受管实例也会停止其受管代理监听器。",
  "setup.epochHint":
    "需要 schema 13 及 owner CLI。停止子节点后，先读取 owner status，再将实际当前 epoch 填入 grant。不要猜测为 1，也不要复用旧代次。本管理端须已作为非自身的启用 peer 登记在子节点上；即使授予同一控制端，也会推进代次。",
  "setup.restartHint":
    "再次用 owner status 核对控制节点 ID 与本管理端完全一致，再使用原先已核验的 serve 配置启动子节点。向导不能代子节点授信或重启。命令结果不确定时，先检查 status，再决定下一步，不要自动重放。",
  "setup.close": "关闭向导",
  "setup.previous": "上一步",
  "setup.next": "继续查看",
  "setup.saveAction": "保存一次目标配置",
  "setup.saved": "目标已登记 · 尚未验证控制读取",
  "setup.savedHint":
    "保存只修改本管理端的登记，不证明证书登记、控制归属、可达性、代理可用或出口健康。响应丢失时，保存仍可能已提交。",
  "setup.saveUncertain":
    "未确认保存结果，配置可能已经提交。不要在此重复提交；请关闭向导、刷新节点列表，按确切节点 ID 核对后再决定下一步。",
  "setup.recoverRegistry": "关闭并刷新节点列表",
  "setup.verifyAction": "读取并验证控制权限",
  "setup.verified": "本次控制读取已核实",
  "setup.verifiedHint":
    "选定的登记节点与本管理端控制节点 ID 已和受验证的策略响应匹配。这只是一次观察，不代表持续授权、代理连通或 IP 健康，控制归属之后仍可能变化。",
  "setup.runtimeObserved": "报告代理运行中 · 未测试健康",
  "setup.changed":
    "节点 ID 或目标配置已变化，请刷新列表后重新打开要管理的节点。",
  "setup.inactive":
    "该目标已暂停、退役或被回退检测阻止。请先在节点列表明确处理其状态，再进行验证。",
  "setup.ownerMismatch":
    "受验证的子节点策略未将本管理端指定为控制节点，不能据此认定控制成功。",
  "setup.troubleshoot": "验证失败时应检查什么",
  "setup.failureHint":
    "请核对固定的 node 源地址、双方确切证书登记及版本、CA 信任、证书有效期/SAN 与 serverAuth/clientAuth 双用途、子节点 owner status，以及软件和 schema 兼容性。仅凭授权错误无法判断哪一端配置有误。不要关闭 TLS 校验、自动信任新证书，或重放变更来排查。",
};
