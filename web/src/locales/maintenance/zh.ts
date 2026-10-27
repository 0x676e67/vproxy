export default {
  "maintenance.title": "代理维护",
  "maintenance.read": "读取当前维护状态",
  "maintenance.pause": "暂停新代理任务",
  "maintenance.resume": "恢复新代理任务",
  "maintenance.confirm": "确认本次更改",
  "maintenance.cancel": "取消",
  "maintenance.accepting": "接受新任务",
  "maintenance.paused": "已暂停新任务",
  "maintenance.saved": "已保存接入设置",
  "maintenance.runtime": "当前观测运行设置",
  "maintenance.active": "当前观测活动任务",
  "maintenance.zero": "未观测到活动任务",
  "maintenance.savedRevision": "已保存策略版本",
  "maintenance.runtimeRevision": "观测运行版本",
  "maintenance.durableRevision": "最近持久应用检查点",
  "maintenance.unknown": "未知",
  "maintenance.scope":
    "暂停只影响新认证的代理任务，不中断已有任务，不暂停管理命令下发，也不停止节点。",
  "maintenance.shutdown":
    "暂停后可使用在线连接排空，停止监听并等待本机连接拥有者结束。租约计数即使为零，也不证明 HTTP、HTTP/2、TLS 或 QUIC 队列为空，不能据此强制结束进程。",
  "maintenance.queue":
    "远端更改使用一条持久命令。控制器可能重试下发同一命令身份；本页不会自动重新提交或轮询。",
  "maintenance.confirmHint":
    "使用当前显示的节点、策略版本和归属代际，仅提交一次。已保存与运行时已应用是不同事实；收到回复后，请另行读取当前状态。",
  "maintenance.confirmRemote":
    "本次提交还绑定当前目标版本和下一个命令序号；暂停目标下发是另一项设置。",
  "maintenance.unsupported": "此节点不支持维护状态。",
  "maintenance.interrupted": "读取已中断，请重新读取当前状态。",
  "maintenance.historical":
    "这是先前观测，不代表当前状态。再次决定前请重新读取。",
  "maintenance.localControlled":
    "此节点归另一控制器管理，不能在本机修改维护设置。",
  "maintenance.remoteUnavailable":
    "目标已暂停下发、退役、检测到回退，或不归本控制器管理，不能修改维护设置。",
  "maintenance.otherChange": "请先审阅尚未解决的节点更改，再开始新更改。",
  "maintenance.sequenceExhausted":
    "策略或命令序号已达上限，不能开始新更改。请联系运维人员检查节点，不要重置序号或重放命令。",
  "maintenance.pending": "正在提交本次维护更改……",
  "maintenance.uncertain":
    "本次更改尚无确认的最终结果，不要重复提交。请读取当前状态，并在可用时读取原命令回执；后来的设置不能证明这次写入成功。",
  "maintenance.retained":
    "已保留一项未解决的维护更改。请打开对应节点卡片审阅；刷新列表不会解决它。",
  "maintenance.intent": "原请求接入设置",
  "maintenance.expectedRevision": "原策略版本",
  "maintenance.expectedEpoch": "原归属代际",
  "maintenance.job": "原命令任务 ID",
  "maintenance.readReceipt": "刷新原命令回执",
  "maintenance.receiptMismatch":
    "当前命令不是原维护命令，不能把它的结果归于本次更改。",
  "maintenance.receiptPending":
    "仍有命令等待或阻塞，请完成审阅后再确认这项更改。",
  "maintenance.acknowledge": "已审阅当前状态，允许重新决定",
  "maintenance.acknowledgeHint":
    "此操作只清除浏览器提醒，不表示原更改成功，也不会重放。新的更改仍需重新读取并确认。",
  "maintenance.savedReply":
    "更改已保存；运行时是否应用及活动任务数量仍需另行读取。",
  "maintenance.appliedReply": "命令报告已应用；活动任务数量仍需另行读取。",
  "maintenance.rejectedReply": "命令已拒绝，请先读取当前状态，再决定下一步。",
  "maintenance.jobState": "观测命令状态",
} as const;
