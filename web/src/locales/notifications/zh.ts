export default {
  "notifications.title": "Webhook 通知",
  "notifications.confirm": "确认",
  "notifications.cancel": "取消",
  "notifications.description":
    "发送本管理节点新记录的告警事件。汇集子节点事件需先启用后台告警采集。接收端返回成功不代表有人已查看通知。",
  "notifications.refresh": "刷新状态",
  "notifications.savedState": "已保存配置",
  "notifications.enabled": "已启用",
  "notifications.disabled": "已关闭",
  "notifications.destination": "接收端",
  "notifications.configured": "已配置，不显示秘密",
  "notifications.notConfigured": "未配置",
  "notifications.token": "Bearer 令牌（可选）",
  "notifications.cursor": "已处理至事件序号",
  "notifications.skipped": "配置变更时跳过至序号",
  "notifications.lastAccepted": "最近获接收端确认的投递",
  "notifications.discarded": "最近放弃的投递",
  "notifications.none": "暂无",
  "notifications.enable": "启用通知",
  "notifications.url": "HTTPS 接收地址",
  "notifications.urlHint":
    "只允许公网 HTTPS 地址。地址可能含秘密，读取接口不会返回它。私网、回环、重定向和环境代理均不使用。",
  "notifications.keep": "留空保留原值",
  "notifications.tokenHint":
    "只在替换时输入。浏览器复核记录不保存令牌；私有数据库备份会包含它。",
  "notifications.clearToken": "删除当前令牌",
  "notifications.auto": "接收端支持去重，启用自动重试",
  "notifications.autoHint":
    "接收端必须按 observer_node_id 与 delivery_id 去重。自动尝试最多共 6 次，至少间隔 30、60、120、240、480 秒；否则停用此选项并人工复核。",
  "notifications.autoEligible": "此失败符合自动重试条件；最多共 6 次。",
  "notifications.discardHint": "允许放弃当前投递，包括可能已到达接收端的请求",
  "notifications.save": "保存配置",
  "notifications.saveWarning":
    "保存后从当前事件序号开始，不补发旧记录。若已勾选放弃当前投递，将保留放弃记录；已提交给接收端的请求无法撤回。",
  "notifications.forget": "删除接收端配置",
  "notifications.forgetWarning":
    "关闭通知并删除当前地址和令牌。已有备份不会被修改，已提交的请求无法撤回。",
  "notifications.retry": "用原 ID 重试一次",
  "notifications.retryWarning":
    "接收端可能已收到原请求。请先确认接收端支持去重，并满足其等待要求；本次会复用原投递 ID 和请求体，不创建新投递。",
  "notifications.attempts": "已开始 {count} 次尝试",
  "notifications.refreshDelivery": "刷新状态查看后续结果。",
  "notifications.outcome.ready": "已保存一次投递许可，等待执行",
  "notifications.outcome.sending": "本次尝试已开始，结果尚未记录",
  "notifications.outcome.rejected": "接收端返回非成功状态",
  "notifications.outcome.deferred": "接收端要求延后，自动重试已暂停",
  "notifications.outcome.unknown": "投递结果未知",
  "notifications.outcome.destination_blocked": "接收端未通过连接预检",
  "notifications.reviewRequired": "上次操作需要复核，暂不提交新操作",
  "notifications.result.saved": "当前回执证明原配置已保存。",
  "notifications.result.admitted":
    "当前记录证明原重试已获准；不代表接收端已处理。",
  "notifications.result.unknown": "当前记录无法确认原操作结果，不会自动重放。",
  "notifications.finishReview": "确认已复核，继续管理",
  "notifications.reviewWarning":
    "只清除这条浏览器复核记录，不重发请求、不撤销服务器操作，也不把未知结果记为成功。",
  "notifications.notesUnavailable":
    "浏览器复核记录不可用。请使用支持 Web Locks 和本地存储的浏览器；为避免丢失未知操作，本页暂不写入。",
  "notifications.invalid": "通知配置无效，请检查地址、令牌和待处理投递。",
  "notifications.changed": "配置或投递已变化，请刷新后复核。",
};
