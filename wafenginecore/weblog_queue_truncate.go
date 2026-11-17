package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
)

// truncateWebLogBodyForQueue 日志入队前把报文截到记录上限。
// 引擎按检测预算最多读 1MB 喂检测，但内存队列、Kafka 与文件出口不需要全量原文，
// 落库本来也会按同一上限截断，这里在入队前截断，避免大报文把队列内存放大。
// 调用点必须在检测链完成之后（检测已消费完整检测输入）。
func truncateWebLogBodyForQueue(weblog *innerbean.WebLog) {
	if weblog == nil {
		return
	}
	limit := int(global.GCONFIG_RECORD_MAX_BODY_LENGTH)
	if limit <= 0 {
		return
	}
	if len(weblog.BODY) > limit {
		weblog.BODY = weblog.BODY[:limit]
	}
	if len(weblog.SrcByteBody) > limit {
		weblog.SrcByteBody = weblog.SrcByteBody[:limit]
	}
}
