package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"strings"
)

// truncateWebLogBodyForQueue 日志入队前把报文截到记录上限，并释放仅检测期使用的临时大块内存。
// 引擎按检测预算最多读 1MB 喂检测，但内存队列、Kafka 与文件出口不需要全量原文，
// 落库本来也会按同一上限截断，这里在入队前截断并用 strings.Clone 解除对 1MB 底层数组的引用，
// 同时清空 BodyDecoded/MultipartText/BodyValues 等仅检测期使用的字段，防止高并发攻击积压时队列内存膨胀。
func truncateWebLogBodyForQueue(weblog *innerbean.WebLog) {
	if weblog == nil {
		return
	}
	weblog.BodyDecoded = ""
	weblog.MultipartText = ""
	weblog.MultipartPlainFiles = nil
	weblog.CookiesDecoded = ""
	weblog.BodyValues = nil
	weblog.BodyFields = nil

	limit := int(global.GCONFIG_RECORD_MAX_BODY_LENGTH)
	if limit <= 0 {
		return
	}
	if len(weblog.BODY) > limit {
		weblog.BODY = strings.Clone(weblog.BODY[:limit])
	}
	if len(weblog.SrcByteBody) > limit {
		clipped := make([]byte, limit)
		copy(clipped, weblog.SrcByteBody[:limit])
		weblog.SrcByteBody = clipped
	}
}
