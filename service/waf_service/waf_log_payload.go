package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/wafdb"
)

// payloadFetchChunk 一次 IN 查询带的 req_uuid 个数。
// SQLite 默认最多 999 个绑定变量，留足余量。
const payloadFetchChunk = 500

// FillLivePayloads 给实时库查出来的日志补上报文列。
func FillLivePayloads(rows []*innerbean.WebLog) {
	FillShardPayloads("", rows)
}

// FillShardPayloads 按 req_uuid 把报文补回日志对象。
//
// 报文自本次改造起写在独立的 event_payload 表里，web_logs 那几列对新数据是空的。
// 凡是要看报文的读取方，查完日志都得再走这一步，否则拿到的是空字符串。
//
// 三种情况都能正确落地：
//   - 新数据：找得到报文行，以它为准
//   - 改造前的存量行：找不到报文行，保留 web_logs 原列里的报文
//   - 改造前切出去的归档分片：整张报文表都不存在，直接返回，同样保留原列
func FillShardPayloads(currentDbName string, rows []*innerbean.WebLog) {
	if len(rows) == 0 {
		return
	}
	db, _, payloadTable := wafdb.ResolveLogTables(currentDbName)
	if db == nil || payloadTable == "" {
		return
	}

	index := make(map[string][]*innerbean.WebLog, len(rows))
	uuids := make([]string, 0, len(rows))
	for _, r := range rows {
		if r == nil || r.REQ_UUID == "" {
			continue
		}
		if _, ok := index[r.REQ_UUID]; !ok {
			uuids = append(uuids, r.REQ_UUID)
		}
		index[r.REQ_UUID] = append(index[r.REQ_UUID], r)
	}
	if len(uuids) == 0 {
		return
	}

	for start := 0; start < len(uuids); start += payloadFetchChunk {
		end := start + payloadFetchChunk
		if end > len(uuids) {
			end = len(uuids)
		}
		var found []model.EventPayload
		err := db.Table(payloadTable).
			Select("req_uuid", "header", "cookies", "body", "res_body", "post_form", "res_header", "truncated").
			Where("req_uuid in ?", uuids[start:end]).Find(&found).Error
		if err != nil {
			// 报文读不到不该让整个页面失败：日志本身已经查出来了，报文列留空即可
			zlog.Warn("读取报文失败", "table", payloadTable, "条数", end-start, "error", err.Error())
			return
		}
		for i := range found {
			p := &found[i]
			for _, r := range index[p.ReqUUID] {
				applyPayload(r, p)
			}
		}
	}
}

// applyPayload 只用非空值覆盖，空值一律不动 web_logs 上的原值。
//
// 这条规则同时管住三件事：报文表里某列为空时不会把窄行上仍然有效的值抹掉
// （HEADER 这一列本次就还留在窄行里，见 wafqueue/log_split.go）；
// 存量行与新行混在一页时各取各的；将来把某一列挪进报文表也不用改这里。
//
// 原始字节列(src_byte_*/src_url)不回填：详情与列表历来都不返回它们，回填只会把响应撑大。
func applyPayload(r *innerbean.WebLog, p *model.EventPayload) {
	if p.HEADER != "" {
		r.HEADER = p.HEADER
	}
	if p.COOKIES != "" {
		r.COOKIES = p.COOKIES
	}
	if p.BODY != "" {
		r.BODY = p.BODY
	}
	if p.RES_BODY != "" {
		r.RES_BODY = p.RES_BODY
	}
	if p.POST_FORM != "" {
		r.POST_FORM = p.POST_FORM
	}
	if p.ResHeader != "" {
		r.ResHeader = p.ResHeader
	}
	if p.Truncated == 1 {
		r.Truncated = 1
	}
}
