package wafqueue

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"

	"gorm.io/gorm/clause"
)

// PayloadKindEvent 当前唯一在写的报文归属。采样负样本(sample)与观察名单(watch)在后续分层写入里接上。
const PayloadKindEvent = "event"

// splitForStore 把一批日志拆成两份落库数据：只剩窄列的 web_logs 行，和装报文的 event_payload 行。
//
// 两条硬性约束：
//
//  1. 不改原对象。Kafka 出口、文件日志、统计与规则引擎共享同一批指针，且落库排在它们前面，
//     就地清列会让下游只拿到空报文。所以每条都是在副本上动手。
//  2. req_uuid 为空的日志不拆。报文表以 req_uuid 为主键，没有它就没法再找回来，
//     这种日志维持老样子——报文留在 web_logs 自己的列里（仍然截断）。
//
// 同一个 req_uuid 在一批里可能出现两次（一次请求分阶段入队，后一条信息更全），
// web_logs 没有主键容得下两行，报文表容不下，所以按 req_uuid 去重取后到的那条。
//
// HEADER 这一列本次不搬：访问日志页把它当独立列显示，还带一个 LIKE 全文筛选。
// 搬走等于那一列立刻空掉、筛选也不再命中，而替代的筛选入口要等日志分层(access_log /
// security_event)拆出来之后才有地方放。它留在窄行里，跟着后续的视图拆分一起走。
func splitForStore(logs []*innerbean.WebLog) ([]*innerbean.WebLog, []*model.EventPayload) {
	narrow := make([]*innerbean.WebLog, 0, len(logs))
	payloads := make([]*model.EventPayload, 0, len(logs))
	seen := make(map[string]int, len(logs))

	for _, lg := range logs {
		if lg == nil {
			continue
		}
		c := *lg

		header := cutUTF8(lg.HEADER)
		cookies := cutUTF8(lg.COOKIES)
		body := cutUTF8(lg.BODY)
		resBody := cutUTF8(lg.RES_BODY)
		postForm := cutUTF8(lg.POST_FORM)
		resHeader := cutUTF8(lg.ResHeader)
		srcBody := cutBytes(lg.SrcByteBody)
		srcResBody := cutBytes(lg.SrcByteResBody)
		srcURL := cutBytes(lg.SrcURL)

		if len(header) != len(lg.HEADER) || len(cookies) != len(lg.COOKIES) ||
			len(body) != len(lg.BODY) || len(resBody) != len(lg.RES_BODY) ||
			len(postForm) != len(lg.POST_FORM) || len(resHeader) != len(lg.ResHeader) ||
			len(srcBody) != len(lg.SrcByteBody) || len(srcResBody) != len(lg.SrcByteResBody) ||
			len(srcURL) != len(lg.SrcURL) {
			c.Truncated = 1
		}

		c.HEADER = header

		if lg.REQ_UUID == "" {
			c.COOKIES, c.BODY = cookies, body
			c.RES_BODY, c.POST_FORM, c.ResHeader = resBody, postForm, resHeader
			c.SrcByteBody, c.SrcByteResBody, c.SrcURL = srcBody, srcResBody, srcURL
			narrow = append(narrow, &c)
			continue
		}

		p := &model.EventPayload{
			ReqUUID:        lg.REQ_UUID,
			TenantId:       lg.TenantId,
			UserCode:       lg.USER_CODE,
			HostCode:       lg.HOST_CODE,
			Kind:           PayloadKindEvent,
			COOKIES:        cookies,
			BODY:           body,
			RES_BODY:       resBody,
			POST_FORM:      postForm,
			ResHeader:      resHeader,
			SrcByteBody:    srcBody,
			SrcByteResBody: srcResBody,
			SrcURL:         srcURL,
			Truncated:      c.Truncated,
			CreateTime:     lg.CREATE_TIME,
			UnixAddTime:    lg.UNIX_ADD_TIME,
			Day:            lg.Day,
		}

		c.COOKIES, c.BODY = "", ""
		c.RES_BODY, c.POST_FORM, c.ResHeader = "", "", ""
		c.SrcByteBody, c.SrcByteResBody, c.SrcURL = nil, nil, nil
		narrow = append(narrow, &c)

		// 报文列全空就不占一行：读侧找不到报文行时会回落读 web_logs 的原列，结果一样是空。
		if p.IsEmpty() {
			continue
		}
		if at, dup := seen[p.ReqUUID]; dup {
			payloads[at] = p
			continue
		}
		seen[p.ReqUUID] = len(payloads)
		payloads = append(payloads, p)
	}

	return narrow, payloads
}

// storePayloads 写报文表。单独一条语句，且失败只告警：
// 日志行已经落库，报文丢了详情页显示「未留存报文」，比整批日志一起回滚强。
// 跨批次可能撞上同一个 req_uuid（同一请求分两批入队），主键冲突按「保留先到的」跳过。
func storePayloads(payloads []*model.EventPayload) {
	if len(payloads) == 0 {
		return
	}
	// 不指定冲突列：三个引擎对"无目标的 DO NOTHING"都认（MySQL 走 INSERT IGNORE），
	// 指定了反而要各写各的。这里只有主键一种冲突，无目标正合适。
	err := global.GWAF_LOCAL_LOG_DB.
		Clauses(clause.OnConflict{DoNothing: true}).
		CreateInBatches(payloads, len(payloads)).Error
	if err != nil {
		zlog.Warn("报文落库失败", "条数", len(payloads), "error", err.Error())
	}
}
