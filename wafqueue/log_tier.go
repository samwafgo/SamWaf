package wafqueue

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"unicode/utf8"

	"gorm.io/gorm/clause"
)

// narrowURLMaxBytes url/raw_query 落库的字节上限（C8）。极长 URL 只在报文里看全。
const narrowURLMaxBytes = 2048

// ipWatchHas 观察名单判定。包级变量，单测可替换。
var ipWatchHas = func(ip string) bool { return global.GWAF_IP_WATCH.Has(ip) }

// 报文行的三种归属：事件全量留、正常请求只留蓄水池采到的样本、观察名单内的 IP 全量留。
const (
	PayloadKindSample = "sample"
	PayloadKindWatch  = "watch"
)

// tierForStore 把一批日志分流到三层存储，全部在副本上动手（原对象还要给 Kafka 出口与统计）：
//
//   - security_event：安全事件（IsSecurityEvent），必有；报文进 event_payload(kind=event)
//   - access_log：窄行。db 档全量，sample 档事件+采到的样本，off 档仅事件（安全事件始终双写，
//     访问日志页因此不用做两表 UNION）；观察名单内的 IP 任意档位都写
//
// 正常请求的报文不在这里写：蓄水池（log_reservoir.go）采中的攒在内存里定期刷成
// event_payload(kind=sample)。本函数只问池子「这条有没有被采中」，决定 sample 档下写不写窄行。
// 例外是观察名单：名单内 IP 的报文就地写 kind=watch，不等池子。
//
// web_logs 从此不再写入：改造前的数据靠一次性切库变成归档分片，照旧可读（D6 只读到期删）。
// 同一 req_uuid 一批里可能出现两次（分阶段入队），三张表都以它为主键，批内去重取后到的那条，
// 跨批次由主键 DoNothing 兜住。
func tierForStore(logs []*innerbean.WebLog) (events []*model.SecurityEvent, accesses []*model.AccessLog, payloads []*model.EventPayload) {
	mode := global.GDATA_ACCESS_LOG_MODE
	seenEvent := make(map[string]int, len(logs))
	seenAccess := make(map[string]int, len(logs))
	seenPayload := make(map[string]int, len(logs))

	for _, lg := range logs {
		if lg == nil {
			continue
		}
		// req_uuid 是三张表的寻址键。正常路径它一定在；真缺了就地补一个，
		// 让这一行在库里也能被点开（Kafka 出口与这行用同一个对象，一并受益）。
		if lg.REQ_UUID == "" {
			lg.REQ_UUID = uuid.GenUUID()
		}

		isEvent := lg.IsSecurityEvent()
		// 观察名单（C7）：名单内 IP 的正常请求也全量留痕——窄行必写、报文 kind=watch。
		// 已按安全事件处理的不再重复取报文（event_payload 以 req_uuid 为主键，一条只有一行）。
		watched := !isEvent && ipWatchHas(lg.SRC_IP)
		sampled := false
		if !isEvent && !watched && mode != "off" {
			// 正常请求的报文只留蓄水池采中的那部分（D2 负样本池）。
			// 池子攒在内存里定期刷库（见 log_reservoir.go），这里只问「有没有被采中」。
			// off 档不采样：用户已明确放弃 AI 训练负样本（档位说明里列了这条）。
			// 观察名单内的已由 watch 全量留痕，不重复采样。
			sampled = negSampler.Pick(lg)
		}

		ln := narrowFromLog(lg)

		if isEvent {
			events = dedupByUUID(events, seenEvent, lg.REQ_UUID,
				&model.SecurityEvent{LogNarrow: ln, PayloadHash: PayloadHash(lg.RULE, lg.BodyHash)})
			if p := extractPayload(lg, PayloadKindEvent); p != nil {
				payloads = dedupByUUID(payloads, seenPayload, p.ReqUUID, p)
			}
		}
		if watched {
			if p := extractPayload(lg, PayloadKindWatch); p != nil {
				payloads = dedupByUUID(payloads, seenPayload, p.ReqUUID, p)
			}
		}
		if isEvent || watched || mode == "db" || (mode == "sample" && sampled) {
			accesses = dedupByUUID(accesses, seenAccess, lg.REQ_UUID, &model.AccessLog{LogNarrow: ln})
		}
	}
	return events, accesses, payloads
}

// dedupByUUID 批内按 req_uuid 去重，后到的那条覆盖先到的（分阶段入队，后一条信息更全）。
func dedupByUUID[T any](dst []T, seen map[string]int, id string, item T) []T {
	if at, dup := seen[id]; dup {
		dst[at] = item
		return dst
	}
	seen[id] = len(dst)
	return append(dst, item)
}

// narrowFromLog 从完整日志对象拷出窄行：url/raw_query 截断到 2KB，三个分析键算好。
func narrowFromLog(lg *innerbean.WebLog) model.LogNarrow {
	url := cutUTF8N(lg.URL, narrowURLMaxBytes)
	rawQuery := cutUTF8N(lg.RawQuery, narrowURLMaxBytes)
	truncated := 0
	if len(url) != len(lg.URL) || len(rawQuery) != len(lg.RawQuery) {
		truncated = 1
	}
	return model.LogNarrow{
		ReqUUID:            lg.REQ_UUID,
		TenantId:           lg.TenantId,
		UserCode:           lg.USER_CODE,
		HostCode:           lg.HOST_CODE,
		Host:               lg.HOST,
		URL:                url,
		RawQuery:           rawQuery,
		Method:             lg.METHOD,
		Scheme:             lg.Scheme,
		REFERER:            cutUTF8N(lg.REFERER, 1024),
		USER_AGENT:         cutUTF8N(lg.USER_AGENT, 500),
		SRC_IP:             lg.SRC_IP,
		SRC_PORT:           lg.SRC_PORT,
		NetSrcIp:           lg.NetSrcIp,
		COUNTRY:            lg.COUNTRY,
		PROVINCE:           lg.PROVINCE,
		CITY:               lg.CITY,
		ACTION:             lg.ACTION,
		RULE:               lg.RULE,
		STATUS:             lg.STATUS,
		STATUS_CODE:        lg.STATUS_CODE,
		RISK_LEVEL:         lg.RISK_LEVEL,
		AI_SCORE:           lg.AI_SCORE,
		IsBot:              lg.IsBot,
		LogOnlyMode:        lg.LogOnlyMode,
		GUEST_IDENTIFICATION: lg.GUEST_IDENTIFICATION,
		TimeSpent:          lg.TimeSpent,
		CONTENT_LENGTH:     lg.CONTENT_LENGTH,
		ResContentLength:   lg.RES_CONTENT_LENGTH,
		PreCheckCost:       lg.PreCheckCost,
		ForwardCost:        lg.ForwardCost,
		BackendCheckCost:   lg.BackendCheckCost,
		IsBalance:          lg.IsBalance,
		BalanceInfo:        lg.BalanceInfo,
		BodyHash:           lg.BodyHash,
		Truncated:          truncated,
		ActorKey:           ActorKey(lg.GUEST_IDENTIFICATION, lg.SRC_IP),
		UaHash:             UaHash(lg.USER_AGENT),
		PathNorm:           NormalizePath(lg.URL),
		CREATE_TIME:        lg.CREATE_TIME,
		UNIX_ADD_TIME:      lg.UNIX_ADD_TIME,
		Day:                lg.Day,
	}
}

// extractPayload 拷出报文行（含 HEADER——它随窄行拆出后只能跟报文走），单列 64KB 截断。
// 报文列全空返回 nil：不占一行，读侧找不到报文行时本来就显示「未留存报文」。
func extractPayload(lg *innerbean.WebLog, kind string) *model.EventPayload {
	header := cutUTF8(lg.HEADER)
	cookies := cutUTF8(lg.COOKIES)
	body := cutUTF8(lg.BODY)
	resBody := cutUTF8(lg.RES_BODY)
	postForm := cutUTF8(lg.POST_FORM)
	resHeader := cutUTF8(lg.ResHeader)
	srcBody := cutBytes(lg.SrcByteBody)
	srcResBody := cutBytes(lg.SrcByteResBody)
	srcURL := cutBytes(lg.SrcURL)

	p := &model.EventPayload{
		ReqUUID:        lg.REQ_UUID,
		TenantId:       lg.TenantId,
		UserCode:       lg.USER_CODE,
		HostCode:       lg.HOST_CODE,
		Kind:           kind,
		HEADER:         header,
		COOKIES:        cookies,
		BODY:           body,
		RES_BODY:       resBody,
		POST_FORM:      postForm,
		ResHeader:      resHeader,
		SrcByteBody:    srcBody,
		SrcByteResBody: srcResBody,
		SrcURL:         srcURL,
		CreateTime:     lg.CREATE_TIME,
		UnixAddTime:    lg.UNIX_ADD_TIME,
		Day:            lg.Day,
	}
	if len(header) != len(lg.HEADER) || len(cookies) != len(lg.COOKIES) ||
		len(body) != len(lg.BODY) || len(resBody) != len(lg.RES_BODY) ||
		len(postForm) != len(lg.POST_FORM) || len(resHeader) != len(lg.ResHeader) ||
		len(srcBody) != len(lg.SrcByteBody) || len(srcResBody) != len(lg.SrcByteResBody) ||
		len(srcURL) != len(lg.SrcURL) {
		p.Truncated = 1
	}
	if p.IsEmpty() {
		return nil
	}
	return p
}

// storeTiered 三张表各一条批量语句，主键冲突（跨批次重复入队）保留先到的。
// 任何一张失败只告警：行还在另外两张里，比整批回滚强。
func storeTiered(logs []*innerbean.WebLog) {
	events, accesses, payloads := tierForStore(logs)
	if len(events) > 0 {
		if err := conflictIgnoreInsert(events); err != nil {
			zlog.Warn("安全事件落库失败", "条数", len(events), "error", err.Error())
		}
	}
	if len(accesses) > 0 {
		if err := conflictIgnoreInsert(accesses); err != nil {
			zlog.Warn("访问日志落库失败", "条数", len(accesses), "error", err.Error())
		}
	}
	storePayloads(payloads)
}

// conflictIgnoreInsert 整批写入，撞主键的行跳过（保留先到的）。不指定冲突列：
// 三个引擎对"无目标的 DO NOTHING"都认（MySQL 走 INSERT IGNORE），与 storePayloads 同理。
func conflictIgnoreInsert[T any](rows []T) error {
	if len(rows) == 0 {
		return nil
	}
	return global.GWAF_LOCAL_LOG_DB.
		Clauses(clause.OnConflict{DoNothing: true}).
		CreateInBatches(rows, len(rows)).Error
}

// cutUTF8N 与 cutUTF8 同规则，上限可调（窄行 url 用 2KB，报文列用 64KB）。
func cutUTF8N(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	for i := 0; i < 3 && len(cut) > 0; i++ {
		r, size := utf8.DecodeLastRuneInString(cut)
		if r != utf8.RuneError || size > 1 {
			break
		}
		cut = cut[:len(cut)-1]
	}
	return cut
}
