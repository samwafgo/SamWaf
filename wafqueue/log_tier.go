package wafqueue

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"

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
			if !lg.SkipPayloadStore {
				if p := extractPayload(lg, PayloadKindEvent); p != nil {
					payloads = dedupByUUID(payloads, seenPayload, p.ReqUUID, p)
				}
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
// 脱敏开时查询串按参数名抹值（GET 凭证常挂 ?api_key= 上），路径保持原样。
func narrowFromLog(lg *innerbean.WebLog) model.LogNarrow {
	srcURL, srcRawQuery := lg.URL, lg.RawQuery
	if global.GCONFIG_RECORD_LOG_DESENSITIZE == 1 {
		srcURL = maskPersistedRequestURI(srcURL)
		srcRawQuery = maskPersistedQuery(srcRawQuery)
	}
	truncated := 0
	mark := func(src, out string) string {
		if out != src {
			truncated = 1
		}
		return out
	}
	text := func(s string, max int) string { return mark(s, cutTextCharsN(s, max)) }
	byteText := func(s string, max int) string { return mark(s, cutUTF8N(s, max)) }
	ln := model.LogNarrow{
		ReqUUID:              text(lg.REQ_UUID, 64),
		TenantId:             text(lg.TenantId, 64),
		UserCode:             text(lg.USER_CODE, 64),
		HostCode:             text(lg.HOST_CODE, 64),
		Host:                 text(lg.HOST, 255),
		URL:                  byteText(srcURL, narrowURLMaxBytes),
		RawQuery:             byteText(srcRawQuery, narrowURLMaxBytes),
		Method:               text(lg.METHOD, 20),
		Scheme:               text(lg.Scheme, 20),
		REFERER:              byteText(lg.REFERER, 1024),
		USER_AGENT:           byteText(lg.USER_AGENT, 500),
		SRC_IP:               text(lg.SRC_IP, 64),
		SRC_PORT:             text(lg.SRC_PORT, 10),
		NetSrcIp:             text(lg.NetSrcIp, 64),
		COUNTRY:              text(lg.COUNTRY, 100),
		PROVINCE:             text(lg.PROVINCE, 100),
		CITY:                 text(lg.CITY, 100),
		ACTION:               text(lg.ACTION, 100),
		RULE:                 byteText(lg.RULE, payloadMaxBytes),
		STATUS:               text(lg.STATUS, 50),
		STATUS_CODE:          lg.STATUS_CODE,
		RISK_LEVEL:           lg.RISK_LEVEL,
		AI_SCORE:             lg.AI_SCORE,
		IsBot:                lg.IsBot,
		LogOnlyMode:          lg.LogOnlyMode,
		GUEST_IDENTIFICATION: text(lg.GUEST_IDENTIFICATION, 191),
		TimeSpent:            lg.TimeSpent,
		CONTENT_LENGTH:       lg.CONTENT_LENGTH,
		ResContentLength:     lg.RES_CONTENT_LENGTH,
		PreCheckCost:         lg.PreCheckCost,
		ForwardCost:          lg.ForwardCost,
		BackendCheckCost:     lg.BackendCheckCost,
		IsBalance:            lg.IsBalance,
		BalanceInfo:          text(lg.BalanceInfo, 255),
		BodyHash:             text(lg.BodyHash, 100),
		ActorKey:             text(ActorKey(lg.SRC_IP), 100),
		UaHash:               UaHash(lg.USER_AGENT),
		PathNorm:             text(NormalizePath(lg.URL), pathNormMaxLen),
		CREATE_TIME:          text(lg.CREATE_TIME, 32),
		UNIX_ADD_TIME:        lg.UNIX_ADD_TIME,
		Day:                  lg.Day,
	}
	ln.Truncated = truncated
	return ln
}

// extractPayload 在副本上应用报文配置与单列 65535 字节上限。
// 报文列全空返回 nil：不占一行，读侧找不到报文行时本来就显示「未留存报文」。
func extractPayload(lg *innerbean.WebLog, kind string) *model.EventPayload {
	// 副本上做凭证脱敏（Basic 凭据/令牌/会话/表单密码不进报文表），原对象保持完整，
	// 检测、Kafka 与文件出口拿的还是未脱敏报文。截断判定对脱敏后的源串做，
	// 否则脱敏缩短了内容会被误标成截断。
	srcHeader, srcCookies, srcResHeader, srcPostForm := lg.HEADER, lg.COOKIES, lg.ResHeader, lg.POST_FORM
	srcURL := string(lg.SrcURL)
	if global.GCONFIG_RECORD_LOG_DESENSITIZE == 1 {
		srcHeader = maskPersistedHeaderLines(srcHeader, false)
		srcCookies = maskPersistedCookies(srcCookies)
		srcResHeader = maskPersistedHeaderLines(srcResHeader, true)
		srcPostForm = maskPersistedForm(srcPostForm)
		srcURL = maskPersistedRequestURI(srcURL)
	}
	srcBody, srcResBody := lg.BODY, lg.RES_BODY
	requestLimit := persistedBodyLimit(global.GCONFIG_RECORD_MAX_BODY_LENGTH)
	responseLimit := persistedBodyLimit(global.GCONFIG_RECORD_MAX_RES_BODY_LENGTH)

	header := cutUTF8(srcHeader)
	cookies := cutUTF8(srcCookies)
	body := cutUTF8N(srcBody, requestLimit)
	resBody := cutUTF8N(srcResBody, responseLimit)
	postForm := cutUTF8N(srcPostForm, requestLimit)
	resHeader := cutUTF8(srcResHeader)
	srcByteBody := cutBytesN(lg.SrcByteBody, requestLimit)
	srcByteResBody := cutBytesN(lg.SrcByteResBody, responseLimit)
	srcURLBytes := cutBytes([]byte(srcURL))

	p := &model.EventPayload{
		ReqUUID:        cutTextCharsN(lg.REQ_UUID, 64),
		TenantId:       cutTextCharsN(lg.TenantId, 64),
		UserCode:       cutTextCharsN(lg.USER_CODE, 64),
		HostCode:       cutTextCharsN(lg.HOST_CODE, 64),
		Kind:           cutTextCharsN(kind, 16),
		HEADER:         header,
		COOKIES:        cookies,
		BODY:           body,
		RES_BODY:       resBody,
		POST_FORM:      postForm,
		ResHeader:      resHeader,
		SrcByteBody:    srcByteBody,
		SrcByteResBody: srcByteResBody,
		SrcURL:         srcURLBytes,
		CreateTime:     cutTextCharsN(lg.CREATE_TIME, 32),
		UnixAddTime:    lg.UNIX_ADD_TIME,
		Day:            lg.Day,
	}
	if header != srcHeader || cookies != srcCookies || body != srcBody || resBody != srcResBody ||
		postForm != srcPostForm || resHeader != srcResHeader ||
		len(srcByteBody) != len(lg.SrcByteBody) || len(srcByteResBody) != len(lg.SrcByteResBody) ||
		len(srcURLBytes) != len(srcURL) || p.ReqUUID != lg.REQ_UUID || p.TenantId != lg.TenantId ||
		p.UserCode != lg.USER_CODE || p.HostCode != lg.HOST_CODE || p.Kind != kind || p.CreateTime != lg.CREATE_TIME {
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
