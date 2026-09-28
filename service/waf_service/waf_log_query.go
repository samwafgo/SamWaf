package waf_service

// 日志列表查询的分区扇出（M3 E5）。
//
// E4 之前「访问日期」与「日志归档库」各管一半时间语义，互不联动：日期选今天、分区停在实时，
// 结果就是空的，而界面不会告诉你数据在另一个分区里。M3 之后分区本身就是一段时间，
// 于是这里让分区**由时间范围算出来**：
//
//   - shardName == "auto"（前端默认）：按时间范围挑出候选分区，从新到旧顺序取数、跨分区翻页；
//   - 填了访问识别码：忽略时间与分区，按分区从新到旧逐个主键点查、命中即停；
//   - 明确指定了某个分区：照旧只查它（排障与导出要的就是这个）。
//
// 顺序取数之所以成立，是因为分区按时间互不重叠：整体按时间排序 == 各分区内排序后按分区时间拼接。
// 其它排序字段没有这个性质，所以跨分区时强制按时间排序（SortForcedTime 会告诉前端说明一句）。

import (
	"SamWaf/common/validfield"
	"SamWaf/common/zlog"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
)

// AutoShard 前端默认传的分区标识：让后端按时间范围自己算
const AutoShard = "auto"

// fanoutBudget 一次扇出查询的时间预算。比前端默认超时（20 秒）短一截：
// 宁可返回「部分结果 + 说明」，也不要让浏览器那边白屏超时，那种失败什么线索都留不下。
const fanoutBudget = 8 * time.Second

// fanoutParallel 同时统计几个分区。分区之间互不相干，串行 count 是把每个分区的
// 索引扫描时间直接相加——分区一多就必然超时。并发度不开太大：SQLite 下每个分区是独立文件，
// 开太多只会互相抢磁盘。
const fanoutParallel = 4

// maxUuidLookupShards 识别码直查最多翻几个分区。分区量级是「一个月一个」，
// 正常远达不到；设上限只是防止分片表被手工塞出成百上千条时把一次查询拖垮。
const maxUuidLookupShards = 60

// LogShardHit 一次查询里某个分区贡献了多少行
type LogShardHit struct {
	Name  string `json:"name"`  // 分片标识（share_dbs.file_name / 实时标识）
	Count int64  `json:"count"` // 该分区内命中条数
}

// LogQueryMeta 告诉前端这次查询到底查了哪里
type LogQueryMeta struct {
	Shards         []LogShardHit `json:"shards"`           // 本次覆盖的分区（按时间从新到旧）
	FoundIn        string        `json:"found_in"`         // 识别码直查命中的分区
	Scanned        int           `json:"scanned"`          // 识别码直查翻了几个分区
	UuidLookup     bool          `json:"uuid_lookup"`      // 是否走了识别码直查
	SortForcedTime bool          `json:"sort_forced_time"` // 跨分区时排序被强制成时间
	Partial        bool          `json:"partial"`          // 查询超出时间预算，结果与总数都只是一部分
	TookMs         int64         `json:"took_ms"`          // 本次耗时，界面用来解释「为什么只给了一部分」
}

// shardCountCache 归档分区的计数缓存。
//
// 归档分区是**不可变**的——写入只发生在实时库，归档只会被整体丢掉。所以同一组过滤条件
// 在同一个归档分区上的计数永远是同一个值，算一次就能一直用。
// 只有「时间范围完整覆盖该分区」时才缓存：这时时间条件是个空条件，计数与用户选的具体区间无关，
// 缓存键才稳定得下来（否则每次点「最近30天」毫秒数都不同，缓存永远不命中）。
// 实时分区一律不缓存。
var shardCountCache sync.Map

// shardCountCacheMax 缓存条目上限，超了整个清空。条目本身很小，这里只是防止
// 「每天不同过滤条件」日积月累把它撑大。
const shardCountCacheMax = 2000

var shardCountCacheN atomic.Int64

// InvalidateShardCounts 分区发生变化（切库、丢过期分区）时清空计数缓存。
func InvalidateShardCounts() {
	shardCountCache.Range(func(k, _ any) bool {
		shardCountCache.Delete(k)
		return true
	})
	shardCountCacheN.Store(0)
}

// countCacheKey 非时间条件的签名 + 分区名。时间条件不进键——只有完整覆盖时才会用到本缓存。
func countCacheKey(req request.WafAttackLogSearch, shard string) string {
	return strings.Join([]string{
		shard, req.ViewType, req.HostCode, req.Rule, req.ReqUuid, req.Action,
		req.SrcIp, req.StatusCode, req.Method, req.LogOnlyMode, req.FilterBy, req.FilterValue,
	}, "")
}

// logQuery 一个分区上组装好的查询：条件、参数、选列与强制索引都定死了，
// 之后只差 count 与 find 两个动作。
type logQuery struct {
	db          *gorm.DB
	tier        wafdb.TierTables
	shardName   string
	logTable    string
	forceIndex  string
	whereField  string
	whereValues []interface{}
	orderInfo   string
	isEventView bool
}

// buildLogQuery 在指定分区上组装查询条件。ignoreTime=true 时不带时间范围（识别码直查用）。
func buildLogQuery(req request.WafAttackLogSearch, shardName string, ignoreTime bool) (*logQuery, error) {
	splitFilterBys := strings.Split(req.FilterBy, "|")
	splitFilterValues := strings.Split(req.FilterValue, "|")
	// 解析当前分片的三层表：访问日志视图读 access_log，安全事件视图读 security_event；
	// 分层改造之前切出去的归档只有 web_logs，回落到它（列交集会自适应它的结构）。
	tier := wafdb.ResolveTierTables(shardName)
	logDB := tier.DB
	isEventView := req.ViewType == "event"
	logTable := tier.Access
	if isEventView {
		logTable = tier.Event
	}
	if logTable == "" {
		logTable = tier.WebLog
	}
	if logTable == "" {
		return nil, errors.New("该分片没有可查询的日志表")
	}
	// 老分片上的安全事件视图：web_logs 里按事件条件过滤（与引擎 abnormal 判定同一条规则）
	legacyEventView := isEventView && logTable == tier.WebLog
	isLegacyTable := strings.HasPrefix(logTable, wafdb.LogTableName)

	/*where条件*/
	var whereField = ""
	var whereValues []interface{}

	//where字段
	{
		// 按识别码直查时不带时间条件：识别码是主键，用户手里往往只有这串码、并不知道是哪天
		if !ignoreTime {
			whereField = whereField + " (unix_add_time>=? and unix_add_time<=?)"
		}
		if legacyEventView {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " (action<>? or rule<>? or log_only_mode=1) "
		}
		if len(req.HostCode) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " host_code=? "
		}
		if len(req.Rule) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " rule=? "
		}
		if len(req.ReqUuid) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " req_uuid=? "
		}
		if len(req.Action) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " action=? "
		}
		if len(req.SrcIp) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " src_ip=? "
		}
		if len(req.StatusCode) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " status_code=? "
		}
		if len(req.Method) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " method=? "
		}
		if len(req.LogOnlyMode) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " log_only_mode=? "
		}
		for _, by := range splitFilterBys {

			if len(by) > 0 {
				if !validfield.IsValidWebLogFilterField(by) {
					return nil, errors.New("输入过滤字段不合法")
				}
				if len(whereField) > 0 {
					whereField = whereField + " and "
				}
				if by == "guest_identification" {
					by = "guest_id_entification"
				}
				if by == "header" && !isLegacyTable {
					// header 随报文搬进 event_payload：访问日志视图没有这一列，
					// 安全事件视图走报文子查询（该视图行数小、且必有报文）。
					if !isEventView {
						return nil, errors.New("「请求」全文筛选仅在安全事件视图可用，访问日志视图请改用 UA / Referer 筛选")
					}
					if tier.Payload == "" {
						return nil, errors.New("该分片没有报文表，无法按「请求」内容筛选")
					}
					whereField = whereField + " req_uuid in (select req_uuid from " + tier.Payload + " where header like ?) "
				} else {
					whereField = whereField + " " + by + " like ? "
				}
			}
		}
	}
	//强制索引
	forceIndex := logTable
	{
		idxTime, idxIP := "idx_web_time_desc_tenant_user_code", "idx_web_time_desc_tenant_user_code_ip"
		if strings.HasPrefix(logTable, model.AccessLogTableName) {
			idxTime, idxIP = "idx_al_time", "idx_al_ip_time"
		} else if strings.HasPrefix(logTable, model.SecurityEventTableName) {
			idxTime, idxIP = "idx_se_time", "idx_se_ip_time"
		}
		if strings.Contains(whereField, "unix_add_time") && !strings.Contains(whereField, "src_ip") {
			forceIndex = dialect.Get().ForceIndexClause(logTable, idxTime)
		} else if strings.Contains(whereField, "src_ip") {
			forceIndex = dialect.Get().ForceIndexClause(logTable, idxIP)
		}
	}

	// 将字符串转换为 int64 类型
	unixBegin, err := strconv.ParseInt(req.UnixAddTimeBegin, 10, 64)
	if err != nil {
		fmt.Println("Error converting UnixAddTimeBegin to int64:", err)

	}

	unixEnd, err := strconv.ParseInt(req.UnixAddTimeEnd, 10, 64)
	if err != nil {
		fmt.Println("Error converting UnixAddTimeEnd to int64:", err)

	}

	//where字段赋值
	{
		if !ignoreTime {
			whereValues = append(whereValues, unixBegin)
			whereValues = append(whereValues, unixEnd)
		}
		if legacyEventView {
			whereValues = append(whereValues, "放行", "")
		}
		if len(req.HostCode) > 0 {
			whereValues = append(whereValues, req.HostCode)
		}
		if len(req.Rule) > 0 {
			whereValues = append(whereValues, req.Rule)
		}
		if len(req.ReqUuid) > 0 {
			whereValues = append(whereValues, req.ReqUuid)
		}
		if len(req.Action) > 0 {
			whereValues = append(whereValues, req.Action)
		}
		if len(req.SrcIp) > 0 {
			whereValues = append(whereValues, req.SrcIp)
		}
		if len(req.StatusCode) > 0 {
			whereValues = append(whereValues, req.StatusCode)
		}
		if len(req.Method) > 0 {
			whereValues = append(whereValues, req.Method)
		}
		if len(req.LogOnlyMode) > 0 {
			whereValues = append(whereValues, req.LogOnlyMode)
		}
		for _, val := range splitFilterValues {
			if len(val) > 0 {
				whereValues = append(whereValues, "%"+val+"%")
			}
		}
	}

	orderInfo := ""

	/**
	排序
	*/
	if WafLogServiceApp.isValidSortField(req.SortBy) {
		if req.SortDescending == "desc" {
			orderInfo = req.SortBy + " desc"
		} else {
			orderInfo = req.SortBy + " asc"
		}
	} else {
		return nil, errors.New("输入排序字段不合法")
	}
	if whereField == "" {
		// 条件全空（识别码直查又没给识别码）不该发出去：那是全表扫
		return nil, errors.New("查询条件为空")
	}
	return &logQuery{
		db:          logDB,
		tier:        tier,
		shardName:   shardName,
		logTable:    logTable,
		forceIndex:  forceIndex,
		whereField:  whereField,
		whereValues: whereValues,
		orderInfo:   orderInfo,
		isEventView: isEventView,
	}, nil
}

// count 该分区内命中多少行。ctx 到期时底层驱动会取消查询，不会把整次请求拖死。
func (q *logQuery) count(ctx context.Context) (int64, error) {
	var total int64
	if err := q.db.WithContext(ctx).Table(q.forceIndex).Where(q.whereField, q.whereValues...).Count(&total).Error; err != nil {
		return 0, fmt.Errorf("统计日志条数失败: %w", err)
	}
	return total, nil
}

// find 取一页。orderOverride 非空时覆盖排序（跨分区时统一按时间）。
func (q *logQuery) find(ctx context.Context, offset, limit int, orderOverride string) ([]innerbean.WebLog, error) {
	order := q.orderInfo
	if orderOverride != "" {
		order = orderOverride
	}
	var rows []innerbean.WebLog
	sel := webLogSelect(q.db, q.shardName, q.logTable, getWebLogListColumns(), "list")
	// 错误必须往上抛：吞掉它就只剩「有分页、没数据」，连从哪查起都不知道
	if err := q.db.WithContext(ctx).Select(sel).Table(q.forceIndex).Limit(limit).Offset(offset).
		Where(q.whereField, q.whereValues...).Order(order).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查询日志失败: %w", err)
	}
	// 标上来源分区：跨分区时界面要能说明这行从哪来，详情链接也能据此直达
	for i := range rows {
		rows[i].ShardName = q.shardName
	}
	// 安全事件视图每页补一回报文（事件必有报文）：「请求」列与详情都靠它
	if q.isEventView && len(rows) > 0 {
		ptrs := make([]*innerbean.WebLog, 0, len(rows))
		for i := range rows {
			ptrs = append(ptrs, &rows[i])
		}
		FillShardPayloads(q.shardName, ptrs)
	}
	return rows, nil
}

// logShard 一个候选分区：标识 + 它装着的时间范围
type logShard struct {
	Name  string
	Start time.Time
	End   time.Time
	Live  bool
}

// candidateShards 挑出与 [fromMs, toMs] 有交集的分区，按时间**从新到旧**排列。
// ignoreTime=true 时不做时间过滤，返回全部分区（识别码直查用）。
//
// 实时分区的起点取「最新归档分片的结束时间」：归档之后写进来的都还在实时库里。
// 一条归档记录的起止时间缺失时按「覆盖到边界」处理——宁可多查一个分区，也不要漏掉数据。
func candidateShards(fromMs, toMs int64, ignoreTime bool) []logShard {
	live := logShard{Name: wafdb.LiveLogName(), Live: true, End: time.Now()}

	all, err := WafShareDbServiceApp.GetAllShareDbApi()
	if err != nil {
		zlog.Warn("日志分区扇出", "读取分片列表失败，只查实时库", "error", err.Error())
		return []logShard{live}
	}

	shards := make([]logShard, 0, len(all)+1)
	for _, s := range all {
		if s.DbLogicType != "" && s.DbLogicType != "log" {
			continue
		}
		if s.FileName == "" || s.FileName == live.Name {
			continue
		}
		st, en := time.Time(s.StartTime), time.Time(s.EndTime)
		if en.After(live.Start) {
			live.Start = en
		}
		shards = append(shards, logShard{Name: s.FileName, Start: st, End: en})
	}
	shards = append(shards, live)
	sort.Slice(shards, func(i, j int) bool { return shards[i].End.After(shards[j].End) })

	if ignoreTime {
		return shards
	}
	from, to := time.UnixMilli(fromMs), time.UnixMilli(toMs)
	picked := make([]logShard, 0, len(shards))
	for _, sh := range shards {
		if !sh.Start.IsZero() && sh.Start.After(to) {
			continue
		}
		if !sh.End.IsZero() && sh.End.Before(from) {
			continue
		}
		picked = append(picked, sh)
	}
	if len(picked) == 0 {
		// 时间范围落在所有分区之外：仍然查一次实时库，让「查不到」是查出来的结论而不是算出来的
		return []logShard{live}
	}
	return picked
}

// GetListApiWithMeta 日志列表查询，并告诉调用方这次到底查了哪些分区。
//
// 三条路：填了识别码走直查（忽略时间与分区）／auto 走按时间范围扇出／指定了分区就只查它。
func (receiver *WafLogService) GetListApiWithMeta(req request.WafAttackLogSearch) ([]innerbean.WebLog, int64, LogQueryMeta, error) {
	var meta LogQueryMeta
	shardName := strings.TrimSpace(req.CurrrentDbName)
	// 只有明确传 auto 才扇出。空值沿用旧语义（实时库）——存量调用方与 Vue3 还在传空，
	// 悄悄改成扇出会让它们的每次查询都多打几个分区
	auto := shardName == AutoShard

	if auto && strings.TrimSpace(req.ReqUuid) != "" {
		return receiver.lookupByUuid(req)
	}

	ctx, cancel := context.WithTimeout(context.Background(), fanoutBudget)
	defer cancel()
	started := time.Now()
	defer func() { meta.TookMs = time.Since(started).Milliseconds() }()

	if !auto {
		q, err := buildLogQuery(req, shardName, false)
		if err != nil {
			return nil, 0, meta, err
		}
		total, err := q.count(ctx)
		if err != nil {
			return nil, 0, meta, err
		}
		rows, err := q.find(ctx, req.PageSize*(req.PageIndex-1), req.PageSize, "")
		if err != nil {
			return nil, 0, meta, err
		}
		meta.Shards = []LogShardHit{{Name: shardName, Count: total}}
		return rows, total, meta, nil
	}

	// —— 自动：按时间范围扇出 ——
	fromMs, _ := strconv.ParseInt(req.UnixAddTimeBegin, 10, 64)
	toMs, _ := strconv.ParseInt(req.UnixAddTimeEnd, 10, 64)
	shards := candidateShards(fromMs, toMs, false)

	// 跨分区时统一按时间排序：分区之间只有时间是可比的，按别的列排出来的「全局顺序」是假的
	order := ""
	if len(shards) > 1 {
		dir := "desc"
		if req.SortDescending == "asc" {
			dir = "asc"
		}
		order = "unix_add_time " + dir
		meta.SortForcedTime = req.SortBy != "unix_add_time"
		if dir == "asc" {
			for i, j := 0, len(shards)-1; i < j; i, j = i+1, j-1 {
				shards[i], shards[j] = shards[j], shards[i]
			}
		}
	}

	// 先把各分区的查询组装出来（只是探表拼条件，很便宜），统计放到后面并发做。
	// 组装不并发：SQLite 下解析分区会按需打开归档文件，串行更稳。
	type plan struct {
		q      *logQuery
		sh     logShard
		cnt    int64
		name   string
		cached bool
	}
	plans := make([]plan, 0, len(shards))
	var firstErr error
	for _, sh := range shards {
		q, err := buildLogQuery(req, sh.Name, false)
		if err != nil {
			// 某个分区没有可查的表（改造前的老分片）不该让整次查询失败，跳过即可
			if firstErr == nil {
				firstErr = err
			}
			zlog.Debug("日志分区扇出", "跳过分区", sh.Name, "原因", err.Error())
			continue
		}
		plans = append(plans, plan{q: q, sh: sh, name: sh.Name})
	}
	if len(plans) == 0 {
		if firstErr != nil {
			return nil, 0, meta, firstErr
		}
		return []innerbean.WebLog{}, 0, meta, nil
	}

	// 时间范围完整覆盖的归档分区：计数与具体区间无关，可以复用上次算过的值。
	// 归档不可变，缓存一直有效，直到切库或丢分区把它清掉。
	from, to := time.UnixMilli(fromMs), time.UnixMilli(toMs)
	cacheable := func(sh logShard) bool {
		if sh.Live || sh.Start.IsZero() || sh.End.IsZero() {
			return false
		}
		return !sh.Start.Before(from) && !sh.End.After(to)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, fanoutParallel)
	for i := range plans {
		i := i
		key := ""
		if cacheable(plans[i].sh) {
			key = countCacheKey(req, plans[i].name)
			if v, ok := shardCountCache.Load(key); ok {
				plans[i].cnt, plans[i].cached = v.(int64), true
				continue
			}
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			cnt, err := plans[i].q.count(ctx)
			if err != nil {
				zlog.Warn("日志分区扇出", "统计分区失败", plans[i].name, "error", err.Error())
				plans[i].cnt = -1 // 统计失败：这个分区的条数算不进总数，但它的行照取
				return
			}
			plans[i].cnt = cnt
			if key != "" {
				if shardCountCacheN.Add(1) > shardCountCacheMax {
					InvalidateShardCounts()
				}
				shardCountCache.Store(key, cnt)
			}
		}()
	}
	wg.Wait()

	var total int64
	for i := range plans {
		if plans[i].cnt < 0 {
			meta.Partial = true // 有分区没统计上，总数只是一部分
			plans[i].cnt = 0
			continue
		}
		total += plans[i].cnt
	}
	if ctx.Err() != nil {
		meta.Partial = true
	}

	offset := int64(req.PageSize * (req.PageIndex - 1))
	remaining := req.PageSize
	rows := make([]innerbean.WebLog, 0, req.PageSize)
	for _, p := range plans {
		if p.cnt > 0 {
			meta.Shards = append(meta.Shards, LogShardHit{Name: p.name, Count: p.cnt})
		}
		if remaining <= 0 || p.cnt == 0 {
			continue
		}
		if offset >= p.cnt {
			offset -= p.cnt
			continue
		}
		if ctx.Err() != nil {
			// 预算用完了：把已经拿到的行还回去并标 partial，
			// 让界面提示「缩小时间范围或锁定分区」，而不是让浏览器那边干等到超时
			meta.Partial = true
			break
		}
		part, err := p.q.find(ctx, int(offset), remaining, order)
		if err != nil {
			if ctx.Err() != nil {
				meta.Partial = true
				break
			}
			return nil, 0, meta, err
		}
		rows = append(rows, part...)
		remaining -= len(part)
		offset = 0
	}
	return rows, total, meta, nil
}

// lookupByUuid 按访问识别码直查：忽略时间与分区，从新到旧逐个分区做主键点查，命中即停。
//
// 识别码是三张日志表的主键，一次点查就是一次索引命中；最常见的来路是访客把拦截页上的
// 识别码报给管理员——他手里只有这串码，不知道是哪天，更不知道在哪个分区。
// 查不到不是错误：调用方按空结果处理，界面负责解释可能的原因（已过保留期 / 抄错 / 本就没记录）。
func (receiver *WafLogService) lookupByUuid(req request.WafAttackLogSearch) ([]innerbean.WebLog, int64, LogQueryMeta, error) {
	meta := LogQueryMeta{UuidLookup: true}
	ctx, cancel := context.WithTimeout(context.Background(), fanoutBudget)
	defer cancel()
	started := time.Now()
	defer func() { meta.TookMs = time.Since(started).Milliseconds() }()

	shards := candidateShards(0, 0, true)
	var firstErr error
	for i, sh := range shards {
		if i >= maxUuidLookupShards {
			zlog.Warn("识别码直查", "分区过多，已停在上限", maxUuidLookupShards)
			break
		}
		if ctx.Err() != nil {
			meta.Partial = true
			break
		}
		meta.Scanned = i + 1
		q, err := buildLogQuery(req, sh.Name, true)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		found, err := q.find(ctx, 0, req.PageSize, "")
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			zlog.Warn("识别码直查", "分区查询失败", sh.Name, "error", err.Error())
			continue
		}
		if len(found) > 0 {
			meta.FoundIn = sh.Name
			meta.Shards = []LogShardHit{{Name: sh.Name, Count: int64(len(found))}}
			return found, int64(len(found)), meta, nil
		}
	}
	return []innerbean.WebLog{}, 0, meta, nil
}

// ResolveDetailShard 详情按识别码定位分区：明确给了就用它，
// auto / 空 时从新到旧找出第一个有这条记录的分区。找不到返回空字符串（调用方回落实时库）。
func ResolveDetailShard(shardName, reqUuid string) string {
	name := strings.TrimSpace(shardName)
	if name != "" && name != AutoShard {
		return name
	}
	if strings.TrimSpace(reqUuid) == "" {
		return name
	}
	ctx, cancel := context.WithTimeout(context.Background(), fanoutBudget)
	defer cancel()
	for i, sh := range candidateShards(0, 0, true) {
		if i >= maxUuidLookupShards || ctx.Err() != nil {
			break
		}
		tier := wafdb.ResolveTierTables(sh.Name)
		if tier.DB == nil {
			continue
		}
		for _, table := range []string{tier.Event, tier.Access, tier.WebLog} {
			if table == "" {
				continue
			}
			var cnt int64
			if err := tier.DB.WithContext(ctx).Table(table).Where("req_uuid = ?", reqUuid).Count(&cnt).Error; err != nil {
				continue
			}
			if cnt > 0 {
				return sh.Name
			}
		}
	}
	return ""
}
