package waf_service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"

	"gorm.io/gorm"
)

type WafCCThresholdService struct{}

var WafCCThresholdServiceApp = new(WafCCThresholdService)

const (
	ccThDefaultDays = 7
	ccThMaxDays     = 30
	// ccThMinReq / ccThMinDim 样本下限。低于这个量算出来的分位数没有代表性，
	// 宁可不给推荐，也不给一个看起来很准的错数。
	ccThMinReq    = 1000
	ccThMinDim    = 20
	ccThTopReturn = 50
)

// 预算与容量阈值使用包级变量，方便单测直接注入小值做确定性回归验证。
var (
	// ccThMaxScanRows 单次推荐允许纳入统计的有效匹配样本上限。
	ccThMaxScanRows int64 = 1000000
	// ccThMaxRawRows 单次推荐允许从数据库读取的原始行上限（含静态资源/被过滤行）。
	ccThMaxRawRows int64 = 3500000
	// ccThQueryBudget 服务端硬时间预算（与日志扇出 8 秒对齐，远低于前端默认 20 秒超时）。
	ccThQueryBudget time.Duration = 8 * time.Second
	// ccThSemAcquireWait 等待并发闸门的最长时间。
	ccThSemAcquireWait time.Duration = 2 * time.Second
	// ccThMaxTrackDims 维度峰值表最大键数，防止高频随机 URL 扫描撑爆堆内存。
	ccThMaxTrackDims int = 100000
	// ccThSem 进程内并发上限，防止连点/多管理员同时触发重扫描争抢磁盘 I/O。
	ccThSem = make(chan struct{}, 2)
)

// ccThTableRe 分片表名只允许字母数字下划线：表名不能参数化，必须先校验再拼进 SQL。
var ccThTableRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// ccThPlan 一次推荐查询的执行计划（口径固定下来之后的产物）。
type ccThPlan struct {
	ipCol       string          // 客户端 IP 列名；host_total 维度为空
	dimCols     []string        // 统计维度对应的日志列；空 = 按站点总量
	where       string          // 固定以 tenant_id = ? AND user_code = ? AND host_code = ? 打头
	args        []interface{}   // 对应 where 的参数
	excludeExts map[string]bool // dynamic 口径需排除的静态后缀集合（小写带前导点）
	needURL     bool            // 是否需要从数据库读取 url 列
	bucketMs    int64
	scopeNote   string
}

// RecommendApi 按历史流量推荐 CC 阈值（兼容旧无 ctx 签名）。
func (receiver *WafCCThresholdService) RecommendApi(req request.WafCCThresholdRecommendReq) response2.CCThresholdRep {
	return receiver.RecommendApiWithCtx(context.Background(), req)
}

// RecommendApiWithCtx 按历史流量推荐 CC 阈值（支持请求取消与服务端硬时间预算）。
//
// 口径必须与运行时一致，否则算出来的分布和实际计数对不上：
//   - 客户端 IP 取哪一列跟站点的 IPMode 走（代理→src_ip，网卡→net_src_ip）
//   - 「排除静态资源」在 Go 侧按 path.Ext(去查询串后的路径) 判定，与 ccrule/matcher.go 一致
//   - 分桶用固定窗口（运行时是 10 桶近似滑动窗口，固定桶会略低估峰值，属已知偏差）
//   - 复用 candidateShards 按时间从新到旧懒打开分片，按索引顺序单遍流式归并，避免预探量与双扫
func (receiver *WafCCThresholdService) RecommendApiWithCtx(ctx context.Context, req request.WafCCThresholdRecommendReq) response2.CCThresholdRep {
	rep := response2.CCThresholdRep{Top: []response2.CCThresholdTopRep{}}
	if ctx == nil {
		ctx = context.Background()
	}

	host := WafHostServiceApp.GetDetailByCodeApi(req.HostCode)
	if host.Code == "" {
		rep.Reason = "网站不存在"
		return rep
	}

	window := req.WindowSec
	if window <= 0 {
		window = 60
	}
	if window > 86400 {
		window = 86400
	}
	days := req.Days
	if days <= 0 {
		days = ccThDefaultDays
	}
	// 可选天数上限跟随 access_log 的保留期：选到没有数据的区间只会算出偏小的推荐值
	maxDays := ccThMaxDays
	if global.GDATA_ACCESS_LOG_RETENTION_DAYS < int64(maxDays) {
		maxDays = int(global.GDATA_ACCESS_LOG_RETENTION_DAYS)
	}
	if days > maxDays {
		days = maxDays
	}
	rep.WindowSec = window

	// off 档正常请求不入库，推荐功能失去数据基础——明说原因而不是算个偏小的值出来
	if global.GDATA_ACCESS_LOG_MODE == "off" {
		rep.Reason = "访问日志档位为 off（仅安全事件入库），正常请求不留存，无法按历史流量推荐阈值。" +
			"需要这个功能请在系统配置把 access_log_mode 调回 db 或 sample。"
		return rep
	}

	// ── 先判定这套口径能不能从日志里可靠还原 ──
	switch req.StatDim {
	case "", model.CCStatDimIP, model.CCStatDimIPURI, model.CCStatDimHostTotal:
	default:
		rep.Reason = "统计维度「" + ccThDimName(req.StatDim) + "」暂不支持推荐：日志里没有可靠还原该维度的字段，" +
			"硬算出来的分布和运行时对不上。可以先切到「按IP」估个量级。"
		return rep
	}
	if req.CountScope == model.CCCountScopeDocument {
		rep.Reason = "统计口径「仅页面文档」暂不支持推荐：该口径靠请求头 Sec-Fetch-Dest 判定，" +
			"日志里存的是整段头文本，还原不可靠。可以切到「排除静态资源」再推荐。"
		return rep
	}

	plan, err := ccThBuildPlan(req, host, window)
	if err != nil {
		rep.Reason = err.Error()
		return rep
	}
	rep.ScopeNote = plan.scopeNote

	// ── 并发闸门：最多允许 2 个重扫描同时运行，避免重试或连点放大磁盘压力 ──
	waitTimer := time.NewTimer(ccThSemAcquireWait)
	select {
	case ccThSem <- struct{}{}:
		waitTimer.Stop()
		defer func() { <-ccThSem }()
	case <-ctx.Done():
		waitTimer.Stop()
		rep.Reason = "查询已取消"
		return rep
	case <-waitTimer.C:
		rep.Reason = "当前已有历史流量统计任务正在执行，请稍候几秒再试。"
		return rep
	}

	budget := ccThQueryBudget
	queryCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	started := time.Now()

	nowMs := started.UnixMilli()
	targetStartMs := started.AddDate(0, 0, -days).UnixMilli()
	shards := candidateShards(targetStartMs, nowMs, false)

	hist := map[int64]int64{}
	dimStats := map[string]*response2.CCThresholdTopRep{}
	curCounts := map[string]int64{}

	var (
		curBucket       int64 = -1
		oldestFlushedMs int64 = nowMs
		flushedBuckets  int64
		flushedReq      int64
		matchedRows     int64
		rawRows         int64
		evictedDims     int64
		truncatedBy     string
	)

	flushBucket := func() {
		if curBucket < 0 || len(curCounts) == 0 {
			return
		}
		flushedBuckets++
		oldestFlushedMs = curBucket
		for key, cnt := range curCounts {
			hist[cnt]++
			flushedReq += cnt
			if len(plan.dimCols) == 0 {
				continue
			}
			if cur, ok := dimStats[key]; ok {
				if cnt > cur.Peak {
					cur.Peak = cnt
				}
				cur.Total += cnt
				continue
			}
			if len(dimStats) >= ccThMaxTrackDims {
				for k, v := range dimStats {
					if v.Peak <= 1 && v.Total <= 1 {
						delete(dimStats, k)
						evictedDims++
						if len(dimStats) < ccThMaxTrackDims*3/4 {
							break
						}
					}
				}
			}
			if len(dimStats) >= ccThMaxTrackDims {
				evictedDims++
				continue
			}
			dimStats[key] = &response2.CCThresholdTopRep{
				DimValue: key,
				Peak:     cnt,
				Total:    cnt,
			}
		}
		clear(curCounts)
	}

	// ── 从新到旧懒加载分片，单遍流式扫描并按时间桶归并 ──
	for _, sh := range shards {
		if truncatedBy != "" {
			break
		}
		if time.Since(started) >= budget || queryCtx.Err() != nil {
			truncatedBy = "time_budget"
			break
		}

		db, table := ccThResolveShardTable(sh)
		if db == nil || table == "" {
			continue
		}

		remainingRaw := ccThMaxRawRows - rawRows
		if remainingRaw <= 0 {
			truncatedBy = "raw_rows"
			break
		}

		fromClause := ccThSelectFromClause(db, sh.Name, table)
		cols := ccThSelectCols(plan)
		sqlStr := "SELECT " + cols + " FROM " + fromClause +
			" WHERE " + plan.where + " AND unix_add_time >= ? AND unix_add_time <= ? ORDER BY unix_add_time DESC LIMIT ?"
		args := make([]interface{}, 0, len(plan.args)+3)
		args = append(args, plan.args...)
		args = append(args, targetStartMs, nowMs, remainingRaw)

		rows, qerr := db.WithContext(queryCtx).Raw(sqlStr, args...).Rows()
		if qerr != nil {
			if queryCtx.Err() != nil || time.Since(started) >= budget {
				truncatedBy = "time_budget"
				break
			}
			continue
		}

		var (
			ts     int64
			ipVal  string
			urlVal string
		)
		for rows.Next() {
			rawRows++
			if rawRows&1023 == 0 {
				if time.Since(started) >= budget || queryCtx.Err() != nil {
					truncatedBy = "time_budget"
					break
				}
				if rawRows >= ccThMaxRawRows {
					truncatedBy = "raw_rows"
					break
				}
			}

			var scanErr error
			switch {
			case plan.ipCol == "" && !plan.needURL:
				scanErr = rows.Scan(&ts)
			case plan.ipCol == "" && plan.needURL:
				scanErr = rows.Scan(&ts, &urlVal)
			case plan.ipCol != "" && !plan.needURL:
				scanErr = rows.Scan(&ts, &ipVal)
			default:
				scanErr = rows.Scan(&ts, &ipVal, &urlVal)
			}
			if scanErr != nil {
				continue
			}

			if len(plan.excludeExts) > 0 && ccThIsStaticURL(urlVal, plan.excludeExts) {
				continue
			}

			var dimKey string
			switch len(plan.dimCols) {
			case 0:
				dimKey = "_total_"
			case 1:
				if ipVal == "" {
					continue
				}
				dimKey = ipVal
			default:
				if ipVal == "" {
					continue
				}
				if urlVal != "" {
					dimKey = ipVal + " " + urlVal
				} else {
					dimKey = ipVal
				}
			}

			b := ts - ts%plan.bucketMs
			if curBucket == -1 {
				curBucket = b
			} else if b < curBucket {
				flushBucket()
				curBucket = b
			} else if b > curBucket {
				// 跨分片边界偶发毫秒级乱序时归入当前桶，保证流式单调性
				b = curBucket
			}

			curCounts[dimKey]++
			matchedRows++
			if matchedRows >= ccThMaxScanRows {
				truncatedBy = "rows"
				break
			}
		}
		if truncatedBy != "" {
			// MySQL/PG 提前截断时先取消 ctx 再 Close，避免驱动排空服务端剩余结果集
			cancel()
		}
		_ = rows.Close()

		if truncatedBy == "" && (queryCtx.Err() != nil || time.Since(started) >= budget) {
			truncatedBy = "time_budget"
		}
	}

	if truncatedBy == "" {
		flushBucket()
		rep.Days = days
		rep.SampleHours = days * 24
	} else {
		rep.Sampled = true
		rep.TruncatedBy = truncatedBy
		// 提前截断时丢弃扫了一半的尾桶，确保直方图里每个窗口都完整；
		// 仅当整个扫描停在唯一一个超大窗口内尚未刷出任何桶时才兜底保留。
		if flushedBuckets == 0 && len(curCounts) > 0 {
			flushBucket()
		}
		coveredMs := nowMs - oldestFlushedMs
		if coveredMs < 0 {
			coveredMs = 0
		}
		sampleHours := int(math.Ceil(float64(coveredMs) / float64(time.Hour.Milliseconds())))
		if sampleHours < 1 {
			sampleHours = 1
		}
		sampleDays := int(math.Ceil(float64(sampleHours) / 24.0))
		if sampleDays < 1 {
			sampleDays = 1
		}
		rep.SampleHours = sampleHours
		rep.Days = sampleDays
		if sampleHours < 24 {
			note := fmt.Sprintf("本次样本实际覆盖最近 %d 小时（未满 24 小时完整昼夜周期）；若当前处于业务低谷期，建议优先选择「宽松」档并先观察 24 小时。", sampleHours)
			if rep.ScopeNote != "" {
				rep.ScopeNote += "\n" + note
			} else {
				rep.ScopeNote = note
			}
		}
	}

	var samples int64
	for _, freq := range hist {
		samples += freq
	}
	rep.TotalReq = flushedReq
	if len(plan.dimCols) == 0 {
		rep.TotalDim = 1
	} else {
		rep.TotalDim = int64(len(dimStats)) + evictedDims
	}

	if rep.TotalReq < ccThMinReq || (len(plan.dimCols) > 0 && rep.TotalDim < ccThMinDim) || samples == 0 {
		if truncatedBy == "time_budget" || truncatedBy == "raw_rows" {
			rep.Reason = fmt.Sprintf("在查询保护上限（%.0f 秒）内已扫描最近 %d 小时数据，该站点口径下仅匹配到 %d 条请求、%d 个统计对象"+
				"（需要至少 %d 条请求且 %d 个统计对象才算得出可信分布）。",
				budget.Seconds(), rep.SampleHours, rep.TotalReq, rep.TotalDim, ccThMinReq, ccThMinDim)
		} else {
			rep.Reason = fmt.Sprintf("样本不足：最近 %d 天这个口径下只有 %d 条请求、%d 个统计对象"+
				"（需要至少 %d 条请求且 %d 个统计对象才算得出可信分布）。"+
				"只有一两个统计对象时，算出来的其实是「这一个访客的习惯」，拿它当全站阈值会误伤。",
				rep.Days, rep.TotalReq, rep.TotalDim, ccThMinReq, ccThMinDim)
		}
		rep.Reference = "可先用业界起步值：按 IP 每分钟 100 次（来源：Cloudflare Rate Limiting 文档的入门建议），" +
			"动作设为「观察」跑几天，再回来推荐。"
		return rep
	}

	rep.P50 = ccThPercentile(hist, samples, 0.50)
	rep.P95 = ccThPercentile(hist, samples, 0.95)
	rep.P99 = ccThPercentile(hist, samples, 0.99)
	rep.Max = ccThPercentile(hist, samples, 1)

	rep.Loose = ccThCeil(rep.P99, 5)
	rep.Balanced = ccThCeil(rep.P99, 3)
	rep.Strict = ccThCeil(rep.P99, 1.5)

	list := make([]response2.CCThresholdTopRep, 0, len(dimStats))
	for _, v := range dimStats {
		list = append(list, *v)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Peak != list[j].Peak {
			return list[i].Peak > list[j].Peak
		}
		if list[i].Total != list[j].Total {
			return list[i].Total > list[j].Total
		}
		return list[i].DimValue < list[j].DimValue
	})
	if len(list) > ccThTopReturn {
		list = list[:ccThTopReturn]
	}
	rep.Top = list
	rep.Supported = true
	return rep
}

// ccThBuildPlan 把规则口径翻成 SQL 片段与 Go 侧静态过滤集合。所有取值一律走占位符，列名走白名单。
func ccThBuildPlan(req request.WafCCThresholdRecommendReq, host model.Hosts, window int) (*ccThPlan, error) {
	plan := &ccThPlan{bucketMs: int64(window) * 1000}

	// 客户端 IP 列跟站点的 IPMode 走，与运行时同一口径
	ipCol := "net_src_ip"
	if host.IPMode == "proxy" {
		ipCol = "src_ip"
	}
	switch req.StatDim {
	case model.CCStatDimHostTotal:
		plan.ipCol = ""
		plan.dimCols = nil
	case model.CCStatDimIPURI:
		plan.ipCol = ipCol
		plan.dimCols = []string{ipCol, "url"}
	default:
		plan.ipCol = ipCol
		plan.dimCols = []string{ipCol}
	}

	// 裸 SQL 不触发 GORM before_query，必须显式带 tenant_id + user_code，
	// 既保证租户隔离，也命中 idx_al_host_time / idx_al_time 的最左前导列。
	conds := []string{"tenant_id = ?", "user_code = ?", "host_code = ?"}
	args := []interface{}{global.GWAF_TENANT_ID, global.GWAF_USER_CODE, req.HostCode}

	// 统计口径：排除静态资源改在 Go 侧按 path.Ext(纯路径) 判定，
	// 避免 SQL 展开 40 次前导 % 通配符扫描及查询串误判。
	if req.CountScope == "" || req.CountScope == model.CCCountScopeDynamic {
		rule := &model.AntiCCRule{ExcludeExts: req.ExcludeExts}
		exts := rule.ExcludeExtList()
		plan.excludeExts = make(map[string]bool, len(exts))
		for _, ext := range exts {
			plan.excludeExts[ext] = true
		}
	}
	plan.needURL = len(plan.excludeExts) > 0 || req.StatDim == model.CCStatDimIPURI

	// 匹配范围：只按 uri 条件收窄，其余条件（UA / 地域 / 请求头…）日志里还原不可靠，
	// 收窄不了就如实说明，不假装样本已经收敛。
	if req.MatchMode == model.CCMatchModeSimple && strings.TrimSpace(req.Conditions) != "" {
		var list []model.MatchCondition
		if err := json.Unmarshal([]byte(req.Conditions), &list); err != nil {
			return nil, fmt.Errorf("匹配条件解析失败")
		}
		others := 0
		for _, c := range list {
			if c.Field != model.CCFieldURI {
				others++
				continue
			}
			sub, subArgs := ccThURICond(c)
			if sub == "" {
				others++
				continue
			}
			conds = append(conds, sub)
			args = append(args, subArgs...)
		}
		if others > 0 {
			plan.scopeNote = fmt.Sprintf("本规则还有 %d 个非 URI 条件（如 UA / 地域 / 请求头），"+
				"日志里还原不可靠，样本没有按它们收窄——实际命中会少于这里的估算。", others)
		}
	} else if req.MatchMode == model.CCMatchModeExpr {
		plan.scopeNote = "本规则用的是高级匹配条件（脚本），样本没有按脚本收窄——实际命中会少于这里的估算。"
	}

	plan.where = strings.Join(conds, " AND ")
	plan.args = args
	return plan, nil
}

// ccThIsStaticURL 判断日志里的 RequestURI 是否属于需排除的静态资源。
// 先剥离查询串与锚点再按 path.Ext 匹配，与运行时 ccrule/matcher.go:121 保持一致。
func ccThIsStaticURL(rawURL string, exclude map[string]bool) bool {
	if len(exclude) == 0 || rawURL == "" {
		return false
	}
	p := rawURL
	if idx := strings.IndexAny(p, "?#"); idx >= 0 {
		p = p[:idx]
	}
	ext := path.Ext(p)
	if ext == "" || len(ext) > 10 {
		return false
	}
	return exclude[strings.ToLower(ext)]
}

func ccThSelectCols(plan *ccThPlan) string {
	switch {
	case plan.ipCol == "" && !plan.needURL:
		return "unix_add_time"
	case plan.ipCol == "" && plan.needURL:
		return "unix_add_time, url"
	case plan.ipCol != "" && !plan.needURL:
		return "unix_add_time, " + plan.ipCol
	default:
		return "unix_add_time, " + plan.ipCol + ", url"
	}
}

func ccThResolveShardTable(sh logShard) (*gorm.DB, string) {
	tier := wafdb.ResolveTierTables(sh.Name)
	if tier.Err != nil || tier.DB == nil {
		return nil, ""
	}
	var table string
	if sh.Live {
		if tier.Access != "" && dialect.Get().TableExists(tier.DB, tier.Access) {
			table = tier.Access
		} else if tier.WebLog != "" && dialect.Get().TableExists(tier.DB, tier.WebLog) {
			table = tier.WebLog
		}
	} else {
		table = tier.Access
		if table == "" {
			table = tier.WebLog
		}
	}
	if table == "" || !ccThTableRe.MatchString(table) {
		return nil, ""
	}
	return tier.DB, table
}

func ccThSelectFromClause(db *gorm.DB, shardName, table string) string {
	if strings.HasPrefix(table, model.AccessLogTableName) {
		if wafdb.ShardHasIndex(db, shardName, table, "idx_al_host_time") {
			return dialect.Get().ForceIndexClause(table, "idx_al_host_time")
		}
		if wafdb.ShardHasIndex(db, shardName, table, "idx_al_time") {
			return dialect.Get().ForceIndexClause(table, "idx_al_time")
		}
	} else if strings.HasPrefix(table, wafdb.LogTableName) {
		if wafdb.ShardHasIndex(db, shardName, table, "idx_web_time_desc_tenant_user_code") {
			return dialect.Get().ForceIndexClause(table, "idx_web_time_desc_tenant_user_code")
		}
	}
	return table
}

// ccThURICond 把一条 uri 条件翻成 SQL。
// 规则里的 uri 取的是 URL.Path（不含查询串），而日志的 url 列含查询串，所以要多带一种形态。
func ccThURICond(c model.MatchCondition) (string, []interface{}) {
	vals := []string(c.Value)
	clean := make([]string, 0, len(vals))
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			clean = append(clean, v)
		}
	}
	if len(clean) == 0 {
		return "", nil
	}
	switch c.Op {
	case model.CCOpEq, model.CCOpIn:
		parts := make([]string, 0, len(clean))
		args := make([]interface{}, 0, len(clean)*2)
		for _, v := range clean {
			parts = append(parts, "(url = ? OR url LIKE ?)")
			args = append(args, v, v+"?%")
		}
		return "(" + strings.Join(parts, " OR ") + ")", args
	case model.CCOpPrefix:
		parts := make([]string, 0, len(clean))
		args := make([]interface{}, 0, len(clean))
		for _, v := range clean {
			parts = append(parts, "url LIKE ?")
			args = append(args, v+"%")
		}
		return "(" + strings.Join(parts, " OR ") + ")", args
	}
	return "", nil
}

// ccThPercentile 从「请求数 → 出现次数」直方图里取分位数。
// 直方图的好处是行数只有 max(请求数) 那么多，再大的日志库也不用把明细拉回进程。
func ccThPercentile(hist map[int64]int64, samples int64, p float64) int64 {
	if samples <= 0 {
		return 0
	}
	keys := make([]int64, 0, len(hist))
	for k := range hist {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	target := int64(math.Ceil(float64(samples) * p))
	if target < 1 {
		target = 1
	}
	var acc int64
	for _, k := range keys {
		acc += hist[k]
		if acc >= target {
			return k
		}
	}
	if len(keys) == 0 {
		return 0
	}
	return keys[len(keys)-1]
}

func ccThCeil(p99 int64, k float64) int64 {
	v := int64(math.Ceil(float64(p99) * k))
	if v < 1 {
		v = 1
	}
	return v
}

func ccThDimName(dim string) string {
	switch dim {
	case model.CCStatDimCookie:
		return "Cookie值"
	case model.CCStatDimHeader:
		return "请求头值"
	case model.CCStatDimQuery:
		return "查询参数值"
	case model.CCStatDimBody:
		return "请求体字段"
	case model.CCStatDimSession:
		return "会话"
	}
	return dim
}
