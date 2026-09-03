package waf_service

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/wafdb"

	"gorm.io/gorm"
)

type WafCCThresholdService struct{}

var WafCCThresholdServiceApp = new(WafCCThresholdService)

const (
	ccThDefaultDays = 7
	ccThMaxDays     = 30
	// ccThMaxScanRows 单次推荐允许扫描的样本上限。超过就缩短天数重来，
	// 而不是硬算——这个功能是给人省事的，不能变成新的性能问题。
	ccThMaxScanRows = 2000000
	// ccThMinReq / ccThMinDim 样本下限。低于这个量算出来的分位数没有代表性，
	// 宁可不给推荐，也不给一个看起来很准的错数。
	ccThMinReq = 1000
	ccThMinDim = 20
	// ccThTopPerShard 每个分片取的候选客户端数；合并后再截 ccThTopReturn 条给前端。
	// 取多于返回数是为了降低「某客户端在每片都排不进前列、合起来却是第一」的漏选。
	ccThTopPerShard = 200
	ccThTopReturn   = 50
)

// ccThTableRe 分片表名只允许字母数字下划线：表名不能参数化，必须先校验再拼进 SQL。
var ccThTableRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// ccThShard 一个待查的日志分片。
type ccThShard struct {
	db    *gorm.DB
	table string
}

// ccThPlan 一次推荐查询的执行计划（口径固定下来之后的产物）。
type ccThPlan struct {
	dimCols   []string // 统计维度对应的日志列；空 = 按站点总量
	where     string
	args      []interface{}
	bucketMs  int64
	scopeNote string
}

// RecommendApi 按历史流量推荐 CC 阈值。
//
// 口径必须与运行时一致，否则算出来的分布和实际计数对不上：
//   - 客户端 IP 取哪一列跟站点的 IPMode 走（代理→src_ip，网卡→net_src_ip）
//   - 「排除静态资源」用规则自己那份后缀清单，且要处理日志里 url 带查询串的情况
//   - 分桶用固定窗口（运行时是 10 桶近似滑动窗口，固定桶会略低估峰值，属已知偏差）
func (receiver *WafCCThresholdService) RecommendApi(req request.WafCCThresholdRecommendReq) response2.CCThresholdRep {
	rep := response2.CCThresholdRep{Top: []response2.CCThresholdTopRep{}}

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
	if days > ccThMaxDays {
		days = ccThMaxDays
	}
	rep.WindowSec = window

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

	shards := ccThResolveShards(days)

	// ── 探量：超上限就缩短天数，而不是硬扫 ──
	for {
		start := time.Now().AddDate(0, 0, -days).UnixNano() / 1e6
		total := ccThCountRows(shards, plan, start)
		if total <= ccThMaxScanRows || days <= 1 {
			rep.Days = days
			rep.TotalReq = total
			break
		}
		days = days / 2
		if days < 1 {
			days = 1
		}
		rep.Sampled = true
	}
	if rep.Days == 0 {
		rep.Days = days
	}

	start := time.Now().AddDate(0, 0, -rep.Days).UnixNano() / 1e6

	hist := map[int64]int64{}
	tops := map[string]*response2.CCThresholdTopRep{}
	for _, sh := range shards {
		ccThAccumHistogram(sh, plan, start, hist)
		if len(plan.dimCols) > 0 {
			ccThAccumTop(sh, plan, start, tops)
		}
	}

	var samples int64
	for _, freq := range hist {
		samples += freq
	}
	rep.TotalDim = int64(len(tops))
	if len(plan.dimCols) == 0 {
		rep.TotalDim = 1
	}
	if rep.TotalReq < ccThMinReq || (len(plan.dimCols) > 0 && rep.TotalDim < ccThMinDim) || samples == 0 {
		rep.Reason = fmt.Sprintf("样本不足：最近 %d 天这个口径下只有 %d 条请求、%d 个统计对象"+
			"（需要至少 %d 条请求且 %d 个统计对象才算得出可信分布）。"+
			"只有一两个统计对象时，算出来的其实是「这一个访客的习惯」，拿它当全站阈值会误伤。",
			rep.Days, rep.TotalReq, rep.TotalDim, ccThMinReq, ccThMinDim)
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

	list := make([]response2.CCThresholdTopRep, 0, len(tops))
	for _, v := range tops {
		list = append(list, *v)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Peak != list[j].Peak {
			return list[i].Peak > list[j].Peak
		}
		return list[i].Total > list[j].Total
	})
	if len(list) > ccThTopReturn {
		list = list[:ccThTopReturn]
	}
	rep.Top = list
	rep.Supported = true
	return rep
}

// ccThBuildPlan 把规则口径翻成 SQL 片段。所有取值一律走占位符，列名走白名单。
func ccThBuildPlan(req request.WafCCThresholdRecommendReq, host model.Hosts, window int) (*ccThPlan, error) {
	plan := &ccThPlan{bucketMs: int64(window) * 1000}

	// 客户端 IP 列跟站点的 IPMode 走，与运行时同一口径
	ipCol := "net_src_ip"
	if host.IPMode == "proxy" {
		ipCol = "src_ip"
	}
	switch req.StatDim {
	case model.CCStatDimHostTotal:
		plan.dimCols = nil
	case model.CCStatDimIPURI:
		plan.dimCols = []string{ipCol, "url"}
	default:
		plan.dimCols = []string{ipCol}
	}

	conds := []string{"host_code = ?"}
	args := []interface{}{req.HostCode}

	// 统计口径：排除静态资源。日志的 url 列存的是 RequestURI（可能带查询串），
	// 所以每个后缀要比两次：结尾命中、以及后面跟着 ? 的情况。
	if req.CountScope == "" || req.CountScope == model.CCCountScopeDynamic {
		rule := &model.AntiCCRule{ExcludeExts: req.ExcludeExts}
		for _, ext := range rule.ExcludeExtList() {
			conds = append(conds, "url NOT LIKE ?", "url NOT LIKE ?")
			args = append(args, "%"+ext, "%"+ext+"?%")
		}
	}

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

// ccThResolveShards 列出需要查的日志分片：活跃表 + 时间范围有交集的归档分片。
// 只查活跃表的话，天数一长就只算到最近一片，推荐值会偏小。
func ccThResolveShards(days int) []ccThShard {
	out := []ccThShard{}
	if global.GWAF_LOCAL_LOG_DB != nil {
		out = append(out, ccThShard{db: global.GWAF_LOCAL_LOG_DB, table: wafdb.LogTableName})
	}
	from := time.Now().AddDate(0, 0, -days)
	all, err := WafShareDbServiceApp.GetAllShareDbApi()
	if err != nil {
		return out
	}
	for _, s := range all {
		if s.DbLogicType != "" && s.DbLogicType != "log" {
			continue
		}
		if time.Time(s.EndTime).Before(from) {
			continue
		}
		db, table := wafdb.ResolveLogDB(s.FileName)
		if db == nil || !ccThTableRe.MatchString(table) {
			continue
		}
		if db == global.GWAF_LOCAL_LOG_DB && table == wafdb.LogTableName {
			continue // 分片解析失败被降级回活跃表，别重复统计
		}
		out = append(out, ccThShard{db: db, table: table})
	}
	return out
}

func ccThCountRows(shards []ccThShard, plan *ccThPlan, start int64) int64 {
	var total int64
	for _, sh := range shards {
		var n int64
		args := append(append([]interface{}{}, plan.args...), start)
		sql := "SELECT COUNT(*) FROM " + sh.table + " WHERE " + plan.where + " AND unix_add_time >= ?"
		if err := sh.db.Raw(sql, args...).Scan(&n).Error; err == nil {
			total += n
		}
	}
	return total
}

// ccThInnerSQL 内层：每个统计对象在每个固定窗口里的请求数。
//
// 分桶用取模而不是除法：MySQL 的 / 返回小数、SQLite 的 FLOOR 不保证可用，
// 而 % 在 sqlite / mysql / postgres 上都是整数取模。
func ccThInnerSQL(table string, plan *ccThPlan) (string, string) {
	sel := ""
	grp := ""
	for i := range plan.dimCols {
		sel += plan.dimCols[i] + " AS d" + fmt.Sprint(i+1) + ", "
		if grp != "" {
			grp += ", "
		}
		grp += "d" + fmt.Sprint(i+1)
	}
	if grp != "" {
		grp += ", b"
	} else {
		grp = "b"
	}
	inner := "SELECT " + sel + "(unix_add_time - unix_add_time % ?) AS b, COUNT(*) AS c FROM " + table +
		" WHERE " + plan.where + " AND unix_add_time >= ? GROUP BY " + grp
	return inner, grp
}

func ccThAccumHistogram(sh ccThShard, plan *ccThPlan, start int64, hist map[int64]int64) {
	inner, _ := ccThInnerSQL(sh.table, plan)
	sql := "SELECT c AS cnt, COUNT(*) AS freq FROM (" + inner + ") t GROUP BY c"
	args := append([]interface{}{plan.bucketMs}, plan.args...)
	args = append(args, start)

	rows := []struct {
		Cnt  int64
		Freq int64
	}{}
	if err := sh.db.Raw(sql, args...).Scan(&rows).Error; err != nil {
		return
	}
	for _, r := range rows {
		hist[r.Cnt] += r.Freq
	}
}

func ccThAccumTop(sh ccThShard, plan *ccThPlan, start int64, tops map[string]*response2.CCThresholdTopRep) {
	inner, grp := ccThInnerSQL(sh.table, plan)
	dimSel := ""
	for i := range plan.dimCols {
		dimSel += "d" + fmt.Sprint(i+1) + ", "
	}
	dimGrp := strings.TrimSuffix(strings.TrimSuffix(grp, "b"), ", ")
	sql := "SELECT " + dimSel + "MAX(c) AS peak, SUM(c) AS total FROM (" + inner + ") t" +
		" GROUP BY " + dimGrp + " ORDER BY peak DESC LIMIT " + fmt.Sprint(ccThTopPerShard)
	args := append([]interface{}{plan.bucketMs}, plan.args...)
	args = append(args, start)

	rows := []struct {
		D1    string
		D2    string
		Peak  int64
		Total int64
	}{}
	if err := sh.db.Raw(sql, args...).Scan(&rows).Error; err != nil {
		return
	}
	for _, r := range rows {
		key := r.D1
		if len(plan.dimCols) > 1 && r.D2 != "" {
			key = r.D1 + " " + r.D2
		}
		if key == "" {
			continue
		}
		cur, ok := tops[key]
		if !ok {
			tops[key] = &response2.CCThresholdTopRep{DimValue: key, Peak: r.Peak, Total: r.Total}
			continue
		}
		if r.Peak > cur.Peak {
			cur.Peak = r.Peak
		}
		cur.Total += r.Total
	}
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
