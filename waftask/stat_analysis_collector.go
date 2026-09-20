package waftask

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/wafdb/dialect"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	// pathTemplatePerSiteDay 每站每天最多认多少个路径模板（D10）。
	// 字典爆破会造出成千上万个互不相同的字面路径（/admin、/.env、/wp-login…），
	// NormalizePath 归一不掉它们；没有这道闸，汇总表会被扫目录打爆。
	pathTemplatePerSiteDay = 5000
	// pathOverflowTemplate 超出上限之后所有没见过的模板的去处。
	pathOverflowTemplate = "{overflow}"
	// analysisUpsertBatch 单条 upsert 语句最多带多少行，同 ipTagUpsertBatch 的考量。
	analysisUpsertBatch = 200
)

// pathGate 记住每个「站点×天」已认下的路径模板，给 D10 的上限把门。
// 只保留最近两天的桶（跨零点时新旧各一个），重启会清空——
// 上限是防爆的闸不是精确不变式，重启后这一天最多再放行一批新模板，可以接受。
type pathGate struct {
	mu   sync.Mutex
	seen map[int]map[string]map[string]struct{} // day → host_code → 模板集合
}

var analysisPathGate = &pathGate{seen: map[int]map[string]map[string]struct{}{}}

// admit 返回这个模板在汇总里该记成什么：认识的原样返回，
// 没见过且没到上限就收下，到了上限就归进 {overflow}。
func (g *pathGate) admit(hostCode string, day int, path string) string {
	if path == "" {
		return path
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	dayBucket := g.seen[day]
	if dayBucket == nil {
		dayBucket = map[string]map[string]struct{}{}
		g.seen[day] = dayBucket
		g.pruneDaysLocked(day)
	}
	bucket := dayBucket[hostCode]
	if bucket == nil {
		bucket = make(map[string]struct{}, 256)
		dayBucket[hostCode] = bucket
	}
	if _, ok := bucket[path]; ok {
		return path
	}
	if len(bucket) >= pathTemplatePerSiteDay {
		return pathOverflowTemplate
	}
	bucket[path] = struct{}{}
	return path
}

// pruneDaysLocked 只留 keep 和比它小的那一天，其余丢掉。调用方须持锁。
func (g *pathGate) pruneDaysLocked(keep int) {
	for len(g.seen) > 2 {
		oldest := 0
		for d := range g.seen {
			if oldest == 0 || d < oldest {
				oldest = d
			}
		}
		if oldest == keep || oldest == 0 {
			return
		}
		delete(g.seen, oldest)
	}
}

// CollectAnalysisStats 把一批请求聚合进分析层的三张天级汇总表。
//
// 与档位正交：吃的是全量请求流，access_log_mode 只决定明细写多少，不影响汇总口径——
// 这是 stats_* 今天就有的性质（统计不依赖日志入库），不能丢。
func CollectAnalysisStats(rows []model.LogAnalysisRow) {
	if len(rows) == 0 || global.GWAF_LOCAL_STATS_DB == nil {
		return
	}

	type actorPathKey struct {
		HostCode string
		Day      int
		ActorKey string
		PathNorm string
	}
	type actorUaKey struct {
		HostCode string
		Day      int
		ActorKey string
		UaHash   string
	}
	type pathRuleKey struct {
		HostCode string
		Day      int
		PathNorm string
		Rule     string
	}
	type actorPathVal struct {
		Req    int64
		Deny   int64
		Err4xx int64
	}

	actorPathAgg := make(map[actorPathKey]*actorPathVal)
	actorUaAgg := make(map[actorUaKey]int64)
	pathRuleAgg := make(map[pathRuleKey]int64)

	for _, r := range rows {
		if r.HostCode == "" || r.ActorKey == "" {
			continue
		}
		path := analysisPathGate.admit(r.HostCode, r.Day, cutRunes(r.PathNorm, model.StatsPathNormLen))

		apk := actorPathKey{HostCode: r.HostCode, Day: r.Day, ActorKey: r.ActorKey, PathNorm: path}
		v := actorPathAgg[apk]
		if v == nil {
			v = &actorPathVal{}
			actorPathAgg[apk] = v
		}
		v.Req++
		if r.Action == "阻止" {
			v.Deny++
		} else if r.StatusCode >= 400 && r.StatusCode < 500 {
			v.Err4xx++
		}

		if r.UaHash != "" {
			actorUaAgg[actorUaKey{HostCode: r.HostCode, Day: r.Day, ActorKey: r.ActorKey, UaHash: r.UaHash}]++
		}
		if r.Rule != "" {
			pathRuleAgg[pathRuleKey{HostCode: r.HostCode, Day: r.Day, PathNorm: path, Rule: cutRunes(r.Rule, model.StatsRuleLen)}]++
		}
	}

	now := customtype.JsonTime(time.Now())
	db := global.GWAF_LOCAL_STATS_DB
	inc := dialect.Get().UpsertExcludedRef

	if len(actorPathAgg) > 0 {
		batch := make([]model.StatsActorPathDay, 0, len(actorPathAgg))
		for k, v := range actorPathAgg {
			batch = append(batch, model.StatsActorPathDay{
				BaseOrm:   newStatsBaseOrm(now),
				HostCode:  k.HostCode,
				Day:       k.Day,
				ActorKey:  k.ActorKey,
				PathNorm:  k.PathNorm,
				ReqCnt:    v.Req,
				DenyCnt:   v.Deny,
				Err4xxCnt: v.Err4xx,
			})
		}
		err := db.Clauses(clause.OnConflict{
			Columns: analysisConflictCols("host_code", "day", "actor_key", "path_norm"),
			DoUpdates: clause.Assignments(map[string]interface{}{
				"req_cnt":     gorm.Expr("stats_actor_path_days.req_cnt + " + inc("req_cnt")),
				"deny_cnt":    gorm.Expr("stats_actor_path_days.deny_cnt + " + inc("deny_cnt")),
				"err4xx_cnt":  gorm.Expr("stats_actor_path_days.err4xx_cnt + " + inc("err4xx_cnt")),
				"update_time": now,
			}),
		}).CreateInBatches(batch, analysisUpsertBatch).Error
		if err != nil {
			zlog.Debug("分析层 行为×目标 聚合写入失败", "错误", err.Error(), "条数", len(batch))
		}
	}

	if len(actorUaAgg) > 0 {
		batch := make([]model.StatsActorUaDay, 0, len(actorUaAgg))
		for k, delta := range actorUaAgg {
			batch = append(batch, model.StatsActorUaDay{
				BaseOrm:  newStatsBaseOrm(now),
				HostCode: k.HostCode,
				Day:      k.Day,
				ActorKey: k.ActorKey,
				UaHash:   k.UaHash,
				Cnt:      delta,
			})
		}
		err := db.Clauses(clause.OnConflict{
			Columns: analysisConflictCols("host_code", "day", "actor_key", "ua_hash"),
			DoUpdates: clause.Assignments(map[string]interface{}{
				"cnt":         gorm.Expr("stats_actor_ua_days.cnt + " + inc("cnt")),
				"update_time": now,
			}),
		}).CreateInBatches(batch, analysisUpsertBatch).Error
		if err != nil {
			zlog.Debug("分析层 行为×UA 聚合写入失败", "错误", err.Error(), "条数", len(batch))
		}
	}

	if len(pathRuleAgg) > 0 {
		batch := make([]model.StatsPathRuleDay, 0, len(pathRuleAgg))
		for k, delta := range pathRuleAgg {
			batch = append(batch, model.StatsPathRuleDay{
				BaseOrm:  newStatsBaseOrm(now),
				HostCode: k.HostCode,
				Day:      k.Day,
				PathNorm: k.PathNorm,
				Rule:     k.Rule,
				Cnt:      delta,
			})
		}
		err := db.Clauses(clause.OnConflict{
			Columns: analysisConflictCols("host_code", "day", "path_norm", "rule"),
			DoUpdates: clause.Assignments(map[string]interface{}{
				"cnt":         gorm.Expr("stats_path_rule_days.cnt + " + inc("cnt")),
				"update_time": now,
			}),
		}).CreateInBatches(batch, analysisUpsertBatch).Error
		if err != nil {
			zlog.Debug("分析层 目标×规则 聚合写入失败", "错误", err.Error(), "条数", len(batch))
		}
	}

	zlog.Debug("分析层聚合完成",
		"行为×目标", len(actorPathAgg), "行为×UA", len(actorUaAgg), "目标×规则", len(pathRuleAgg))
}

// analysisConflictCols 唯一索引以 user_code/tenant_id 打头（与 ip_tags 同款），冲突目标要逐列对齐。
func analysisConflictCols(cols ...string) []clause.Column {
	out := []clause.Column{{Name: "user_code"}, {Name: "tenant_id"}}
	for _, c := range cols {
		out = append(out, clause.Column{Name: c})
	}
	return out
}

func newStatsBaseOrm(now customtype.JsonTime) baseorm.BaseOrm {
	return baseorm.BaseOrm{
		Id:          uuid.GenUUID(),
		USER_CODE:   global.GWAF_USER_CODE,
		Tenant_ID:   global.GWAF_TENANT_ID,
		CREATE_TIME: now,
		UPDATE_TIME: now,
	}
}

// cutRunes 按字符截断（列宽是字符数，不是字节数）。
func cutRunes(s string, max int) string {
	if max <= 0 || s == "" {
		return s
	}
	n := 0
	for i := range s {
		n++
		if n > max {
			return s[:i]
		}
	}
	return s
}
