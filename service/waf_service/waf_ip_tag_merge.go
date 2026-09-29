package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafdb/dialect"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// 合并的节奏。ip_tags 是跟着攻击量长的派生表，实例跑久了几百万甚至上千万行都正常，
// 一次切换就要把它整张搬过去，所以这段循环必须让得出写锁：
// 批太小则往返次数爆炸（千万行按 500 一批就是两万轮、六万次往返），
// 批太大则单个事务变长，SQLite 上会把正在落库的日志顶住。
const (
	ipTagMergeBatch    = 1000
	ipTagMergePause    = 10 * time.Millisecond // 每批之间让一下写锁，日志落库不至于被饿死
	ipTagMergeLogEvery = 50000                 // 每搬这么多行报一次进度，大表上别让人以为卡死了
	ipTagMergeSlowHint = 200000                // 超过这个量级先把预期讲清楚
)

// MergeIPTagsInto 把另一个库里的 ip_tags 并进 target 指定的库（0=核心库，1=统计库）。
//
// ip_tags 的归属由 database.ip_tag_db 决定，读写都只认当前那一个库。
// 切换归属之前积累的标签会留在原来的库里——数据没丢，但界面按新库查，看起来像"历史没了"。
// 这个任务把它们搬过来：唯一键相同的 cnt 相加、首次时间取早、最近时间取晚。
//
// 按内容驱动而不是按"切换事件"驱动：源库空就直接返回，所以启动时跑一次就能把
// 更早版本切换时留下的历史一并收回来，重复跑也没有副作用。
func MergeIPTagsInto(target int64) {
	if !atomic.CompareAndSwapInt32(&global.GDATA_IP_TAG_MERGING, 0, 1) {
		zlog.Debug("IP标签合并已在进行中，跳过本次")
		return
	}
	defer atomic.StoreInt32(&global.GDATA_IP_TAG_MERGING, 0)

	dst, src := global.GWAF_LOCAL_STATS_DB, global.GWAF_LOCAL_DB
	dstName, srcName := "统计库", "核心库"
	if target != 1 {
		dst, src = global.GWAF_LOCAL_DB, global.GWAF_LOCAL_STATS_DB
		dstName, srcName = "核心库", "统计库"
	}
	if dst == nil || src == nil {
		return
	}
	if !src.Migrator().HasTable(&model.IPTag{}) {
		return
	}

	var pending int64
	if err := src.Model(&model.IPTag{}).Count(&pending).Error; err != nil {
		zlog.Warn("统计待合并IP标签失败", "来源", srcName, "error", err.Error())
		return
	}
	if pending == 0 {
		return
	}

	zlog.Info("开始合并IP标签", "来源", srcName, "目标", dstName, "待合并", pending)
	if pending >= ipTagMergeSlowHint {
		// 讲清楚而不是默默跑：合并期间风险日志页的计数会一直变，用户得知道那是正常的
		zlog.Warn("待合并的IP标签较多，合并会持续一段时间",
			"条数", pending, "来源", srcName, "目标", dstName,
			"说明", "合并期间风险日志页的标签计数会持续变动，完成后自动稳定；进程重启会从断点继续")
	}
	start := time.Now()
	var merged, lastLogged int64
	for {
		var rows []model.IPTag
		if err := src.Model(&model.IPTag{}).Limit(ipTagMergeBatch).Find(&rows).Error; err != nil {
			zlog.Warn("读取待合并IP标签失败", "来源", srcName, "已合并", merged, "error", err.Error())
			return
		}
		if len(rows) == 0 {
			break
		}
		// 先写目标再删来源。两个库之间没有共同事务，只能选一头承担中断风险：
		// 中断在这两步之间，这一批下次会再并一遍（计数偏大），比删掉之后没写进去要好收拾。
		if err := upsertIPTags(dst, rows); err != nil {
			zlog.Warn("写入IP标签失败", "目标", dstName, "已合并", merged, "error", err.Error())
			return
		}
		ids := make([]string, 0, len(rows))
		for i := range rows {
			ids = append(ids, rows[i].Id)
		}
		if err := src.Where("id in ?", ids).Delete(&model.IPTag{}).Error; err != nil {
			zlog.Warn("清理来源IP标签失败", "来源", srcName, "已合并", merged, "error", err.Error())
			return
		}
		merged += int64(len(rows))

		if merged-lastLogged >= ipTagMergeLogEvery {
			lastLogged = merged
			zlog.Info("IP标签合并进行中", "已合并", merged, "共", pending, "耗时", time.Since(start).String())
		}
		time.Sleep(ipTagMergePause)
	}
	zlog.Info("IP标签合并完成", "来源", srcName, "目标", dstName, "条数", merged, "耗时", time.Since(start).String())
}

// CleanLegacyBenignIPTags 一次性清掉存量「正常」标签行（核心库与统计库都清）。
//
// 分层后不再为未命中规则的请求生成「正常」标签（D7）——放行数量改由 stats_ip_days 承担，
// 那是同一份数据的重复记录，也是 ip_tags 行数的大头。存量行切换后不再更新但仍占表，
// 这里按批删掉；必须在归属合并（MergeIPTagsInto）之前跑，否则大表用户要先把一堆
// 马上要删的行白搬一遍。
func CleanLegacyBenignIPTags() {
	for _, db := range []*gorm.DB{global.GWAF_LOCAL_DB, global.GWAF_LOCAL_STATS_DB} {
		if db == nil || !db.Migrator().HasTable(&model.IPTag{}) {
			continue
		}
		var total int64
		if err := db.Model(&model.IPTag{}).Where("ip_tag = ?", "正常").Count(&total).Error; err != nil || total == 0 {
			continue
		}
		zlog.Info("清理存量「正常」IP标签", "条数", total)
		start := time.Now()
		var deleted int64
		for {
			// 分批 + 让锁：这张表可能有几百万上千万行，一口气删会把日志落库顶死（SQLite 单写者）。
			// 各引擎的批量删法不同（PG 不认 DELETE...LIMIT），统一走方言层。
			res := db.Exec(dialect.Get().BatchDeleteSQL("ip_tags", "ip_tag=?", ipTagMergeBatch), "正常")
			if res.Error != nil {
				zlog.Warn("清理「正常」IP标签失败", "已删", deleted, "error", res.Error.Error())
				break
			}
			if res.RowsAffected == 0 {
				break
			}
			deleted += res.RowsAffected
			if deleted%ipTagMergeLogEvery < ipTagMergeBatch {
				zlog.Info("清理「正常」IP标签进行中", "已删", deleted, "共", total, "耗时", time.Since(start).String())
			}
			time.Sleep(ipTagMergePause)
		}
		zlog.Info("清理「正常」IP标签完成", "条数", deleted, "耗时", time.Since(start).String())
	}
}

// upsertIPTags 按唯一索引 uni_iptags_full 合并写入：cnt 相加，首次时间取早、最近时间取晚。
// 冲突分支要引用"本次待插入的值"，三个引擎写法不同，由方言给出。
func upsertIPTags(dst *gorm.DB, rows []model.IPTag) error {
	cnt := dialect.Get().UpsertExcludedRef("cnt")
	upd := dialect.Get().UpsertExcludedRef("update_time")
	cre := dialect.Get().UpsertExcludedRef("create_time")
	return dst.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "user_code"}, {Name: "tenant_id"}, {Name: "ip"}, {Name: "ip_tag"},
		},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"cnt":         gorm.Expr("ip_tags.cnt + " + cnt),
			"update_time": gorm.Expr("CASE WHEN " + upd + " > ip_tags.update_time THEN " + upd + " ELSE ip_tags.update_time END"),
			"create_time": gorm.Expr("CASE WHEN " + cre + " < ip_tags.create_time THEN " + cre + " ELSE ip_tags.create_time END"),
		}),
	}).CreateInBatches(rows, ipTagMergeBatch).Error
}
