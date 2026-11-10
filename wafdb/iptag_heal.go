package wafdb

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafdb/tableheal"
	"sync/atomic"

	"gorm.io/gorm"
)

// 「正常」标签分层后不再记录（放行数量由 stats_ip_days 承担），回填时直接丢弃。
const ipTagBenign = "正常"

var ipTagUniqueCols = []string{"user_code", "tenant_id", "ip", "ip_tag"}

// ipTagHealSpec 返回 ip_tags 的自愈规格。核心库与统计库的普通索引不同，与各自迁移的现状保持一致。
func ipTagHealSpec(isCore bool) tableheal.Spec {
	indexes := []tableheal.IndexDef{
		{Name: "idx_iptag_ip", Columns: []string{"user_code", "tenant_id", "ip"}},
	}
	if !isCore {
		indexes = append(indexes,
			tableheal.IndexDef{Name: "idx_ip_tags_create_time", Columns: []string{"create_time"}},
			tableheal.IndexDef{Name: "idx_ip_tags_update_time", Columns: []string{"update_time"}},
		)
	}
	return tableheal.Spec{
		Table:       "ip_tags",
		Model:       &model.IPTag{},
		UniqueIndex: tableheal.IndexDef{Name: "uni_iptags_full", Columns: ipTagUniqueCols},
		Indexes:     indexes,
		MergeBatch:  mergeIPTagsBatch,
	}
}

// ensureIPTagIndexes 在全部迁移之后检查 ip_tags 的必需索引，缺失则修复（启动期，毫秒级）。
func ensureIPTagIndexes(db *gorm.DB, isCore bool) {
	label := "统计库"
	if isCore {
		label = "核心库"
	}
	tableheal.Ensure(db, label, []tableheal.Spec{ipTagHealSpec(isCore)})
}

// mergeIPTagsBatch 从 ip_tags__heal 读一批，丢弃「正常」，折叠后并入 ip_tags，并在同一事务里删掉整批。
// 写入与删除同事务：中途中断，这批要么都生效要么都不生效，不会重复计数。
//
// 读放在事务之外：SQLite 的默认事务先读后写时，升级写锁遇到别的连接已提交的写入会立刻返回
// BUSY（不走 busy_timeout）。heal 表只有回填线程自己在写，事务外读不存在竞争，
// 这样事务的第一条语句就是写，会按 busy_timeout 等锁。
func mergeIPTagsBatch(db *gorm.DB, heal string, limit int) (int, error) {
	var rows []model.IPTag
	if err := db.Table(heal).Order("id").Limit(limit).Find(&rows).Error; err != nil {
		return 0, err
	}
	n := len(rows)
	if n == 0 {
		return 0, nil
	}
	keep := make([]model.IPTag, 0, n)
	ids := make([]string, 0, n)
	for i := range rows {
		ids = append(ids, rows[i].Id)
		if rows[i].IPTag != ipTagBenign {
			keep = append(keep, rows[i])
		}
	}
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := UpsertIPTags(tx, keep); err != nil {
			return err
		}
		return tx.Table(heal).Where("id IN ?", ids).Delete(&model.IPTag{}).Error
	})
	return n, err
}

// RunIPTagBackfill 把核心库、统计库里遗留的 ip_tags__heal 并回主表。
// 期间置 GDATA_IP_TAG_MERGING，界面据此显示“合并中”；返回时已复位，调用方可接着做跨库合并。
func RunIPTagBackfill() {
	if !atomic.CompareAndSwapInt32(&global.GDATA_IP_TAG_MERGING, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&global.GDATA_IP_TAG_MERGING, 0)
	if global.GWAF_LOCAL_DB != nil {
		tableheal.RunBackfill(global.GWAF_LOCAL_DB, "核心库", ipTagHealSpec(true))
	}
	if global.GWAF_LOCAL_STATS_DB != nil && global.GWAF_LOCAL_STATS_DB != global.GWAF_LOCAL_DB {
		tableheal.RunBackfill(global.GWAF_LOCAL_STATS_DB, "统计库", ipTagHealSpec(false))
	}
	zlog.Debug("IP标签旧表回填检查结束")
}
