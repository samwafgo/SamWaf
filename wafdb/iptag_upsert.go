package wafdb

import (
	"SamWaf/model"
	"SamWaf/wafdb/dialect"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ipTagUpsertBatch 单条 upsert 语句里最多带多少行：IPTag 有 8 列，
// 200 行约 1600 个绑定变量，低于 SQLite 的变量上限并留足余量。
const ipTagUpsertBatch = 200

type ipTagKey struct {
	user, tenant, ip, tag string
}

// foldIPTags 把批内同键的行合成一行：cnt 相加，首次时间取早、最近时间取晚。
// PG 的 ON CONFLICT 在同一条语句里命中同一行两次会报错，所以写入前必须先折叠。
func foldIPTags(rows []model.IPTag) []model.IPTag {
	idx := make(map[ipTagKey]int, len(rows))
	out := make([]model.IPTag, 0, len(rows))
	for _, r := range rows {
		k := ipTagKey{r.USER_CODE, r.Tenant_ID, r.IP, r.IPTag}
		i, ok := idx[k]
		if !ok {
			idx[k] = len(out)
			out = append(out, r)
			continue
		}
		cur := &out[i]
		cur.Cnt += r.Cnt
		if time.Time(r.CREATE_TIME).Before(time.Time(cur.CREATE_TIME)) {
			cur.CREATE_TIME = r.CREATE_TIME
		}
		if time.Time(r.UPDATE_TIME).After(time.Time(cur.UPDATE_TIME)) {
			cur.UPDATE_TIME = r.UPDATE_TIME
		}
	}
	return out
}

// UpsertIPTags 按唯一索引 uni_iptags_full 合并写入：cnt 相加，首次时间取早、最近时间取晚。
// 冲突分支要引用“本次待插入的值”，三个引擎写法不同，由方言给出。
// 实时写入、跨库合并、换表回填三处共用。
func UpsertIPTags(dst *gorm.DB, rows []model.IPTag) error {
	if len(rows) == 0 {
		return nil
	}
	rows = foldIPTags(rows)
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
	}).CreateInBatches(rows, ipTagUpsertBatch).Error
}
