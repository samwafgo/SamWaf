//go:build crossdb

// IP 标签跨库合并的三库回归：切换存放位置时把另一个库的历史并过来，
// 相同唯一键 cnt 相加、首次时间取早、最近时间取晚，且重复跑不改数。
// 冲突分支要引用"本次待插入的值"，三个引擎写法不同，正是这里要钉住的地方。
// 由 TestCrossEngine 每引擎调一次。
package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"testing"
	"time"
)

func runIPTagMergeCases(t *testing.T, x *xdb) {
	saved := global.GDATA_IP_TAG_DB
	defer func() { global.GDATA_IP_TAG_DB = saved }()

	ip := "9.9." + sfx()
	early := customtype.JsonTime(time.Now().Add(-48 * time.Hour))
	late := customtype.JsonTime(time.Now())

	mk := func(id string, cnt int64, create, update customtype.JsonTime) *model.IPTag {
		return &model.IPTag{
			BaseOrm: baseorm.BaseOrm{
				Id: id, USER_CODE: xtestUser, Tenant_ID: xtestTenant,
				CREATE_TIME: create, UPDATE_TIME: update,
			},
			IP: ip, IPTag: "SQL注入", Cnt: cnt,
		}
	}

	// 目标库(统计库)已有一行，来源库(核心库)有同键的另一行 + 一行独有的
	must(t, x.stats.Create(mk(uuid.GenUUID(), 3, late, late)).Error)
	must(t, x.core.Create(mk(uuid.GenUUID(), 7, early, early)).Error)
	onlyInCore := &model.IPTag{
		BaseOrm: baseorm.BaseOrm{
			Id: uuid.GenUUID(), USER_CODE: xtestUser, Tenant_ID: xtestTenant,
			CREATE_TIME: early, UPDATE_TIME: early,
		},
		IP: ip, IPTag: "XSS", Cnt: 5,
	}
	must(t, x.core.Create(onlyInCore).Error)

	global.GDATA_IP_TAG_DB = 1
	MergeIPTagsInto(1)

	var merged model.IPTag
	firstBy(t, x.stats, &merged, "ip = ? and ip_tag = ?", ip, "SQL注入")
	if merged.Cnt != 10 {
		t.Fatalf("同键的 cnt 应相加为 10，实际 %d", merged.Cnt)
	}
	if time.Time(merged.CREATE_TIME).After(time.Time(early).Add(time.Second)) {
		t.Fatalf("首次时间应取早的那个，实际 %v", time.Time(merged.CREATE_TIME))
	}
	if time.Time(merged.UPDATE_TIME).Before(time.Time(late).Add(-time.Second)) {
		t.Fatalf("最近时间应取晚的那个，实际 %v", time.Time(merged.UPDATE_TIME))
	}

	var moved model.IPTag
	firstBy(t, x.stats, &moved, "ip = ? and ip_tag = ?", ip, "XSS")
	if moved.Cnt != 5 {
		t.Fatalf("来源库独有的标签应原样搬过来，实际 cnt=%d", moved.Cnt)
	}

	if n := countBy(t, x.core, &model.IPTag{}, "ip = ?", ip); n != 0 {
		t.Fatalf("合并完来源库应清空，还剩 %d 行", n)
	}

	// 幂等：源库已空，再跑一次不能把计数翻倍
	MergeIPTagsInto(1)
	var again model.IPTag
	firstBy(t, x.stats, &again, "ip = ? and ip_tag = ?", ip, "SQL注入")
	if again.Cnt != 10 {
		t.Fatalf("重复合并把计数改了，实际 %d", again.Cnt)
	}
}
