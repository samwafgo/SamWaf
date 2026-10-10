package waftask

import (
	"SamWaf/customtype"
	"SamWaf/model"
	"testing"
	"time"
)

// 回收会真的删数据，所以「什么算过期」「认不出的一律不动」这两条判断必须单独钉住。

func TestExpiredByUsesRetentionDays(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.Local)
	end := time.Date(2026, 9, 30, 23, 59, 0, 0, time.Local)

	if expiredBy(end, 30, now) {
		t.Error("数据截止 9/30、保留 30 天、现在 10/10：还在保留期内，不该过期")
	}
	if !expiredBy(end, 5, now) {
		t.Error("保留 5 天时 9/30 的数据已过期")
	}
	// 0 / 负数 = 不按天清理，任何数据都不能被删
	if expiredBy(time.Date(2000, 1, 1, 0, 0, 0, 0, time.Local), 0, now) {
		t.Error("保留天数 <=0 表示不按天清理，不该判过期")
	}
	if expiredBy(time.Date(2000, 1, 1, 0, 0, 0, 0, time.Local), -1, now) {
		t.Error("保留天数为负同样不该判过期")
	}
}

func TestShardEndPrefersRecordedTime(t *testing.T) {
	want := time.Date(2026, 9, 21, 15, 4, 5, 0, time.Local)
	got, ok := shardEnd(model.ShareDb{FileName: "access_log_202609", EndTime: customtype.JsonTime(want)})
	if !ok || !got.Equal(want) {
		t.Fatalf("有 EndTime 时应直接用它，实际 (%v,%v)", got, ok)
	}

	// EndTime 缺失：回落周期键算出来的周期终点（9 月 → 10/1 零点）
	got, ok = shardEnd(model.ShareDb{FileName: "access_log_202609"})
	if !ok {
		t.Fatal("EndTime 缺失时应能靠周期键算出终点")
	}
	if got.Year() != 2026 || got.Month() != time.October || got.Day() != 1 {
		t.Fatalf("周期终点应是 2026-10-01，实际 %v", got)
	}

	// 既没有 EndTime、名字也算不出周期（按体积切的旧分片）：认不出就别动它
	if _, ok := shardEnd(model.ShareDb{FileName: "access_log_20260921153045"}); ok {
		t.Error("时间范围认不出来的分片必须返回 false，宁可留着也不能误删")
	}
}

func TestIsLiveShardNameCoversEveryDriver(t *testing.T) {
	for _, name := range []string{"", "local_log.db", "web_logs", "access_log"} {
		if !isLiveShardName(name) {
			t.Errorf("%q 是实时库标识，必须被挡在回收之外", name)
		}
	}
	for _, name := range []string{"local_log_202609.db", "access_log_202609", "web_logs_20260921153045"} {
		if isLiveShardName(name) {
			t.Errorf("%q 是归档分片，不该被当成实时库", name)
		}
	}
}

func TestArchiveSuffix(t *testing.T) {
	cases := map[string]string{
		"access_log_202609":       "202609",
		"access_log_202609_02":    "202609_02",
		"web_logs_20260921153045": "20260921153045",
		"local_log_202609.db":     "", // SQLite 走删文件那条路，不需要后缀
		"access_log":              "", // 实时表：取不出后缀，回收逻辑因此不会碰它
		"security_event_202609":   "", // 只认 web_logs_/access_log_ 两种标识，与读侧口径一致
	}
	for name, want := range cases {
		if got := archiveSuffix(name); got != want {
			t.Errorf("archiveSuffix(%q) = %q，期望 %q", name, got, want)
		}
	}
}
