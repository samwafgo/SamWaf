package partition

import (
	"testing"
	"time"
)

func TestKeyOfAndRange(t *testing.T) {
	key := KeyOf(time.Date(2026, 9, 21, 15, 30, 0, 0, time.Local))
	if key != "202609" {
		t.Fatalf("周期键应为 202609，实际 %q", key)
	}
	start, end, err := Range(key)
	if err != nil {
		t.Fatalf("Range 失败: %v", err)
	}
	if start.Year() != 2026 || start.Month() != time.September || start.Day() != 1 {
		t.Fatalf("起点应是 2026-09-01，实际 %v", start)
	}
	// 右开：9 月分区的终点是 10/1 零点，不是 9/30 23:59:59。
	// 写成右闭会在月末最后一秒漏掉数据。
	if end.Year() != 2026 || end.Month() != time.October || end.Day() != 1 {
		t.Fatalf("终点应是 2026-10-01，实际 %v", end)
	}
}

func TestRangeCrossYear(t *testing.T) {
	_, end, err := Range("202612")
	if err != nil {
		t.Fatalf("Range 失败: %v", err)
	}
	if end.Year() != 2027 || end.Month() != time.January {
		t.Fatalf("12 月的终点应跨年到 2027-01，实际 %v", end)
	}
}

func TestIsKeyRejectsJunk(t *testing.T) {
	for _, bad := range []string{"", "2026", "20260921150405", "202613", "202600", "20260a", "-20260"} {
		if IsKey(bad) {
			t.Errorf("%q 不该被当成周期键", bad)
		}
	}
	for _, ok := range []string{"202601", "202612", "202509"} {
		if !IsKey(ok) {
			t.Errorf("%q 应是合法周期键", ok)
		}
	}
}

func TestKeyFromName(t *testing.T) {
	cases := []struct {
		name string
		want string
		ok   bool
	}{
		{"access_log_202609", "202609", true},
		{"event_payload_202512", "202512", true},
		{"local_log_202609.db", "202609", true},
		// 按体积切出来的旧分片：14 位时间戳，认不出来是故意的，
		// 它们的时间范围只能查 share_dbs，不能从名字算
		{"access_log_20260921153045", "", false},
		{"local_log_20260921153045.db", "", false},
		{"access_log", "", false},
		{"access_log_", "", false},
		{"access_log_shardtmp", "", false},
		// 同周期内体积超限被迫再切的兜底命名，仍要认得出周期
		{"access_log_202609_02", "202609", true},
		{"local_log_202609_02.db", "202609", true},
	}
	for _, c := range cases {
		got, ok := KeyFromName(c.name)
		if ok != c.ok || got != c.want {
			t.Errorf("KeyFromName(%q) = (%q,%v)，期望 (%q,%v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestTableAndFileNameSeq(t *testing.T) {
	// seq<=1 不带序号：一个周期一个分区是常态，名字里不该多出噪音
	if got := TableNameSeq("access_log", "202609", 1); got != "access_log_202609" {
		t.Errorf("seq=1 应不带序号，实际 %q", got)
	}
	if got := TableNameSeq("access_log", "202609", 2); got != "access_log_202609_02" {
		t.Errorf("seq=2 表名 = %q", got)
	}
	if got := FileNameSeq("202609", 3); got != "local_log_202609_03.db" {
		t.Errorf("seq=3 文件名 = %q", got)
	}
	if got := FileNameSeq("202609", 1); got != "local_log_202609.db" {
		t.Errorf("seq=1 应不带序号，实际 %q", got)
	}
}

func TestTableAndFileName(t *testing.T) {
	if got := TableName("access_log", "202609"); got != "access_log_202609" {
		t.Errorf("表名 = %q", got)
	}
	if got := FileName("202609"); got != "local_log_202609.db" {
		t.Errorf("文件名 = %q", got)
	}
}

func TestKeysBetween(t *testing.T) {
	from := time.Date(2026, 11, 20, 0, 0, 0, 0, time.Local)
	to := time.Date(2027, 2, 3, 0, 0, 0, 0, time.Local)
	got := KeysBetween(from, to)
	want := []string{"202611", "202612", "202701", "202702"}
	if len(got) != len(want) {
		t.Fatalf("跨年区间应有 %d 个周期，实际 %v", len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 个周期 = %q，期望 %q（全部：%v）", i, got[i], want[i], got)
		}
	}

	// 同月内的区间只有一个周期
	same := KeysBetween(from, from.AddDate(0, 0, 3))
	if len(same) != 1 || same[0] != "202611" {
		t.Fatalf("同月区间应只有 202611，实际 %v", same)
	}

	// 起点晚于终点：返回空而不是倒序或一整年
	if got := KeysBetween(to, from); got != nil {
		t.Fatalf("起点晚于终点应返回 nil，实际 %v", got)
	}
}

func TestExpiredJudgesByEndNotStart(t *testing.T) {
	const key = "202609" // 装 9/1~9/30 的数据，终点 10/1

	// 保留 30 天、当前 10/5：截止点 9/5，9 月分区里 9/5 之后的数据还在保留期内 → 不能丢
	if Expired(key, 30, time.Date(2026, 10, 5, 12, 0, 0, 0, time.Local)) {
		t.Error("分区里还有在保留期内的数据，不该判为过期（按开始时刻判就会错在这里）")
	}
	// 当前 11/5：截止点 10/6 已越过分区终点 → 整段过期
	if !Expired(key, 30, time.Date(2026, 11, 5, 12, 0, 0, 0, time.Local)) {
		t.Error("整段都超出保留期了，应判为过期")
	}
	// 不按天清理
	if Expired(key, 0, time.Date(2030, 1, 1, 0, 0, 0, 0, time.Local)) {
		t.Error("retentionDays<=0 表示不按天清理，不该过期")
	}
	// 非法键不判过期（宁可留着也不误删）
	if Expired("20260921153045", 30, time.Date(2030, 1, 1, 0, 0, 0, 0, time.Local)) {
		t.Error("认不出的名字不该被判过期")
	}
}
