package wafreport

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	_ "time/tzdata"
)

func TestDefaultConfigEnabledAndJSONRoundTrip(t *testing.T) {
	c := DefaultConfig()
	if !c.Enabled || !c.DailyEnabled || !c.WeeklyEnabled || !c.MonthlyEnabled {
		t.Fatalf("default config should enable all periodic reports: %+v", c)
	}
	if c.RetainDays != 30 || c.QuotaMB != 500 || c.TopN != 10 || c.Language != "zh-CN" {
		t.Fatalf("default config values drifted: %+v", c)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back Config
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back != c {
		t.Fatalf("config JSON round trip mismatch: %+v vs %+v", back, c)
	}

	// 显式 false 必须能持久化，不能被默认值兜底覆盖。
	c.Enabled = false
	c.DailyEnabled = false
	c.WeeklyEnabled = false
	c.MonthlyEnabled = false
	b, err = json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"enabled":true`) || strings.Contains(string(b), `"daily_enabled":true`) {
		t.Fatalf("explicit false flags lost in JSON: %s", b)
	}
	back = Config{}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Enabled || back.DailyEnabled || back.WeeklyEnabled || back.MonthlyEnabled {
		t.Fatalf("explicit false flags not persisted: %+v", back)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("explicit false config should still validate: %v", err)
	}
}

func TestDueRangeNaturalBoundaries(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 11, 3, 12, 0, 0, 0, loc)

	type tc struct {
		kind       Kind
		now        string
		at         string
		due        bool
		start, end string
	}
	cases := []tc{
		// 未到点。
		{"daily", "2026-11-12 00:29", "00:30", false, "", ""},
		// 到点，补前一自然日。
		{"daily", "2026-11-12 00:30", "00:30", true, "2026-11-11", "2026-11-12"},
		// 首次启用不回扫：startedAt 位于当前周期内时，不补前一周。
		{"weekly", "2026-11-04 08:00", "08:00", false, "", ""},
		// 周一当天刚过 08:00，应补前一周而不是当前周。
		{"weekly", "2026-11-09 08:00", "08:00", true, "2026-11-02", "2026-11-09"},
		// 首次启用不回扫：月初启用月报时，当月第一个周期不应触发。
		{"monthly", "2026-11-01 09:00", "09:00", false, "", ""},
		// 到点，补最近一个完整自然月。
		{"monthly", "2026-12-01 09:00", "09:00", true, "2026-11-01", "2026-12-01"},
	}
	for _, c := range cases {
		now, err := time.ParseInLocation("2006-01-02 15:04", c.now, loc)
		if err != nil {
			t.Fatal(err)
		}
		cfg := DefaultConfig()
		cfg.DailyAt, cfg.WeeklyAt, cfg.MonthlyAt = c.at, c.at, c.at
		r, due := DueRange(c.kind, now, started, cfg)
		if due != c.due {
			t.Fatalf("%s %s due=%v want %v (range=%+v)", c.kind, c.now, due, c.due, r)
		}
		if due && (r.Start.Format("2006-01-02") != c.start || r.End.Format("2006-01-02") != c.end) {
			t.Fatalf("%s %s range=%s~%s want %s~%s", c.kind, c.now, r.Start.Format("2006-01-02"), r.End.Format("2006-01-02"), c.start, c.end)
		}
	}
}

func TestDueRangeDisabledAndBadClock(t *testing.T) {
	now := time.Date(2026, 11, 12, 1, 0, 0, 0, time.UTC)
	started := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	cfg.Enabled = false
	if _, due := DueRange("daily", now, started, cfg); due {
		t.Fatal("disabled config should not schedule")
	}
	cfg = DefaultConfig()
	cfg.DailyAt = "24:00"
	if _, due := DueRange("daily", now, started, cfg); due {
		t.Fatal("invalid clock should not schedule")
	}
	cfg = DefaultConfig()
	cfg.DailyEnabled = false
	if _, due := DueRange("daily", now, started, cfg); due {
		t.Fatal("disabled kind should not schedule")
	}
}

func TestDueRangeStartOfPeriodBoundary(t *testing.T) {
	loc := time.UTC
	started := time.Date(2026, 11, 9, 0, 0, 0, 0, loc)
	now := time.Date(2026, 11, 10, 0, 30, 0, 0, loc)
	cfg := DefaultConfig()
	cfg.DailyAt = "00:30"
	r, due := DueRange("daily", now, started, cfg)
	if !due {
		t.Fatal("boundary at exact due minute should schedule")
	}
	if r.Start.Format("2006-01-02") != "2026-11-09" || r.End.Format("2006-01-02") != "2026-11-10" {
		t.Fatalf("daily boundary range=%+v", r)
	}
}

func TestDueRangeCrossYearWeek(t *testing.T) {
	loc := time.UTC
	started := time.Date(2025, 12, 1, 0, 0, 0, 0, loc)
	now := time.Date(2026, 1, 6, 8, 0, 0, 0, loc)
	cfg := DefaultConfig()
	cfg.WeeklyAt = "08:00"
	r, due := DueRange("weekly", now, started, cfg)
	if !due {
		t.Fatal("cross-year week should schedule")
	}
	if r.Start.Format("2006-01-02") != "2025-12-29" || r.End.Format("2006-01-02") != "2026-01-05" {
		t.Fatalf("cross-year week range=%+v", r)
	}
}

func TestDueRangeLeapYearFebruary(t *testing.T) {
	loc := time.UTC
	started := time.Date(2024, 1, 1, 0, 0, 0, 0, loc)
	now := time.Date(2024, 3, 1, 9, 0, 0, 0, loc)
	cfg := DefaultConfig()
	cfg.MonthlyAt = "09:00"
	r, due := DueRange("monthly", now, started, cfg)
	if !due {
		t.Fatal("leap year February monthly should schedule")
	}
	if r.Start.Format("2006-01-02") != "2024-02-01" || r.End.Format("2006-01-02") != "2024-03-01" {
		t.Fatalf("leap year February range=%+v", r)
	}
}
