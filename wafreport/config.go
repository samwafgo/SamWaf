package wafreport

import (
	"errors"
	"regexp"
	"time"
)

type Config struct {
	Enabled        bool   `json:"enabled"`
	DailyEnabled   bool   `json:"daily_enabled"`
	WeeklyEnabled  bool   `json:"weekly_enabled"`
	MonthlyEnabled bool   `json:"monthly_enabled"`
	DailyAt        string `json:"daily_at"`
	WeeklyAt       string `json:"weekly_at"`
	MonthlyAt      string `json:"monthly_at"`
	RetainDays     int    `json:"retain_days"`
	QuotaMB        int    `json:"quota_mb"`
	TopN           int    `json:"top_n"`
	Language       string `json:"language"`
}

func DefaultConfig() Config {
	return Config{true, true, true, true, "00:30", "08:00", "09:00", 30, 500, 10, "zh-CN"}
}

var clockPattern = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)

func (c Config) Validate() error {
	if !clockPattern.MatchString(c.DailyAt) || !clockPattern.MatchString(c.WeeklyAt) || !clockPattern.MatchString(c.MonthlyAt) {
		return errors.New("生成时刻须为 HH:mm")
	}
	if c.RetainDays < 1 || c.RetainDays > 365 || c.QuotaMB < 10 || c.QuotaMB > 10240 || c.TopN < 5 || c.TopN > 50 {
		return errors.New("保留天数应为1–365、配额10–10240MB、TOP数量5–50")
	}
	if c.Language != "zh-CN" && c.Language != "en-US" {
		return errors.New("报告语言不正确")
	}
	return nil
}

// DueRange 仅补最近一个已结束周期；初次启用从当前周期开始。
func DueRange(kind Kind, now time.Time, startedAt time.Time, c Config) (Range, bool) {
	if !c.Enabled {
		return Range{}, false
	}
	enabled, at := false, ""
	switch kind {
	case Kind("daily"):
		enabled, at = c.DailyEnabled, c.DailyAt
	case Kind("weekly"):
		enabled, at = c.WeeklyEnabled, c.WeeklyAt
	case Kind("monthly"):
		enabled, at = c.MonthlyEnabled, c.MonthlyAt
	}
	if !enabled || !clockPattern.MatchString(at) {
		return Range{}, false
	}
	current, err := NewRange(kind, now)
	if err != nil {
		return Range{}, false
	}
	clock, _ := time.Parse("15:04", at)
	due := time.Date(current.Start.Year(), current.Start.Month(), current.Start.Day(), clock.Hour(), clock.Minute(), 0, 0, current.Start.Location())
	if now.Before(due) {
		return Range{}, false
	}
	prev, err := PreviousRange(kind, current)
	if err != nil {
		return Range{}, false
	}
	first, err := NewRange(kind, startedAt.In(now.Location()))
	return prev, err == nil && !prev.Start.Before(first.Start)
}
