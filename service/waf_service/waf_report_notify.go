package waf_service

import (
	"SamWaf/model"
	"SamWaf/wafreport"
	"time"
)

func (s *WafReportService) notify(t model.SecurityReportTask, report wafreport.Report) {
	// 定时产物通过既有订阅投递，手动生成只保存在本地。
	if t.Source != "schedule" {
		return
	}
	total, blocked := int64(-1), int64(-1)
	if report.Current.Summary.State == wafreport.OK {
		total = report.Current.Summary.Data.Requests
		blocked = report.Current.Summary.Data.Blocked
	}
	rangeLabel := time.Unix(t.RangeStart, 0).In(time.Local).Format("2006-01-02") + " ~ " + time.Unix(t.RangeEnd-1, 0).In(time.Local).Format("2006-01-02")
	WafNotifySenderServiceApp.SendPeriodicReportSummary(t.Kind, t.ID, rangeLabel, string(report.Status), total, blocked)
}
func (s *WafReportService) notifyFailure(t model.SecurityReportTask) {
	if t.Source != "schedule" {
		return
	}
	rangeLabel := time.Unix(t.RangeStart, 0).In(time.Local).Format("2006-01-02") + " ~ " + time.Unix(t.RangeEnd-1, 0).In(time.Local).Format("2006-01-02")
	WafNotifySenderServiceApp.SendPeriodicReportSummary(t.Kind, t.ID, rangeLabel, "failed", -1, -1)
}
