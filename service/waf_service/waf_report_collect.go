package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafreport"
	"context"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

// ReportCollector reads aggregates and current configuration only.
type ReportCollector struct {
	StatsDB       *gorm.DB
	LogDB         *gorm.DB
	CoreDB        *gorm.DB
	Version       string
	WebVersion    string
	AccessLogMode string
	Now           func() time.Time
	Sources       []wafreport.Source
}

func NewReportCollector() *ReportCollector {
	return &ReportCollector{StatsDB: global.GWAF_LOCAL_STATS_DB, LogDB: global.GWAF_LOCAL_LOG_DB,
		CoreDB: global.GWAF_LOCAL_DB, Version: global.GWAF_RELEASE_VERSION,
		WebVersion: global.GWAF_WEB_VERSION, AccessLogMode: global.GDATA_ACCESS_LOG_MODE}
}

type reportSource struct {
	name    string
	collect func(context.Context, wafreport.Request, *wafreport.Report) error
}

func (s reportSource) Name() string { return s.name }
func (s reportSource) Collect(ctx context.Context, req wafreport.Request, report *wafreport.Report) error {
	return s.collect(ctx, req, report)
}

// DefaultSources can be selected or extended before assigning Sources.
func (c *ReportCollector) DefaultSources() []wafreport.Source {
	return []wafreport.Source{
		reportSource{"periods", c.collectPeriods}, reportSource{"trend", c.collectTrend},
		reportSource{"rankings", c.collectRankings}, reportSource{"audit", c.collectAudit},
		reportSource{"snapshot", c.collectSnapshot},
	}
}

func (c *ReportCollector) Collect(ctx context.Context, req wafreport.Request) (wafreport.Report, error) {
	if err := req.Validate(); err != nil {
		return wafreport.Report{}, err
	}
	if err := ctx.Err(); err != nil {
		return wafreport.Report{}, err
	}
	if req.TopN == 0 {
		req.TopN = 10
	}
	if req.Locale == "" {
		req.Locale = "zh-CN"
	}
	if req.GeneratedAt.IsZero() {
		req.GeneratedAt = time.Now()
		if c.Now != nil {
			req.GeneratedAt = c.Now()
		}
	}
	previous, _ := wafreport.PreviousRange(req.Kind, req.Range)
	r := wafreport.Report{Request: req, Current: emptyReportPeriod(req.Range), Previous: emptyReportPeriod(previous),
		Trend:      wafreport.Section[[]wafreport.TrendPoint]{State: wafreport.Unavailable},
		TopIPs:     wafreport.Section[[]wafreport.Rank]{State: wafreport.Unavailable},
		TopRules:   wafreport.Section[[]wafreport.Rank]{State: wafreport.Unavailable},
		TopPaths:   wafreport.Section[[]wafreport.Rank]{State: wafreport.Unavailable},
		TopRegions: wafreport.Section[[]wafreport.Rank]{State: wafreport.Unavailable},
		Audit:      wafreport.Section[[]wafreport.AuditCount]{State: wafreport.Unavailable},
		Snapshot:   wafreport.Section[wafreport.Snapshot]{State: wafreport.Unavailable}}
	sources := c.Sources
	if sources == nil {
		sources = c.DefaultSources()
	}
	sourceFailed := false
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if source == nil {
			sourceFailed = true
			continue
		}
		if err := source.Collect(ctx, req, &r); err != nil {
			sourceFailed = true
		}
	}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	r.Status = wafreport.CombineState(r.Current.Summary.State, r.Current.IPs.State, r.Current.Actions.State,
		r.Previous.Summary.State, r.Previous.IPs.State, r.Previous.Actions.State, r.Trend.State,
		r.TopIPs.State, r.TopRules.State, r.TopPaths.State, r.TopRegions.State, r.Audit.State, r.Snapshot.State)
	if sourceFailed {
		r.Status = wafreport.Partial
	}
	return r, nil
}

func emptyReportPeriod(r wafreport.Range) wafreport.PeriodData {
	return wafreport.PeriodData{Range: r, Summary: wafreport.Section[wafreport.Summary]{State: wafreport.Unavailable},
		IPs:     wafreport.Section[wafreport.IPCounts]{State: wafreport.Unavailable},
		Actions: wafreport.Section[[]wafreport.ActionCount]{State: wafreport.Unavailable}}
}

func reportDays(r wafreport.Range) (int, int) {
	start, _ := strconv.Atoi(r.Start.Format("20060102"))
	end, _ := strconv.Atoi(r.End.Format("20060102"))
	return start, end
}

func reportScope(ctx context.Context, db *gorm.DB, m interface{}) *gorm.DB {
	return db.WithContext(ctx).Model(m).
		Where("tenant_id = ? AND user_code = ?", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
}

func reportDayQuery(ctx context.Context, db *gorm.DB, m interface{}, r wafreport.Range) *gorm.DB {
	start, end := reportDays(r)
	return reportScope(ctx, db, m).Where("day >= ? AND day < ?", start, end)
}

func reportState(rows int64, err error) wafreport.State {
	if err != nil {
		return wafreport.Failed
	}
	if rows == 0 {
		return wafreport.NoData
	}
	return wafreport.OK
}

func reportAverage(s *wafreport.Summary) {
	if s.Requests > 0 {
		v := float64(s.TotalTimeMS) / float64(s.Requests)
		s.AverageTimeMS = &v
	}
}

const reportSummarySQL = "coalesce(sum(total_count),0) as requests, coalesce(sum(attack_count),0) as blocked, coalesce(sum(normal_count),0) as allowed, coalesce(sum(traffic_in),0) as traffic_in, coalesce(sum(traffic_out),0) as traffic_out, coalesce(sum(total_time_spent),0) as total_time_ms"

func (c *ReportCollector) collectPeriods(ctx context.Context, req wafreport.Request, r *wafreport.Report) error {
	if c.StatsDB == nil {
		return nil
	}
	for _, p := range []*wafreport.PeriodData{&r.Current, &r.Previous} {
		var sum struct {
			wafreport.Summary
			Rows int64
		}
		err := reportDayQuery(ctx, c.StatsDB, &model.StatsSiteDay{}, p.Range).
			Select("count(*) as rows, " + reportSummarySQL).Scan(&sum).Error
		p.Summary = wafreport.Section[wafreport.Summary]{State: reportState(sum.Rows, err)}
		if err == nil {
			reportAverage(&sum.Summary)
			p.Summary.Data = sum.Summary
		}
		if err != nil {
			p.Summary.Note = "summary_query_failed"
		}

		var ips struct {
			DistinctCount   int64
			BlockedDistinct int64
			Rows            int64
		}
		err = reportDayQuery(ctx, c.StatsDB, &model.StatsIPDay{}, p.Range).
			Select("count(*) as rows, count(distinct ip) as distinct_count, count(distinct case when type = ? then ip end) as blocked_distinct", "阻止").
			Scan(&ips).Error
		if err == nil {
			p.IPs.Data = wafreport.IPCounts{Distinct: ips.DistinctCount, BlockedDistinct: ips.BlockedDistinct}
		}
		p.IPs.State = reportState(ips.Rows, err)
		if err != nil {
			p.IPs.Note = "ip_query_failed"
		}

		var actions []wafreport.ActionCount
		tx := reportDayQuery(ctx, c.StatsDB, &model.StatsDay{}, p.Range).
			Select("type as action, sum(count) as count").Group("type").Order("type asc").Scan(&actions)
		p.Actions = wafreport.Section[[]wafreport.ActionCount]{State: reportState(int64(len(actions)), tx.Error), Data: actions}
		if tx.Error != nil {
			p.Actions.Data = nil
			p.Actions.Note = "action_query_failed"
		}
	}
	return nil
}

func (c *ReportCollector) collectTrend(ctx context.Context, req wafreport.Request, r *wafreport.Report) error {
	if c.StatsDB == nil {
		return nil
	}
	var rows []struct {
		Bucket int64
		wafreport.Summary
	}
	var tx *gorm.DB
	if req.Kind == wafreport.Daily {
		tx = reportScope(ctx, c.StatsDB, &model.StatsSiteHour{}).
			Where("hour_time >= ? AND hour_time < ?", req.Range.Start.Unix(), req.Range.End.Unix()).
			Select("hour_time as bucket, " + reportSummarySQL).Group("hour_time").Order("hour_time asc").Scan(&rows)
	} else {
		tx = reportDayQuery(ctx, c.StatsDB, &model.StatsSiteDay{}, req.Range).
			Select("day as bucket, " + reportSummarySQL).Group("day").Order("day asc").Scan(&rows)
	}
	r.Trend.State = reportState(int64(len(rows)), tx.Error)
	if tx.Error != nil {
		r.Trend.Note = "trend_query_failed"
		return nil
	}
	for _, row := range rows {
		var at time.Time
		if req.Kind == wafreport.Daily {
			at = time.Unix(row.Bucket, 0).In(req.Range.Start.Location())
		} else {
			at, _ = time.ParseInLocation("20060102", strconv.FormatInt(row.Bucket, 10), req.Range.Start.Location())
		}
		reportAverage(&row.Summary)
		r.Trend.Data = append(r.Trend.Data, wafreport.TrendPoint{Start: at, Summary: row.Summary})
	}
	if req.Kind == wafreport.Daily && len(rows) == 0 && r.Current.Summary.State == wafreport.OK {
		r.Trend.State = wafreport.Unavailable
		r.Trend.Note = "hourly_retention_or_missing"
	} else if len(rows) > 0 {
		expected := 0
		for at := req.Range.Start; at.Before(req.Range.End); {
			expected++
			if req.Kind == wafreport.Daily {
				at = at.Add(time.Hour)
			} else {
				at = at.AddDate(0, 0, 1)
			}
		}
		if len(rows) < expected {
			r.Trend.State = wafreport.Partial
			r.Trend.Note = "missing_buckets_not_zero_filled"
		}
	}
	return nil
}

func reportRanks(tx *gorm.DB) wafreport.Section[[]wafreport.Rank] {
	var rows []wafreport.Rank
	err := tx.Scan(&rows).Error
	s := wafreport.Section[[]wafreport.Rank]{State: reportState(int64(len(rows)), err), Data: rows}
	if err != nil {
		s.Data = nil
		s.Note = "ranking_query_failed"
	}
	for i := range s.Data {
		s.Data[i].Name = reportLabel(s.Data[i].Name)
	}
	return s
}

func reportLabel(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	return s
}

func (c *ReportCollector) collectRankings(ctx context.Context, req wafreport.Request, r *wafreport.Report) error {
	if c.StatsDB == nil {
		return nil
	}
	r.TopIPs = reportRanks(reportDayQuery(ctx, c.StatsDB, &model.StatsIPDay{}, req.Range).
		Where("type = ?", "阻止").Select("ip as name, sum(count) as count").Group("ip").
		Order("count desc").Order("ip asc").Limit(req.TopN))
	r.TopRules = reportRanks(reportDayQuery(ctx, c.StatsDB, &model.StatsPathRuleDay{}, req.Range).
		Select("rule as name, sum(cnt) as count").Group("rule").Order("count desc").Order("rule asc").Limit(req.TopN))
	r.TopPaths = reportRanks(reportDayQuery(ctx, c.StatsDB, &model.StatsActorPathDay{}, req.Range).
		Select("path_norm as name, sum(deny_cnt) as count").Group("path_norm").Having("sum(deny_cnt) > ?", 0).
		Order("count desc").Order("path_norm asc").Limit(req.TopN))
	var regions []struct {
		Country, Province, City string
		Count                   int64
	}
	err := reportDayQuery(ctx, c.StatsDB, &model.StatsIPCityDay{}, req.Range).Where("type = ?", "阻止").
		Select("country, province, city, sum(count) as count").Group("country, province, city").
		Order("count desc").Order("country asc, province asc, city asc").Limit(req.TopN).Scan(&regions).Error
	r.TopRegions.State = reportState(int64(len(regions)), err)
	if err != nil {
		r.TopRegions.Note = "ranking_query_failed"
	} else {
		for _, row := range regions {
			r.TopRegions.Data = append(r.TopRegions.Data, wafreport.Rank{
				Name: reportLabel(strings.Join([]string{row.Country, row.Province, row.City}, " / ")), Count: row.Count})
		}
	}
	return nil
}

func (c *ReportCollector) collectAudit(ctx context.Context, req wafreport.Request, r *wafreport.Report) error {
	if c.LogDB == nil {
		return nil
	}
	var rows []wafreport.AuditCount
	err := reportDayQuery(ctx, c.LogDB, &model.SecurityAuditLog{}, req.Range).
		Select("category, event, result, count(*) as count").Group("category, event, result").
		Order("category asc, event asc, result asc").Scan(&rows).Error
	r.Audit = wafreport.Section[[]wafreport.AuditCount]{State: reportState(int64(len(rows)), err), Data: rows,
		Note: "audit_rows_include_write_throttling"}
	if err != nil {
		r.Audit.Data = nil
		r.Audit.Note = "audit_query_failed"
	}
	return nil
}

func (c *ReportCollector) collectSnapshot(ctx context.Context, req wafreport.Request, r *wafreport.Report) error {
	s := wafreport.Snapshot{CollectedAt: req.GeneratedAt, Version: c.Version, WebVersion: c.WebVersion, AccessLogMode: c.AccessLogMode,
		Sites:        wafreport.Section[[]wafreport.Site]{State: wafreport.Unavailable},
		Certificates: wafreport.Section[[]wafreport.Certificate]{State: wafreport.Unavailable}}
	if c.CoreDB != nil {
		var hosts []model.Hosts
		err := reportScope(ctx, c.CoreDB, &model.Hosts{}).
			Select("code", "host", "start_status", "guard_status", "log_only_mode").
			Where("global_host <> ?", 1).Order("code asc").Scan(&hosts).Error
		s.Sites.State = reportState(int64(len(hosts)), err)
		if err != nil {
			s.Sites.Note = "site_snapshot_failed"
		} else {
			for _, host := range hosts {
				s.Sites.Data = append(s.Sites.Data, wafreport.Site{Code: host.Code, Name: reportLabel(host.Host),
					Enabled: host.START_STATUS == 0, GuardEnabled: host.GUARD_STATUS == 1,
					LogOnly: host.LogOnlyMode == 1})
			}
		}
		var certs []model.SslConfig
		err = reportScope(ctx, c.CoreDB, &model.SslConfig{}).Select("id", "subject", "serial_no", "domains", "valid_from", "valid_to").Order("id asc").Scan(&certs).Error
		s.Certificates.State = reportState(int64(len(certs)), err)
		if err != nil {
			s.Certificates.Note = "certificate_snapshot_failed"
		} else {
			for _, cert := range certs {
				from, to := time.Time(cert.ValidFrom), time.Time(cert.ValidTo)
				state := "valid"
				switch {
				case to.IsZero() || from.IsZero():
					state = "unknown"
				case !to.After(req.GeneratedAt):
					state = "expired"
				case from.After(req.GeneratedAt):
					state = "not_yet_valid"
				case to.Before(req.GeneratedAt.AddDate(0, 0, 30)):
					state = "expiring"
				}
				name := strings.TrimSpace(cert.Subject)
				if name == "" {
					name = strings.TrimSpace(cert.SerialNo)
				}
				if name == "" {
					name = cert.Id
				}
				s.Certificates.Data = append(s.Certificates.Data, wafreport.Certificate{
					ID: cert.Id, Name: name, Domains: cert.Domains, ValidFrom: from, ValidTo: to, State: state,
				})
			}
		}
	}
	r.Snapshot = wafreport.Section[wafreport.Snapshot]{State: wafreport.CombineState(s.Sites.State, s.Certificates.State), Data: s}
	return nil
}

var _ wafreport.Collector = (*ReportCollector)(nil)
