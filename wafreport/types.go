package wafreport

import (
	"context"
	"io"
	"time"
)

type Kind string

const (
	Daily   Kind = "daily"
	Weekly  Kind = "weekly"
	Monthly Kind = "monthly"
)

type State string

const (
	OK          State = "ok"
	NoData      State = "no_data"
	Failed      State = "failed"
	Partial     State = "partial"
	Unavailable State = "unavailable"
)

// Section keeps absent data separate from a measured zero.
type Section[T any] struct {
	State State  `json:"state"`
	Data  T      `json:"data"`
	Note  string `json:"note,omitempty"`
}

type Range struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type Request struct {
	ID          string    `json:"id"`
	Kind        Kind      `json:"kind"`
	Range       Range     `json:"range"`
	Locale      string    `json:"locale"`
	TopN        int       `json:"top_n"`
	GeneratedAt time.Time `json:"generated_at"`
}

type Collector interface {
	Collect(context.Context, Request) (Report, error)
}

type Renderer interface {
	Render(context.Context, io.Writer, Report) error
}

// Source fills one named section; Collectors can compose independent sources.
type Source interface {
	Name() string
	Collect(context.Context, Request, *Report) error
}

type Summary struct {
	Requests      int64    `json:"requests"`
	Blocked       int64    `json:"blocked"`
	Allowed       int64    `json:"allowed"`
	TrafficIn     int64    `json:"traffic_in"`
	TrafficOut    int64    `json:"traffic_out"`
	TotalTimeMS   int64    `json:"total_time_ms"`
	AverageTimeMS *float64 `json:"average_time_ms,omitempty"`
}

type IPCounts struct {
	Distinct        int64 `json:"distinct"`
	BlockedDistinct int64 `json:"blocked_distinct"`
}

type ActionCount struct {
	Action string `json:"action"`
	Count  int64  `json:"count"`
}

type PeriodData struct {
	Range   Range                  `json:"range"`
	Summary Section[Summary]       `json:"summary"`
	IPs     Section[IPCounts]      `json:"ips"`
	Actions Section[[]ActionCount] `json:"actions"`
}

type TrendPoint struct {
	Start time.Time `json:"start"`
	Summary
}

type Rank struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type AuditCount struct {
	Category string `json:"category"`
	Event    string `json:"event"`
	Result   int    `json:"result"`
	Count    int64  `json:"count"`
}

type Site struct {
	Code         string `json:"code"`
	Name         string `json:"name"`
	Enabled      bool   `json:"enabled"`
	GuardEnabled bool   `json:"guard_enabled"`
	LogOnly      bool   `json:"log_only"`
}

type Certificate struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Domains   string    `json:"domains"`
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`
	State     string    `json:"state"`
}

type Snapshot struct {
	CollectedAt   time.Time              `json:"collected_at"`
	Version       string                 `json:"version"`
	WebVersion    string                 `json:"web_version"`
	AccessLogMode string                 `json:"access_log_mode"`
	Sites         Section[[]Site]        `json:"sites"`
	Certificates  Section[[]Certificate] `json:"certificates"`
}

type Report struct {
	Request    Request               `json:"request"`
	Status     State                 `json:"status"`
	Current    PeriodData            `json:"current"`
	Previous   PeriodData            `json:"previous"`
	Trend      Section[[]TrendPoint] `json:"trend"`
	TopIPs     Section[[]Rank]       `json:"top_ips"`
	TopRules   Section[[]Rank]       `json:"top_rules"`
	TopPaths   Section[[]Rank]       `json:"top_paths"`
	TopRegions Section[[]Rank]       `json:"top_regions"`
	Audit      Section[[]AuditCount] `json:"audit"`
	Snapshot   Section[Snapshot]     `json:"snapshot"`
}

// CombineState describes availability, not whether all event counters are zero.
func CombineState(states ...State) State {
	usable, empty, failed, unavailable := false, false, false, false
	for _, state := range states {
		switch state {
		case OK:
			usable = true
		case NoData:
			empty = true
		case Partial:
			return Partial
		case Failed:
			failed = true
		default:
			unavailable = true
		}
	}
	if failed {
		if usable || empty {
			return Partial
		}
		return Failed
	}
	if unavailable {
		if usable || empty {
			return Partial
		}
		return Unavailable
	}
	if usable {
		return OK
	}
	return NoData
}
