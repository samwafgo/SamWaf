package wafreport

import (
	"testing"
	"time"
	_ "time/tzdata"
)

func TestReportCalendarRanges(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		kind                       Kind
		date, start, end, previous string
	}{
		{Daily, "2024-03-10", "2024-03-10", "2024-03-11", "2024-03-09"},
		{Weekly, "2025-01-01", "2024-12-30", "2025-01-06", "2024-12-23"},
		{Monthly, "2024-03-31", "2024-03-01", "2024-04-01", "2024-02-01"},
		{Monthly, "2024-02-29", "2024-02-01", "2024-03-01", "2024-01-01"},
	}
	for _, tc := range cases {
		anchor, _ := time.ParseInLocation("2006-01-02", tc.date, loc)
		r, err := NewRange(tc.kind, anchor.Add(12*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		prev, err := PreviousRange(tc.kind, r)
		if err != nil {
			t.Fatal(err)
		}
		if r.Start.Format("2006-01-02") != tc.start || r.End.Format("2006-01-02") != tc.end || prev.Start.Format("2006-01-02") != tc.previous || !prev.End.Equal(r.Start) {
			t.Fatalf("%s %s: %+v previous %+v", tc.kind, tc.date, r, prev)
		}
		if tc.kind == Daily && r.End.Sub(r.Start) != 23*time.Hour {
			t.Fatalf("DST day must be 23h: %v", r)
		}
	}
}

func TestReportRangeValidation(t *testing.T) {
	if _, err := NewRange("other", time.Now()); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if _, err := NewRange(Daily, time.Time{}); err == nil {
		t.Fatal("zero date accepted")
	}
	r, _ := NewRange(Daily, time.Now())
	r.End = r.End.Add(time.Second)
	if err := r.Validate(Daily); err == nil {
		t.Fatal("noncalendar range accepted")
	}
	r, _ = NewRange(Daily, time.Now())
	for _, req := range []Request{{Kind: Daily, Range: r, Locale: "bad"}, {Kind: Daily, Range: r, TopN: 101}, {Kind: Daily, Range: r, TopN: -1}} {
		if req.Validate() == nil {
			t.Fatalf("invalid request accepted: %+v", req)
		}
	}
}

func TestReportStates(t *testing.T) {
	for _, tc := range []struct {
		states []State
		want   State
	}{
		{[]State{OK, NoData}, OK}, {[]State{Failed, OK}, Partial}, {[]State{Failed, Failed}, Failed},
		{[]State{NoData, NoData}, NoData}, {[]State{Unavailable, OK}, Partial}, {[]State{Partial, OK}, Partial},
	} {
		if got := CombineState(tc.states...); got != tc.want {
			t.Fatalf("%v: %s want %s", tc.states, got, tc.want)
		}
	}
}
