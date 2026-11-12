package wafreport

import (
	"errors"
	"time"
)

// NewRange uses anchor's location; callers use time.Local for instance reports.
func NewRange(kind Kind, anchor time.Time) (Range, error) {
	if anchor.IsZero() {
		return Range{}, errors.New("report date is required")
	}
	start := time.Date(anchor.Year(), anchor.Month(), anchor.Day(), 0, 0, 0, 0, anchor.Location())
	var end time.Time
	switch kind {
	case Daily:
		end = start.AddDate(0, 0, 1)
	case Weekly:
		offset := (int(start.Weekday()) + 6) % 7
		start = start.AddDate(0, 0, -offset)
		end = start.AddDate(0, 0, 7)
	case Monthly:
		start = time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, start.Location())
		end = start.AddDate(0, 1, 0)
	default:
		return Range{}, errors.New("unsupported report kind")
	}
	return Range{Start: start, End: end}, nil
}

func (r Range) Validate(kind Kind) error {
	expected, err := NewRange(kind, r.Start)
	if err != nil {
		return err
	}
	if !r.Start.Equal(expected.Start) || !r.End.Equal(expected.End) || r.End.Location().String() != r.Start.Location().String() {
		return errors.New("report range must be one complete calendar period")
	}
	return nil
}

func PreviousRange(kind Kind, r Range) (Range, error) {
	if err := r.Validate(kind); err != nil {
		return Range{}, err
	}
	return NewRange(kind, r.Start.AddDate(0, 0, -1))
}

func (r Request) Validate() error {
	if err := r.Range.Validate(r.Kind); err != nil {
		return err
	}
	if r.Locale != "" && r.Locale != "zh-CN" && r.Locale != "en-US" {
		return errors.New("unsupported report locale")
	}
	if r.TopN < 0 || r.TopN > 100 {
		return errors.New("report top_n must be between 0 and 100")
	}
	return nil
}
