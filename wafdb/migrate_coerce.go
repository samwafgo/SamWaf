package wafdb

import (
	"SamWaf/wafdb/dialect"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

// ===========================================================================
// Value coercion for cross-engine data copy
// ===========================================================================
//
// SQLite is dynamically typed and MySQL is permissive, but PostgreSQL is strict:
// it will reject an integer 0 going into a boolean column, or an empty string going
// into a timestamp. Copying rows verbatim therefore works for a MySQL target (which
// is what the tool did historically) but blows up on a PostgreSQL target.
//
// The fix is to read the TARGET column types once per table and build a per-column
// conversion function, applied to every scanned value.
//
// When the target is MySQL the coercers deliberately collapse to the historical
// behaviour ([]byte -> string, everything else passed through untouched), so the
// long-standing SQLite -> MySQL path cannot regress.

type coercer func(v interface{}) interface{}

type colKind int

const (
	kindText colKind = iota
	kindBool
	kindNumeric
	kindTime
	kindBytes
)

// classifyPGType maps a PostgreSQL information_schema.data_type string to a kind.
func classifyPGType(dataType string) colKind {
	switch strings.ToLower(strings.TrimSpace(dataType)) {
	case "boolean":
		return kindBool
	case "smallint", "integer", "bigint", "numeric", "real", "double precision":
		return kindNumeric
	case "timestamp with time zone", "timestamp without time zone", "date", "time without time zone":
		return kindTime
	case "bytea":
		return kindBytes
	default:
		return kindText
	}
}

// buildCoercers returns one coercer per column in cols, derived from the target
// table's column types. cols are source column names; matching is case-insensitive
// because PostgreSQL folds unquoted identifiers to lower case.
func buildCoercers(dstDia dialect.DBDialect, dstDB *gorm.DB, table string, cols []string) []coercer {
	out := make([]coercer, len(cols))

	// Only PostgreSQL needs real coercion. For any other target keep the historical
	// permissive behaviour so the existing SQLite -> MySQL path is untouched.
	if dstDia.Name() != "postgres" {
		for i := range out {
			out[i] = coerceText
		}
		return out
	}

	byName := map[string]colKind{}
	if metas, err := dstDia.ColumnInfo(dstDB, table); err == nil {
		for _, m := range metas {
			byName[strings.ToLower(m.Name)] = classifyPGType(m.Type)
		}
	}

	for i, c := range cols {
		switch byName[strings.ToLower(c)] {
		case kindBool:
			out[i] = coerceBool
		case kindNumeric:
			out[i] = coerceNumeric
		case kindTime:
			out[i] = coerceTime
		case kindBytes:
			out[i] = coerceBytes
		default:
			out[i] = coerceText
		}
	}
	return out
}

// coerceText is the historical behaviour: SQLite hands back TEXT/BLOB as []byte,
// which MySQL accepts only as a string.
func coerceText(v interface{}) interface{} {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return v
}

// coerceBytes keeps binary columns binary. PostgreSQL's bytea codec wants []byte;
// stringifying it (as coerceText does) would corrupt or reject the value.
// web_logs.src_byte_body / src_byte_res_body / src_url are the real cases.
func coerceBytes(v interface{}) interface{} {
	switch x := v.(type) {
	case nil:
		return nil
	case []byte:
		return x
	case string:
		return []byte(x)
	default:
		return v
	}
}

// coerceBool converts SQLite/MySQL's 0/1 integer representation into a real boolean.
// anti_ccs.is_enable_rule and anti_ccs.skip_global_cc are the only persisted bool
// columns in the schema, but getting this wrong silently disables every CC rule.
func coerceBool(v interface{}) interface{} {
	switch x := v.(type) {
	case nil:
		return nil
	case bool:
		return x
	case int64:
		return x != 0
	case int32:
		return x != 0
	case int:
		return x != 0
	case float64:
		return x != 0
	case []byte:
		return coerceBool(string(x))
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "":
			return nil
		case "0", "false", "f", "no":
			return false
		default:
			return true
		}
	default:
		return v
	}
}

// coerceNumeric guards the empty-string case. SQLite's dynamic typing happily stores
// '' in a column declared INTEGER; PostgreSQL rejects it outright. NULL — not 0 — is
// the right target: it preserves "no value" rather than inventing a zero.
func coerceNumeric(v interface{}) interface{} {
	switch x := v.(type) {
	case nil:
		return nil
	case []byte:
		return coerceNumeric(string(x))
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return nil
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
		return nil // unparseable -> NULL rather than a hard failure mid-migration
	default:
		return v
	}
}

// pgTimeLayouts are tried in order against a text timestamp from the source.
// go-wxsqlite3 writes time.Time as '2006-01-02 15:04:05.999999999-07:00'.
var pgTimeLayouts = []string{
	"2006-01-02 15:04:05.999999999-07:00",
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999 -0700 MST",
}

// pgTimeLayoutsLocal are zone-less layouts. They MUST be parsed with ParseInLocation
// against time.Local: time.Parse would assume UTC and shift every such value by the
// local offset, which is exactly the silent-8-hour-drift failure this code exists to
// avoid (SamWaf's storage contract is local wall-clock, never UTC).
var pgTimeLayoutsLocal = []string{
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

// coerceTime turns the source's timestamp representation into a time.Time.
// SQLite may hand back either a time.Time or raw text depending on the column's
// declared type; MySQL (parseTime=True, loc=Local) always hands back time.Time.
func coerceTime(v interface{}) interface{} {
	switch x := v.(type) {
	case nil:
		return nil
	case time.Time:
		return x
	case []byte:
		return coerceTime(string(x))
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return nil
		}
		for _, layout := range pgTimeLayouts {
			if t, err := time.Parse(layout, s); err == nil {
				return t
			}
		}
		for _, layout := range pgTimeLayoutsLocal {
			if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
				return t
			}
		}
		return nil // unparseable -> NULL rather than aborting the table
	default:
		return v
	}
}
