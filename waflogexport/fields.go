package waflogexport

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

type Field struct {
	Column string `json:"column"`
	Name   string `json:"name"`
	Type   string `json:"type"`
}

var commonFields = []Field{
	{"req_uuid", "req_uuid", "text"}, {"tenant_id", "tenant_id", "text"}, {"user_code", "user_code", "text"}, {"host_code", "host_code", "text"}, {"host", "host", "text"},
	{"url", "url", "text"}, {"raw_query", "raw_query", "text"}, {"method", "method", "text"}, {"scheme", "scheme", "text"}, {"referer", "referer", "text"}, {"user_agent", "user_agent", "text"},
	{"src_ip", "src_ip", "text"}, {"src_port", "src_port", "text"}, {"net_src_ip", "net_src_ip", "text"}, {"country", "country", "text"}, {"province", "province", "text"}, {"city", "city", "text"},
	{"action", "action", "text"}, {"rule", "rule", "text"}, {"status", "status", "text"}, {"status_code", "status_code", "integer"}, {"risk_level", "risk_level", "integer"}, {"ai_score", "ai_score", "real"}, {"is_bot", "is_bot", "integer"}, {"log_only_mode", "log_only_mode", "integer"}, {"guest_id_entification", "guest_identification", "text"},
	{"time_spent", "time_spent", "integer"}, {"content_length", "content_length", "integer"}, {"res_content_length", "res_content_length", "integer"}, {"pre_check_cost", "pre_check_cost", "integer"}, {"forward_cost", "forward_cost", "integer"}, {"backend_check_cost", "backend_check_cost", "integer"},
	{"is_balance", "is_balance", "integer"}, {"balance_info", "balance_info", "text"}, {"body_hash", "body_hash", "text"}, {"truncated", "truncated", "integer"}, {"actor_key", "actor_key", "text"}, {"ua_hash", "ua_hash", "text"}, {"path_norm", "path_norm", "text"},
	{"create_time", "create_time", "text"}, {"unix_add_time", "unix_add_time", "integer"}, {"day", "day", "integer"},
}

func Fields(table string) ([]Field, error) {
	if table != "access_log" && table != "security_event" {
		return nil, errors.New("unsupported export table")
	}
	out := append([]Field(nil), commonFields...)
	if table == "security_event" {
		out = append(out, Field{"payload_hash", "payload_hash", "text"})
	}
	return out, nil
}

func normalize(table string, row map[string]interface{}) (map[string]interface{}, error) {
	fields, err := Fields(table)
	if err != nil {
		return nil, err
	}
	out := make(map[string]interface{}, len(fields))
	for _, f := range fields {
		v, ok := row[f.Column]
		if !ok {
			v = row[f.Name]
		}
		if v == nil {
			out[f.Name] = nil
			continue
		}
		if raw, ok := v.([]byte); ok {
			v = string(raw)
		}
		switch f.Type {
		case "text":
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("invalid text field %s", f.Name)
			}
			out[f.Name] = s
		case "integer":
			var text string
			switch n := v.(type) {
			case int:
				text = strconv.FormatInt(int64(n), 10)
			case int8:
				text = strconv.FormatInt(int64(n), 10)
			case int16:
				text = strconv.FormatInt(int64(n), 10)
			case int32:
				text = strconv.FormatInt(int64(n), 10)
			case int64:
				text = strconv.FormatInt(n, 10)
			case uint:
				text = strconv.FormatUint(uint64(n), 10)
			case uint8:
				text = strconv.FormatUint(uint64(n), 10)
			case uint16:
				text = strconv.FormatUint(uint64(n), 10)
			case uint32:
				text = strconv.FormatUint(uint64(n), 10)
			case uint64:
				text = strconv.FormatUint(n, 10)
			case float64:
				if n != math.Trunc(n) || math.Abs(n) > 9007199254740991 {
					return nil, fmt.Errorf("inexact integer field %s", f.Name)
				}
				text = strconv.FormatFloat(n, 'f', 0, 64)
			case string:
				text = n
			case json.Number:
				text = string(n)
			default:
				return nil, fmt.Errorf("invalid integer field %s", f.Name)
			}
			n, err := strconv.ParseInt(text, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid integer field %s", f.Name)
			}
			out[f.Name] = n
		case "real":
			text := fmt.Sprint(v)
			n, err := strconv.ParseFloat(text, 64)
			if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
				return nil, fmt.Errorf("invalid real field %s", f.Name)
			}
			out[f.Name] = n
		}
	}
	id, ok := out["req_uuid"].(string)
	if !ok || len(id) == 0 || len(id) > 64 {
		return nil, errors.New("invalid req_uuid")
	}
	return out, nil
}

func csvText(v interface{}) string {
	if v == nil {
		return ""
	}
	text := fmt.Sprint(v)
	if _, ok := v.(string); !ok {
		return text
	}
	trimmed := strings.TrimLeftFunc(text, func(r rune) bool { return r <= 32 || r == 127 || r == ' ' || r == 0xfeff })
	if len(trimmed) > 0 && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + text
	}
	return text
}
