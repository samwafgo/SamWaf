package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestDecodeReportBodyStrict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"unknown_field", `{"enabled":true,"unknown":1}`, "未知字段"},
		{"oversize_body", strings.Repeat("a", 9<<10), "不超过8KiB"},
		{"two_json_objects", `{"enabled":true}{"enabled":false}`, "只能包含一个JSON对象"},
		{"invalid_json", `{"enabled":`, "不超过8KiB"},
		{"null_config", `null`, ""},
		{"empty_object", `{}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/samwaf/report/config", bytes.NewBufferString(tc.body))
			var cfg *struct {
				Enabled bool `json:"enabled"`
			}
			err := decodeReportBody(c, &cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("decode should succeed, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestReportBodyIDValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"valid", `{"id":"report-0123456789abcdef"}`, ""},
		{"too_short", `{"id":"short"}`, "报告编号不正确"},
		{"bad_char", `{"id":"report-0123456789abcde!"}`, "报告编号不正确"},
		{"path_ish", `{"id":"../../etc/passwd"}`, "报告编号不正确"},
		{"unknown_field", `{"id":"report-0123456789abcdef","x":1}`, "未知字段"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/samwaf/report/download", bytes.NewBufferString(tc.body))
			got, err := reportBodyID(c)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("reportBodyID should succeed, got %v", err)
				}
				if tc.body != `null` && got != "report-0123456789abcdef" {
					t.Fatalf("unexpected id: %q", got)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestDecodeReportBodyLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var big bytes.Buffer
	big.WriteString(`{"enabled":`)
	big.WriteString(strings.Repeat("a", 9<<10))
	big.WriteString(`}`)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/samwaf/report/config", &big)
	var cfg *struct {
		Enabled bool `json:"enabled"`
	}
	err := decodeReportBody(c, &cfg)
	if err == nil || !strings.Contains(err.Error(), "不超过8KiB") {
		t.Fatalf("want oversize error, got %v", err)
	}
}

func TestDecodeReportBodySingleObjectOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, body := range []string{
		`{"enabled":true} {}`,
		`{"enabled":true} 123`,
		`{"enabled":true} "x"`,
		`{"enabled":true} null`,
	} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/samwaf/report/config", bytes.NewBufferString(body))
		var cfg *struct {
			Enabled bool `json:"enabled"`
		}
		err := decodeReportBody(c, &cfg)
		if err == nil || !strings.Contains(err.Error(), "只能包含一个JSON对象") {
			t.Fatalf("body %q should be rejected as multiple objects, got %v", body, err)
		}
	}
}

// 直接覆盖 decodeReportBody 的 EOF 分支，防止工具优化掉。
func TestDecodeReportBodyEOFCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/samwaf/report/config", bytes.NewBufferString(`{"enabled":true}`))
	var cfg *struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeReportBody(c, &cfg); err != nil {
		t.Fatalf("single object should pass, got %v", err)
	}
	if cfg == nil || cfg.Enabled != true {
		t.Fatalf("decoded cfg mismatch: %+v", cfg)
	}
}

// 保持 import 使用，避免未使用错误。
var _ = json.Marshal
var _ = io.EOF
