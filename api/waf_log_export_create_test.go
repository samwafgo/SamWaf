package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func decodeCreateForTest(t *testing.T, body string) (err error) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest("POST", "/api/v1/waflog/exports", strings.NewReader(body))
	_, err = decodeLogExportCreate(ctx)
	return err
}

func TestDecodeLogExportCreateDefaultsAndWhitelist(t *testing.T) {
	body := `{"request_id":"req-1","format":"jsonl","tables":["security_event","access_log"],"range_mode":"custom","start_time":"2026-10-29T00:00:00+08:00","end_time":"2026-10-29T01:00:00+08:00"}`
	if err := decodeCreateForTest(t, body); err != nil {
		t.Fatalf("合法请求被拒绝: %v", err)
	}
	if err := decodeCreateForTest(t, `{"request_id":"req-1","tables":["access_log","access_log"]}`); err == nil {
		t.Fatal("重复日志表应被拒绝")
	}
	if err := decodeCreateForTest(t, `{"request_id":"req-1","tables":["web_logs"]}`); err == nil {
		t.Fatal("非白名单日志表应被拒绝")
	}
	if err := decodeCreateForTest(t, `{"request_id":"req-1","unknown":true}`); err == nil {
		t.Fatal("未知字段应被拒绝")
	}
	if err := decodeCreateForTest(t, `{"request_id":"req-1","range_mode":"custom","start_time":"2026-10-29T01:00:00+08:00","end_time":"2026-10-29T01:00:00+08:00"}`); err == nil {
		t.Fatal("开始时间不早于结束时间应被拒绝")
	}
}
