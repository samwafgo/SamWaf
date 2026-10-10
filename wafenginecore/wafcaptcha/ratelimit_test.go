package wafcaptcha

import (
	"net/http/httptest"
	"testing"

	"SamWaf/cache"
)

func newRateLimitTestService() *CaptchaService {
	return &CaptchaService{cache: cache.InitWafCache()}
}

func TestAllowCaptchaRequest_LimitPerIPAndAction(t *testing.T) {
	s := newRateLimitTestService()

	for i := 0; i < 3; i++ {
		if !s.allowCaptchaRequest("verify", "192.0.2.10", 3) {
			t.Fatalf("第 %d 次请求不应被限", i+1)
		}
	}
	if s.allowCaptchaRequest("verify", "192.0.2.10", 3) {
		t.Fatal("超过阈值后应被限")
	}
	if !s.allowCaptchaRequest("verify", "192.0.2.11", 3) {
		t.Fatal("不同 IP 的计数应互相独立")
	}
	if !s.allowCaptchaRequest("click_basic", "192.0.2.10", 3) {
		t.Fatal("不同动作的计数应互相独立")
	}
}

func TestAllowCaptchaRequest_FailOpenWhenIPUnavailable(t *testing.T) {
	s := newRateLimitTestService()
	if !s.allowCaptchaRequest("verify", "", 1) {
		t.Fatal("拿不到 IP 时不应阻断")
	}

	var nilSvc *CaptchaService
	if !nilSvc.allowCaptchaRequest("verify", "192.0.2.10", 1) {
		t.Fatal("服务未初始化时不应阻断")
	}
}

func TestWriteCaptchaRateLimited(t *testing.T) {
	rec := httptest.NewRecorder()
	writeCaptchaRateLimited(rec)

	if rec.Code != 429 {
		t.Fatalf("状态码应为 429，实际 %d", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Fatal("应带 Retry-After 头")
	}
	if body := rec.Body.String(); body == "" || body[0] != '{' {
		t.Fatalf("响应体应为 JSON，实际 %q", body)
	}
}
