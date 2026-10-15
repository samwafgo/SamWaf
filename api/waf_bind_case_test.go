package api

import (
	"SamWaf/model/request"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// GET 接口的 query 绑定历史上只认 Go 字段名（大写），而 Swagger 与产品内文档一律写小写，
// 外部调用方按文档写就会静默拿到零值结构体（issue #1008）。这里用真实 gin 绑定行为做守护。

func bindQuery(t *testing.T, query string, out interface{}) error {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var bindErr error
	r.GET("/probe", func(c *gin.Context) { bindErr = c.ShouldBind(out) })
	target := "/probe"
	if query != "" {
		target += "?" + query
	}
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", target, nil))
	return bindErr
}

func TestGetQueryBindingUsesLowercaseName(t *testing.T) {
	t.Run("host detail", func(t *testing.T) {
		var req request.WafHostDetailReq
		if err := bindQuery(t, "code=abc", &req); err != nil {
			t.Fatalf("bind: %v", err)
		}
		if req.CODE != "abc" {
			t.Fatalf("lowercase code not bound, got %q", req.CODE)
		}
	})
	t.Run("host del", func(t *testing.T) {
		var req request.WafHostDelReq
		if err := bindQuery(t, "code=abc", &req); err != nil {
			t.Fatalf("bind: %v", err)
		}
		if req.CODE != "abc" {
			t.Fatalf("lowercase code not bound, got %q", req.CODE)
		}
	})
	t.Run("host guard status", func(t *testing.T) {
		var req request.WafHostGuardStatusReq
		if err := bindQuery(t, "code=abc&guard_status=1", &req); err != nil {
			t.Fatalf("bind: %v", err)
		}
		if req.CODE != "abc" || req.GUARD_STATUS != 1 {
			t.Fatalf("guard status not bound: %+v", req)
		}
	})
	t.Run("host start status", func(t *testing.T) {
		var req request.WafHostStartStatusReq
		if err := bindQuery(t, "code=abc&start_status=1", &req); err != nil {
			t.Fatalf("bind: %v", err)
		}
		if req.CODE != "abc" || req.START_STATUS != 1 {
			t.Fatalf("start status not bound: %+v", req)
		}
	})
	t.Run("rule detail", func(t *testing.T) {
		var req request.WafRuleDetailReq
		if err := bindQuery(t, "code=rule001", &req); err != nil {
			t.Fatalf("bind: %v", err)
		}
		if req.CODE != "rule001" {
			t.Fatalf("lowercase code not bound, got %q", req.CODE)
		}
	})
	t.Run("rule del", func(t *testing.T) {
		var req request.WafRuleDelReq
		if err := bindQuery(t, "code=rule001", &req); err != nil {
			t.Fatalf("bind: %v", err)
		}
		if req.CODE != "rule001" {
			t.Fatalf("lowercase code not bound, got %q", req.CODE)
		}
	})
	t.Run("rule status", func(t *testing.T) {
		var req request.WafRuleStatusReq
		if err := bindQuery(t, "code=rule001&rule_status=1", &req); err != nil {
			t.Fatalf("bind: %v", err)
		}
		if req.CODE != "rule001" || req.RULE_STATUS != 1 {
			t.Fatalf("rule status not bound: %+v", req)
		}
	})
}

// 关防御/停服务/禁规则传的是 0，不能被当成缺参
func TestGetQueryBindingAllowsZeroStatus(t *testing.T) {
	var guard request.WafHostGuardStatusReq
	if err := bindQuery(t, "code=abc&guard_status=0", &guard); err != nil {
		t.Fatalf("guard_status=0 should bind: %v", err)
	}
	if guard.GUARD_STATUS != 0 || guard.CODE != "abc" {
		t.Fatalf("unexpected: %+v", guard)
	}
	var start request.WafHostStartStatusReq
	if err := bindQuery(t, "code=abc&start_status=0", &start); err != nil {
		t.Fatalf("start_status=0 should bind: %v", err)
	}
	var rule request.WafRuleStatusReq
	if err := bindQuery(t, "code=rule001&rule_status=0", &rule); err != nil {
		t.Fatalf("rule_status=0 should bind: %v", err)
	}
}

// 大写参数名是历史写法，改动后不再生效（缺 code 直接报错，不再静默返回空数据）
func TestGetQueryBindingRejectsLegacyUppercaseAndMissing(t *testing.T) {
	var detail request.WafHostDetailReq
	if err := bindQuery(t, "CODE=abc", &detail); err == nil {
		t.Fatal("uppercase CODE should no longer satisfy the required binding")
	}
	if detail.CODE != "" {
		t.Fatalf("uppercase CODE unexpectedly bound: %q", detail.CODE)
	}
	if err := bindQuery(t, "", &detail); err == nil {
		t.Fatal("missing code should fail binding")
	}
	var guard request.WafHostGuardStatusReq
	if err := bindQuery(t, "guard_status=1", &guard); err == nil {
		t.Fatal("missing code should fail binding")
	}
	guard = request.WafHostGuardStatusReq{}
	if err := bindQuery(t, "code=abc&GUARD_STATUS=1", &guard); err != nil {
		t.Fatalf("uppercase GUARD_STATUS should be ignored: %v", err)
	}
	if guard.GUARD_STATUS != 0 {
		t.Fatalf("uppercase GUARD_STATUS unexpectedly bound: %d", guard.GUARD_STATUS)
	}
}

// 这几个 req 同时被 POST(JSON) 用，必须保持 json 绑定不受影响
func TestJSONBodyBindingStillWorks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var req request.WafHostGuardStatusReq
	r.POST("/probe", func(c *gin.Context) {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.String(500, err.Error())
			return
		}
		c.String(200, req.CODE)
	})
	httpReq := httptest.NewRequest("POST", "/probe", strings.NewReader(`{"code":"abc","guard_status":1}`))
	httpReq.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httpReq)
	if rec.Code != 200 || rec.Body.String() != "abc" {
		t.Fatalf("json bind broken: %d %s", rec.Code, rec.Body.String())
	}
}
