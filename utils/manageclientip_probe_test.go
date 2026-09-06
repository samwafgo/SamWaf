package utils

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"SamWaf/global"

	"github.com/gin-gonic/gin"
)

// TestProbeOverRealSocket 走真实 TCP 连接跑一遍三组配置：验证 gin 的 c.RemoteIP()、
// 诊断接口的 JSON 字段名与取值链路端到端接得上（127.0.0.1 在这里扮演容器网关的角色）。
func TestProbeOverRealSocket(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/probe", func(c *gin.Context) { c.JSON(200, TraceManageClientIP(c)) })
	srv := httptest.NewServer(r)
	defer srv.Close()

	oldH, oldT, oldC := global.GCONFIG_MANAGE_PROXY_HEADER, global.GCONFIG_MANAGE_TRUSTED_PROXIES, global.GCONFIG_MANAGE_CDN_PROVIDER
	defer func() {
		global.GCONFIG_MANAGE_PROXY_HEADER, global.GCONFIG_MANAGE_TRUSTED_PROXIES, global.GCONFIG_MANAGE_CDN_PROVIDER = oldH, oldT, oldC
	}()
	global.GCONFIG_MANAGE_PROXY_HEADER = "CF-Connecting-IP"
	global.GCONFIG_MANAGE_CDN_PROVIDER = ""

	cases := []struct{ name, trusted, wantIP, wantReason string }{
		{"配置A 0.0.0.0/0（过宽）", "0.0.0.0/0", "127.0.0.1", ManageIPReasonOverBroadGate},
		{"配置B 网关精确地址", "127.0.0.1", "1.2.3.4", ManageIPReasonRightmostUntrusted},
		{"配置C private 关键字", "private", "1.2.3.4", ManageIPReasonRightmostUntrusted},
	}
	for _, cs := range cases {
		global.GCONFIG_MANAGE_TRUSTED_PROXIES = cs.trusted
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/probe", nil)
		req.Header.Set("CF-Connecting-IP", "1.2.3.4")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("[%s] 请求失败: %v", cs.name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var got ManageClientIPTrace
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("[%s] 解析失败: %v, body=%s", cs.name, err, body)
		}
		t.Logf("[%s] trusted=%-12s => client_ip=%-10s reason=%-22s peer=%s trusted_by=%q overbroad=%v",
			cs.name, cs.trusted, got.ClientIP, got.Reason, got.RemoteIP, got.PeerTrustedBy, got.GateOverBroad)
		if got.ClientIP != cs.wantIP || got.Reason != cs.wantReason {
			t.Errorf("[%s] got %s/%s want %s/%s", cs.name, got.ClientIP, got.Reason, cs.wantIP, cs.wantReason)
		}
	}
}
