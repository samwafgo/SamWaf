package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"github.com/gin-gonic/gin"
)

// TestIPBlockDatabaseErrors 保证写库失败不返回成功、重载失败不投递空名单。
func TestIPBlockDatabaseErrors(t *testing.T) {
	setupNotifyTestEnv(t, &model.IPBlockList{})
	db, err := global.GWAF_LOCAL_DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	service := waf_service.WafBlockIpServiceApp
	if err = service.AddApi(request.WafBlockIpAddReq{HostCode: "site-a", Ip: "198.51.100.7"}); err == nil {
		t.Fatal("database write failure reported success")
	}
	api := &WafBlockIpApi{}
	if err = api.NotifyWaf("site-a"); err == nil {
		t.Fatal("database read failure reported success")
	}
	if len(global.GWAF_CHAN_MSG) != 0 {
		t.Fatal("failed reload published an empty policy")
	}
	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/wafhost/ipblock/add", bytes.NewBufferString(`{"host_code":"site-a","ip":"198.51.100.7"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	api.AddApi(ctx)
	// 控制台既有协议使用 HTTP 200 + 独立后端故障码，业务代理请求则返回实际 HTTP 503。
	var result struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(writer.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Code != -6 {
		t.Fatalf("database failure returned a success envelope: %s", writer.Body.String())
	}
}
