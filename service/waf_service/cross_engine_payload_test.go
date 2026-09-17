//go:build crossdb

// 报文垂直拆表的三库回归：报文按 req_uuid 点查、老数据回落读 web_logs 原列、
// 保留期清理连报文一起删。由 TestCrossEngine 每引擎调一次。
package waf_service

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	req "SamWaf/model/request"
	"testing"
	"time"

	"gorm.io/gorm"
)

func runPayloadCases(t *testing.T, logdb *gorm.DB) {
	now := time.Now()

	// 新数据：窄行不带报文，报文在 event_payload 里，详情按 req_uuid 点查补回来
	t.Run("拆表后详情能读到报文", func(t *testing.T) {
		uid := "req_split_" + sfx()
		must(t, logdb.Create(&innerbean.WebLog{
			REQ_UUID:      uid,
			HOST_CODE:     "h1",
			URL:           "/login",
			METHOD:        "POST",
			USER_CODE:     xtestUser,
			TenantId:      xtestTenant,
			UNIX_ADD_TIME: now.Unix(),
			CREATE_TIME:   now.Format("2006-01-02 15:04:05"),
			HEADER:        "User-Agent: curl", // HEADER 本次不搬，仍在窄行上
		}).Error)
		must(t, logdb.Create(&model.EventPayload{
			ReqUUID:     uid,
			TenantId:    xtestTenant,
			UserCode:    xtestUser,
			HostCode:    "h1",
			Kind:        "event",
			BODY:        "user=admin&pwd=1",
			RES_BODY:    "<html>ok</html>",
			POST_FORM:   "user=admin&pwd=1",
			COOKIES:     "sid=abc",
			ResHeader:   "Content-Type: text/html",
			Truncated:   1,
			CreateTime:  now.Format("2006-01-02 15:04:05"),
			UnixAddTime: now.Unix(),
			Day:         20260918,
		}).Error)

		got, err := WafLogServiceApp.GetDetailApi(req.WafAttackLogDetailReq{REQ_UUID: uid})
		fatalIf(t, err)
		if got.BODY != "user=admin&pwd=1" {
			t.Fatalf("BODY 没从报文表补回来: %q", got.BODY)
		}
		if got.RES_BODY != "<html>ok</html>" || got.COOKIES != "sid=abc" || got.ResHeader != "Content-Type: text/html" {
			t.Fatalf("报文补得不全: %+v", got)
		}
		if got.HEADER != "User-Agent: curl" {
			t.Fatalf("HEADER 留在窄行上，不该被报文行的空值抹掉: %q", got.HEADER)
		}
		if got.Truncated != 1 {
			t.Fatal("截断标记应跟着报文一起回来")
		}
	})

	// 存量数据：报文还在 web_logs 自己的列里，没有对应的报文行，详情必须照旧能看
	t.Run("改造前的存量行仍读原列", func(t *testing.T) {
		uid := "req_legacy_" + sfx()
		must(t, logdb.Create(&innerbean.WebLog{
			REQ_UUID:      uid,
			HOST_CODE:     "h1",
			URL:           "/old",
			USER_CODE:     xtestUser,
			TenantId:      xtestTenant,
			UNIX_ADD_TIME: now.Unix(),
			CREATE_TIME:   now.Format("2006-01-02 15:04:05"),
			BODY:          "legacy-body",
			RES_BODY:      "legacy-res",
			COOKIES:       "legacy-cookie",
		}).Error)

		got, err := WafLogServiceApp.GetDetailApi(req.WafAttackLogDetailReq{REQ_UUID: uid})
		fatalIf(t, err)
		if got.BODY != "legacy-body" || got.RES_BODY != "legacy-res" || got.COOKIES != "legacy-cookie" {
			t.Fatalf("存量行的报文被抹掉了: %+v", got)
		}
	})

	// 保留期清理要把报文一起删掉，否则报文表只增不减
	t.Run("保留期清理连报文一起删", func(t *testing.T) {
		uid := "req_expire_" + sfx()
		old := now.AddDate(0, 0, -30).Format("2006-01-02 15:04:05")
		must(t, logdb.Create(&innerbean.WebLog{
			REQ_UUID: uid, HOST_CODE: "h1", USER_CODE: xtestUser, TenantId: xtestTenant,
			UNIX_ADD_TIME: now.AddDate(0, 0, -30).Unix(), CREATE_TIME: old,
		}).Error)
		must(t, logdb.Create(&model.EventPayload{
			ReqUUID: uid, TenantId: xtestTenant, UserCode: xtestUser,
			Kind: "event", BODY: "expired", CreateTime: old,
		}).Error)

		WafLogServiceApp.DeleteHistory(now.AddDate(0, 0, -1).Format("2006-01-02 15:04"))

		if n := countBy(t, logdb, &model.EventPayload{}, "req_uuid = ?", uid); n != 0 {
			t.Fatalf("过期报文没被清掉，还剩 %d 行", n)
		}
	})
}
