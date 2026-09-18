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
		// 分层行：安全事件随长保留期删；访问窄行按 accessDay 删（更短）；
		// 采样报文 30 天、观察名单报文 7 天
		must(t, logdb.Create(&model.SecurityEvent{LogNarrow: model.LogNarrow{
			ReqUUID: uid + "_se", UserCode: xtestUser, TenantId: xtestTenant,
			UNIX_ADD_TIME: now.AddDate(0, 0, -30).Unix(), CREATE_TIME: old,
		}}).Error)
		must(t, logdb.Create(&model.AccessLog{LogNarrow: model.LogNarrow{
			ReqUUID: uid + "_al", UserCode: xtestUser, TenantId: xtestTenant,
			UNIX_ADD_TIME: now.AddDate(0, 0, -8).Unix(), CREATE_TIME: now.AddDate(0, 0, -8).Format("2006-01-02 15:04:05"),
		}}).Error)
		must(t, logdb.Create(&model.EventPayload{
			ReqUUID: uid + "_watch", TenantId: xtestTenant, UserCode: xtestUser,
			Kind: "watch", BODY: "expired-watch", CreateTime: now.AddDate(0, 0, -8).Format("2006-01-02 15:04:05"),
		}).Error)
		// 未到期对照组：2 天前的事件报文与访问行都应留下
		must(t, logdb.Create(&model.EventPayload{
			ReqUUID: uid + "_fresh", TenantId: xtestTenant, UserCode: xtestUser,
			Kind: "event", BODY: "fresh", CreateTime: now.AddDate(0, 0, -2).Format("2006-01-02 15:04:05"),
		}).Error)
		must(t, logdb.Create(&model.AccessLog{LogNarrow: model.LogNarrow{
			ReqUUID: uid + "_al2", UserCode: xtestUser, TenantId: xtestTenant,
			UNIX_ADD_TIME: now.AddDate(0, 0, -2).Unix(), CREATE_TIME: now.AddDate(0, 0, -2).Format("2006-01-02 15:04:05"),
		}}).Error)

		// securityDay=4 天前（30 天前的删掉、2 天前的留下）、accessDay=7 天前
		WafLogServiceApp.DeleteHistory(
			now.AddDate(0, 0, -4).Format("2006-01-02 15:04"),
			now.AddDate(0, 0, -7).Format("2006-01-02 15:04"))

		if n := countBy(t, logdb, &model.EventPayload{}, "req_uuid = ?", uid); n != 0 {
			t.Fatalf("过期报文没被清掉，还剩 %d 行", n)
		}
		if n := countBy(t, logdb, &model.SecurityEvent{}, "req_uuid = ?", uid+"_se"); n != 0 {
			t.Fatalf("过期安全事件没被清掉，还剩 %d 行", n)
		}
		if n := countBy(t, logdb, &model.AccessLog{}, "req_uuid = ?", uid+"_al"); n != 0 {
			t.Fatalf("超过访问日志保留期的窄行没被清掉，还剩 %d 行", n)
		}
		if n := countBy(t, logdb, &model.EventPayload{}, "req_uuid = ?", uid+"_watch"); n != 0 {
			t.Fatalf("超过 7 天的观察名单报文没被清掉，还剩 %d 行", n)
		}
		if n := countBy(t, logdb, &model.EventPayload{}, "req_uuid = ?", uid+"_fresh"); n != 1 {
			t.Fatalf("未到期报文被误删了")
		}
		if n := countBy(t, logdb, &model.AccessLog{}, "req_uuid = ?", uid+"_al2"); n != 1 {
			t.Fatalf("未到期访问行被误删了")
		}
	})
}
