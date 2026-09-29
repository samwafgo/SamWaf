//go:build crossdb

// log 库三库回归：验证 log 库写入 + 列表查询（含时间范围、ForceIndex、LIKE 等方言 SQL）
// 在 SQLite/MySQL/PostgreSQL 上都能跑通且数据正确。由 TestCrossEngine 每引擎调一次。
package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/common/request"
	req "SamWaf/model/request"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"
)

func runLogCases(t *testing.T, logdb *gorm.DB) {
	// WebLog：走 WafLogServiceApp.AddApi（TASK_FLAG 默认 -1，曾按值 Create 有 #885 类崩溃风险）
	t.Run("WebLog", func(t *testing.T) {
		uid := "req_" + sfx()
		now := time.Now().Unix()
		wl := innerbean.WebLog{
			REQ_UUID:      uid,
			HOST:          "a.com",
			HOST_CODE:     "h1",
			URL:           "/x",
			METHOD:        "GET",
			SRC_IP:        "1.2.3.4",
			ACTION:        "deny",
			RULE:          "testrule",
			STATUS_CODE:   200,
			USER_CODE:     xtestUser,
			TenantId:      xtestTenant,
			UNIX_ADD_TIME: now,
			CREATE_TIME:   time.Now().Format("2006-01-02 15:04:05"),
			// TASK_FLAG 留 0（默认 -1）：验证按值 Create 修复后不崩、且默认值正确落库
		}
		fatalIf(t, WafLogServiceApp.AddApi(wl))

		// 直接读库确认 TASK_FLAG 落为默认 -1（回写默认值路径工作正常，未 panic）
		var got innerbean.WebLog
		firstBy(t, logdb, &got, "req_uuid = ?", uid)
		if got.TASK_FLAG != -1 {
			t.Fatalf("WebLog TASK_FLAG 期望默认 -1，实际 %d", got.TASK_FLAG)
		}

		// 分层后的列表查询：访问日志视图读 access_log、安全事件视图读 security_event，
		// 「请求」全文筛选只在事件视图可用（走报文子查询），访问视图应明确拒绝
		nowMs := time.Now().UnixNano() / 1e6
		nowStr := time.Now().Format("2006-01-02 15:04:05")
		must(t, logdb.Create(&model.AccessLog{LogNarrow: model.LogNarrow{
			ReqUUID: uid, HostCode: "h1", URL: "/x", Method: "GET", SRC_IP: "1.2.3.4",
			ACTION: "deny", RULE: "testrule", USER_AGENT: "crossdb-probe", UserCode: xtestUser, TenantId: xtestTenant,
			UNIX_ADD_TIME: nowMs, CREATE_TIME: nowStr, Day: 20260918,
		}}).Error)
		must(t, logdb.Create(&model.SecurityEvent{LogNarrow: model.LogNarrow{
			ReqUUID: uid, HostCode: "h1", URL: "/x", Method: "GET", SRC_IP: "1.2.3.4",
			ACTION: "deny", RULE: "testrule", USER_AGENT: "crossdb-probe", UserCode: xtestUser, TenantId: xtestTenant,
			UNIX_ADD_TIME: nowMs, CREATE_TIME: nowStr, Day: 20260918,
		}}).Error)
		must(t, logdb.Create(&model.EventPayload{
			ReqUUID: uid, TenantId: xtestTenant, UserCode: xtestUser, HostCode: "h1",
			Kind: "event", HEADER: "User-Agent: crossdb-probe",
			CreateTime: nowStr, UnixAddTime: nowMs, Day: 20260918,
		}).Error)

		base := req.WafAttackLogSearch{
			ReqUuid:          uid,
			UnixAddTimeBegin: "0",
			UnixAddTimeEnd:   fmt.Sprintf("%d", nowMs+3600000),
			SortBy:           "unix_add_time",
			SortDescending:   "desc",
			PageInfo:         request.PageInfo{PageIndex: 1, PageSize: 20},
		}

		// 访问日志视图（默认）：按 req_uuid 查到窄行
		list, total, err := WafLogServiceApp.GetListApi(base)
		fatalIf(t, err)
		if total < 1 || len(list) < 1 {
			t.Fatalf("访问日志视图未查到刚写入的窄行: total=%d len=%d", total, len(list))
		}

		// 安全事件视图：同一 req_uuid 也查得到（事件双写），且报文被补回
		evReq := base
		evReq.ViewType = "event"
		evList, evTotal, err := WafLogServiceApp.GetListApi(evReq)
		fatalIf(t, err)
		if evTotal < 1 || len(evList) < 1 {
			t.Fatalf("安全事件视图未查到刚写入的事件: total=%d len=%d", evTotal, len(evList))
		}
		if evList[0].HEADER != "User-Agent: crossdb-probe" {
			t.Fatalf("事件视图应按页补回报文，实际 header=%q", evList[0].HEADER)
		}

		// 「请求」全文筛选：事件视图走报文子查询命中，访问视图明确拒绝
		hdrReq := base
		hdrReq.ViewType = "event"
		hdrReq.FilterBy = "header"
		hdrReq.FilterValue = "crossdb-probe"
		_, hdrTotal, err := WafLogServiceApp.GetListApi(hdrReq)
		fatalIf(t, err)
		if hdrTotal < 1 {
			t.Fatal("事件视图的 header 全文筛选应命中报文子查询")
		}
		accHdr := base
		accHdr.FilterBy = "header"
		accHdr.FilterValue = "crossdb-probe"
		if _, _, err = WafLogServiceApp.GetListApi(accHdr); err == nil {
			t.Fatal("访问日志视图的 header 全文筛选应被拒绝（窄行没有这一列）")
		}

		// UA 筛选两个视图都可用（窄行列），访问视图应命中刚写的窄行
		uaReq := base
		uaReq.FilterBy = "user_agent"
		uaReq.FilterValue = "crossdb-probe"
		_, uaTotal, err := WafLogServiceApp.GetListApi(uaReq)
		fatalIf(t, err)
		if uaTotal < 1 {
			t.Fatal("访问视图的 UA 筛选应命中窄行")
		}
	})

	// SysLog：只读 service，直接种子后走 GetListApi（op_content LIKE 过滤）
	t.Run("SysLog", func(t *testing.T) {
		oc := "sys_" + sfx()
		must(t, logdb.Create(&model.WafSysLog{BaseOrm: newBase(uuid.GenUUID()), OpType: "test", OpContent: oc}).Error)
		list, total, err := WafSysLogServiceApp.GetListApi(req.WafSysLogSearchReq{
			OpContent: oc, PageInfo: request.PageInfo{PageIndex: 1, PageSize: 20},
		})
		fatalIf(t, err)
		if total < 1 || len(list) < 1 {
			t.Fatalf("SysLog 列表未查到种子日志: total=%d", total)
		}
	})

	// OPlatformLog：AddLog 写入 + GetListApi（key_name 过滤）
	t.Run("OPlatformLog", func(t *testing.T) {
		kn := "opl_" + sfx()
		fatalIf(t, WafOPlatformLogServiceApp.AddLog(model.OPlatformLog{
			BaseOrm: newBase(uuid.GenUUID()), KeyName: kn, RequestPath: "/api", RequestMethod: "GET", ClientIP: "1.2.3.4", StatusCode: 200,
		}))
		list, total, err := WafOPlatformLogServiceApp.GetListApi(req.WafOPlatformLogSearchReq{
			KeyName: kn, PageInfo: request.PageInfo{PageIndex: 1, PageSize: 20},
		})
		fatalIf(t, err)
		if total < 1 || len(list) < 1 {
			t.Fatalf("OPlatformLog 列表未查到: total=%d", total)
		}
	})

	// NotifyLog：AddLog（裸参数）写入 + GetListApi（channel_id 过滤）
	t.Run("NotifyLog", func(t *testing.T) {
		ch := "nl_" + sfx()
		fatalIf(t, WafNotifyLogServiceApp.AddLog(ch, "chanName", "dingtalk", "attack", "title", "content", "a@b.com", 1, ""))
		list, total, err := WafNotifyLogServiceApp.GetListApi(req.WafNotifyLogSearchReq{
			ChannelId: ch, PageIndex: 1, PageSize: 20,
		})
		fatalIf(t, err)
		if total < 1 || len(list) < 1 {
			t.Fatalf("NotifyLog 列表未查到: total=%d", total)
		}
	})
}
