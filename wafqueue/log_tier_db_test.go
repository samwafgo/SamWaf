//go:build crossdb

// 分层写入的三库回归。tierForStore 的纯逻辑由 log_tier_test.go 覆盖，
// 这里盯的是真正压到数据库上的写入：三张新表都以 req_uuid 为主键、
// 整批 OnConflict DoNothing 的写法三个引擎各不相同（sqlite/pg=DO NOTHING，mysql=INSERT IGNORE），
// 写错了一撞主键整批消失。
//
//	go test -tags crossdb ./wafqueue/ -run TestStoreTieredCrossEngine -v
package wafqueue

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"testing"
)

func TestStoreTieredCrossEngine(t *testing.T) {
	zlog.InitZLog(false, "console")
	savedDB := global.GWAF_LOCAL_LOG_DB
	savedMode := global.GDATA_ACCESS_LOG_MODE
	savedSampler := negSampler
	defer func() {
		global.GWAF_LOCAL_LOG_DB = savedDB
		global.GDATA_ACCESS_LOG_MODE = savedMode
		negSampler = savedSampler
	}()

	for _, e := range payloadEngines() {
		e := e
		t.Run(e.name, func(t *testing.T) {
			db, teardown := e.setup(t)
			if db == nil {
				t.Skipf("%s 未就绪，跳过", e.name)
				return
			}
			defer teardown()
			if err := db.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}); err != nil {
				t.Fatalf("建分层表失败: %v", err)
			}
			global.GWAF_LOCAL_LOG_DB = db
			global.GDATA_ACCESS_LOG_MODE = "db"
			negSampler = &sampleReservoir{buckets: map[string]*sampleBucket{}}

			mk := func(uid, ip, action, rule string) *innerbean.WebLog {
				return &innerbean.WebLog{
					REQ_UUID: uid, HOST_CODE: "h1", SRC_IP: ip, URL: "/login",
					METHOD: "POST", ACTION: action, RULE: rule,
					USER_CODE: "u", TenantId: "t",
					CREATE_TIME: "2026-09-18 10:00:00", UNIX_ADD_TIME: 1, Day: 20260918,
					HEADER: "User-Agent: curl", BODY: "a=1", RES_BODY: "ok",
				}
			}

			// 事件 + 正常各一：事件三层全进（报文 kind=event、HEADER 随报文走），正常只有窄行
			storeTiered([]*innerbean.WebLog{mk("te1", "1.2.3.4", "阻止", "SQLi"), mk("tn1", "1.2.3.4", "放行", "")})

			var nEvent, nAccess, nPayload int64
			db.Model(&model.SecurityEvent{}).Count(&nEvent)
			db.Model(&model.AccessLog{}).Count(&nAccess)
			db.Model(&model.EventPayload{}).Count(&nPayload)
			if nEvent != 1 || nAccess != 2 || nPayload != 1 {
				t.Fatalf("分层计数不对: event=%d access=%d payload=%d（期望 1/2/1）", nEvent, nAccess, nPayload)
			}
			var ev model.SecurityEvent
			db.Where("req_uuid = ?", "te1").First(&ev)
			if ev.ActorKey != "ip:1.2.3.4" || ev.PathNorm != "/login" || ev.PayloadHash == "" {
				t.Fatalf("事件行的分析键没算好: %+v", ev.LogNarrow)
			}
			var p model.EventPayload
			db.Where("req_uuid = ?", "te1").First(&p)
			if p.Kind != PayloadKindEvent || p.HEADER != "User-Agent: curl" {
				t.Fatalf("事件报文不对: kind=%q header=%q", p.Kind, p.HEADER)
			}

			// 同一请求分两批入队：撞主键必须跳过冲突行而不是整批失败
			storeTiered([]*innerbean.WebLog{mk("te1", "1.2.3.4", "阻止", "SQLi"), mk("tn2", "5.6.7.8", "放行", "")})
			db.Model(&model.SecurityEvent{}).Count(&nEvent)
			db.Model(&model.AccessLog{}).Count(&nAccess)
			db.Model(&model.EventPayload{}).Count(&nPayload)
			if nEvent != 1 || nAccess != 3 || nPayload != 1 {
				t.Fatalf("重复入队后计数不对: event=%d access=%d payload=%d（期望 1/3/1）", nEvent, nAccess, nPayload)
			}

			// off 档：正常请求三层都不留，事件照留
			global.GDATA_ACCESS_LOG_MODE = "off"
			storeTiered([]*innerbean.WebLog{mk("to1", "9.9.9.9", "放行", "")})
			var offAccess int64
			db.Model(&model.AccessLog{}).Where("req_uuid = ?", "to1").Count(&offAccess)
			if offAccess != 0 {
				t.Fatalf("off 档正常请求不应有窄行，实际 %d", offAccess)
			}
			global.GDATA_ACCESS_LOG_MODE = "db"
		})
	}
}
