package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestLogURLKeywordQueries(t *testing.T) {
	core, live, root := setupLogLookupTest(t)
	if err := os.Mkdir(filepath.Join(root, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	urls := []string{"/api/a_b%20!x|z?q=hello", "/api/aXbZ20!x|z?q=hello", "/other?name=hello world"}
	at := time.Date(2020, 3, 10, 12, 0, 0, 0, time.Local)
	seed := func(db *gorm.DB, prefix string, when time.Time, legacy bool) {
		t.Helper()
		for i, url := range urls {
			narrow := model.LogNarrow{
				ReqUUID: prefix + strconv.Itoa(i), TenantId: global.GWAF_TENANT_ID, UserCode: global.GWAF_USER_CODE,
				HostCode: "url-host", URL: url, SRC_IP: "203.0.113.8", Method: "GET", USER_AGENT: "url-agent",
				ACTION: "阻止", RULE: "url-rule", UNIX_ADD_TIME: when.Add(time.Duration(i) * time.Second).UnixMilli(),
				CREATE_TIME: when.Format("2006-01-02 15:04:05"),
			}
			if legacy {
				row := innerbean.WebLog{
					REQ_UUID: narrow.ReqUUID, TenantId: narrow.TenantId, USER_CODE: narrow.UserCode,
					HOST_CODE: narrow.HostCode, URL: url, SRC_IP: narrow.SRC_IP, METHOD: narrow.Method,
					ACTION: narrow.ACTION, RULE: narrow.RULE, USER_AGENT: narrow.USER_AGENT,
					UNIX_ADD_TIME: narrow.UNIX_ADD_TIME, CREATE_TIME: narrow.CREATE_TIME,
				}
				if err := db.Create(&row).Error; err != nil {
					t.Fatal(err)
				}
			} else {
				for _, row := range []interface{}{&model.AccessLog{LogNarrow: narrow}, &model.SecurityEvent{LogNarrow: narrow}} {
					if err := db.Create(row).Error; err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
	seed(live, "live-url-", at, false)
	shards := []string{wafdb.LiveLogName()}
	for i, legacy := range []bool{true, false} {
		name := fmt.Sprintf("local_log_20200%d.db", i+1)
		db, err := gorm.Open(sqlite.Open(filepath.Join(root, "data", name)), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err != nil {
			t.Fatal(err)
		}
		sqlDB, _ := db.DB()
		t.Cleanup(func() { _ = sqlDB.Close() })
		if legacy {
			err = db.AutoMigrate(&innerbean.WebLog{})
		} else {
			err = db.AutoMigrate(&model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{})
		}
		if err != nil {
			t.Fatal(err)
		}
		when := at.AddDate(0, i-2, 0)
		seed(db, name+"-", when, legacy)
		if err = core.Create(&model.ShareDb{
			BaseOrm:     baseorm.BaseOrm{Id: name, Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE},
			DbLogicType: "log", FileName: name, Cnt: 3,
			StartTime: customtype.JsonTime(when.Add(-time.Hour)), EndTime: customtype.JsonTime(when.Add(time.Hour)),
		}).Error; err != nil {
			t.Fatal(err)
		}
		if err = wafdb.InitManaulLogDb(root, name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { wafdb.CloseManualLogDb(name) })
		shards = append(shards, name)
	}
	base := request.WafAttackLogSearch{
		HostCode: "url-host", UnixAddTimeBegin: "0", UnixAddTimeEnd: strconv.FormatInt(at.Add(time.Hour).UnixMilli(), 10),
		SortBy: "unix_add_time", SortDescending: "desc",
	}
	base.PageIndex, base.PageSize = 1, 20
	for _, shard := range append(shards, AutoShard) {
		for _, view := range []string{"access", "event"} {
			for _, tc := range []struct {
				keyword string
				want    int64
			}{
				{"", 3}, {"/api/", 2}, {"a_b", 1}, {"%20", 1}, {"!x|z?q=", 2}, {"|z?q=", 2},
				{"hello world", 1}, {" ", 1}, {"missing", 0}, {"' OR 1=1 --", 0}, {"https://example.test/api", 0},
			} {
				t.Run(shard+"/"+view+"/"+tc.keyword, func(t *testing.T) {
					req := base
					req.CurrrentDbName, req.ViewType, req.URLKeyword = shard, view, tc.keyword
					want := tc.want
					if shard == AutoShard {
						want *= 3
					}
					rows, total, meta, err := WafLogServiceApp.GetListApiWithMeta(req)
					if err != nil || meta.Partial || total != want || int64(len(rows)) != want {
						t.Fatalf("want %d rows, total=%d len=%d meta=%+v err=%v", want, total, len(rows), meta, err)
					}
				})
			}
		}
	}
	t.Run("combination-and-uuid", func(t *testing.T) {
		req := base
		req.CurrrentDbName, req.URLKeyword = AutoShard, "a_b%20!x|z"
		req.SrcIp, req.Method, req.FilterBy, req.FilterValue = "203.0.113.8", "GET", "user_agent", "url-agent"
		rows, total, _, err := WafLogServiceApp.GetListApiWithMeta(req)
		if err != nil || total != 3 || len(rows) != 3 {
			t.Fatalf("combined filters: total=%d len=%d err=%v", total, len(rows), err)
		}
		for _, field := range []string{"host", "ip", "method", "agent"} {
			other := req
			switch field {
			case "host":
				other.HostCode = "other-host"
			case "ip":
				other.SrcIp = "203.0.113.9"
			case "method":
				other.Method = "POST"
			case "agent":
				other.FilterValue = "other-agent"
			}
			rows, total, _, err := WafLogServiceApp.GetListApiWithMeta(other)
			if err != nil || total != 0 || len(rows) != 0 {
				t.Fatalf("URL must retain %s filter: total=%d len=%d err=%v", field, total, len(rows), err)
			}
		}
		for _, id := range []string{"local_log_202001.db-0", "local_log_202002.db-0"} {
			for _, view := range []string{"access", "event"} {
				other := req
				other.ReqUuid, other.ViewType = id, view
				other.UnixAddTimeBegin, other.UnixAddTimeEnd = "4102444800000", "4102531200000"
				rows, total, meta, err := WafLogServiceApp.GetListApiWithMeta(other)
				if err != nil || total != 1 || len(rows) != 1 || !meta.UuidLookup {
					t.Fatalf("archive UUID URL lookup: total=%d len=%d meta=%+v err=%v", total, len(rows), meta, err)
				}
				other.URLKeyword = "missing"
				rows, total, _, err = WafLogServiceApp.GetListApiWithMeta(other)
				if err != nil || total != 0 || len(rows) != 0 {
					t.Fatalf("archive UUID must retain URL filter: total=%d len=%d err=%v", total, len(rows), err)
				}
			}
		}
		req.ReqUuid, req.UnixAddTimeBegin, req.UnixAddTimeEnd = "live-url-0", "4102444800000", "4102531200000"
		rows, total, meta, err := WafLogServiceApp.GetListApiWithMeta(req)
		if err != nil || total != 1 || len(rows) != 1 || !meta.UuidLookup {
			t.Fatalf("UUID combination: total=%d len=%d meta=%+v err=%v", total, len(rows), meta, err)
		}
		req.URLKeyword = "missing"
		rows, total, _, err = WafLogServiceApp.GetListApiWithMeta(req)
		if err != nil || total != 0 || len(rows) != 0 {
			t.Fatalf("UUID must retain URL filter: total=%d len=%d err=%v", total, len(rows), err)
		}
	})
	t.Run("fanout-pagination-and-cached-counts", func(t *testing.T) {
		InvalidateShardCounts()
		req := base
		req.CurrrentDbName, req.URLKeyword, req.PageSize = AutoShard, "/api/", 2
		seen := map[string]bool{}
		for page := 1; page <= 3; page++ {
			req.PageIndex = page
			rows, total, _, err := WafLogServiceApp.GetListApiWithMeta(req)
			if err != nil || total != 6 || len(rows) != 2 {
				t.Fatalf("page=%d total=%d len=%d err=%v", page, total, len(rows), err)
			}
			for _, row := range rows {
				if seen[row.REQ_UUID] {
					t.Fatalf("duplicate row %s", row.REQ_UUID)
				}
				seen[row.REQ_UUID] = true
			}
		}
		if shardCountCacheN.Load() == 0 {
			t.Fatal("archive count cache was not exercised")
		}
		req.PageIndex, req.URLKeyword = 1, "a_b"
		_, total, _, err := WafLogServiceApp.GetListApiWithMeta(req)
		if err != nil || total != 3 {
			t.Fatalf("keyword count cache isolation: total=%d err=%v", total, err)
		}
	})
}
