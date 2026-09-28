//go:build crossdb

// SQLite 历史分区：只读打开、按数据选层、缺失标注。
//
// 分层改造边界切出来的分片（以及被旧版打开过、跑过迁移的归档）同时有 web_logs 数据与空的新表，
// 按「表在不在」选层会读到空表——下拉里标着有数据、选中却一条都查不到。
// 分片登记还在而文件已不在时，要标出来，不能在原位置建出空库，也不能回落到实时库。
package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafdb/partition"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
)

func runSQLiteArchiveCases(t *testing.T, core, logdb *gorm.DB) {
	if !dialect.Get().IsFileBased() {
		t.Skip("只针对文件型分区")
	}
	t.Setenv("SamWafIDE", "1") // 让 utils.GetCurrentDir() 返回 "."，归档文件落到临时目录的 data/ 下
	t.Chdir(t.TempDir())
	must(t, os.MkdirAll("data", 0o755))

	now := time.Now()
	midAt := now.AddDate(0, -1, 0)
	oldAt := now.AddDate(0, -2, 0)
	keyMid, keyOld := partition.KeyOf(midAt), partition.KeyOf(oldAt)
	if keyMid == keyOld {
		t.Skip("跨月边界导致周期键相同，跳过")
	}
	tag := sfx()
	hostCode := "arch_" + tag
	polluted := "local_log_" + keyMid + ".db"
	missing := "local_log_" + keyOld + ".db"

	// 被污染的归档：web_logs 3 行（其中 1 行是拦截），新三表存在但为空
	path := filepath.Join("data", polluted)
	adb, err := gorm.Open(sqlitedriver.Open(path+"?_db_key="+url.QueryEscape(global.GWAF_PWD_LOGDB)), silentCfg)
	fatalIf(t, err)
	fatalIf(t, adb.AutoMigrate(&innerbean.WebLog{}, &model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}))
	for i := 0; i < 3; i++ {
		at := midAt.Add(-time.Duration(i+1) * time.Minute)
		action, rule := "放行", ""
		if i == 0 {
			action, rule = "阻止", "sqli"
		}
		fatalIf(t, adb.Create(&innerbean.WebLog{
			REQ_UUID: fmt.Sprintf("arch_%s_%d", tag, i), TenantId: xtestTenant, USER_CODE: xtestUser,
			HOST_CODE: hostCode, ACTION: action, RULE: rule, SRC_IP: "203.0.113.9",
			UNIX_ADD_TIME: at.UnixMilli(), CREATE_TIME: at.Format("2006-01-02 15:04:05"),
			Day: at.Year()*10000 + int(at.Month())*100 + at.Day(),
		}).Error)
	}
	if s, e := adb.DB(); e == nil {
		_ = s.Close()
	}
	before, err := os.Stat(path)
	fatalIf(t, err)

	register := func(name string, at time.Time, cnt int64) {
		must(t, core.Create(&model.ShareDb{
			BaseOrm: baseorm.BaseOrm{
				Id: "arch_" + tag + "_" + name, USER_CODE: xtestUser, Tenant_ID: xtestTenant,
				CREATE_TIME: customtype.JsonTime(now), UPDATE_TIME: customtype.JsonTime(now),
			},
			DbLogicType: "log",
			StartTime:   customtype.JsonTime(at.AddDate(0, 0, -1)),
			EndTime:     customtype.JsonTime(at.AddDate(0, 0, 1)),
			FileName:    name,
			PeriodKey:   partition.KeyOf(at),
			Cnt:         cnt,
		}).Error)
	}
	register(polluted, midAt, 3)
	register(missing, oldAt, 5)
	InvalidateShardCounts()
	defer func() {
		wafdb.CloseManualLogDb(polluted)
		core.Where("id like ?", "arch_"+tag+"%").Delete(&model.ShareDb{})
		InvalidateShardCounts()
	}()

	req := func(shard, view string) request.WafAttackLogSearch {
		r := request.WafAttackLogSearch{}
		r.PageIndex, r.PageSize = 1, 10
		r.SortBy, r.SortDescending = "unix_add_time", "desc"
		r.HostCode = hostCode
		r.CurrrentDbName = shard
		r.ViewType = view
		r.UnixAddTimeBegin = fmt.Sprint(now.AddDate(0, -3, 0).UnixMilli())
		r.UnixAddTimeEnd = fmt.Sprint(now.Add(time.Hour).UnixMilli())
		return r
	}

	t.Run("被污染的归档按 web_logs 读", func(t *testing.T) {
		rows, total, _, err := WafLogServiceApp.GetListApiWithMeta(req(polluted, "access"))
		fatalIf(t, err)
		if total != 3 || len(rows) != 3 {
			t.Fatalf("访问日志视图应读到 3 行，实际 total=%d rows=%d", total, len(rows))
		}
		_, total, _, err = WafLogServiceApp.GetListApiWithMeta(req(polluted, "event"))
		fatalIf(t, err)
		if total != 1 {
			t.Fatalf("安全事件视图应读到 1 行拦截，实际 %d", total)
		}
	})

	t.Run("自动扇出跳过缺失分区并标出", func(t *testing.T) {
		rows, total, meta, err := WafLogServiceApp.GetListApiWithMeta(req(AutoShard, "access"))
		fatalIf(t, err)
		if total != 3 || len(rows) != 3 {
			t.Fatalf("应只读到被污染归档里的 3 行，实际 total=%d rows=%d", total, len(rows))
		}
		var got *LogShardIssue
		for i := range meta.Issues {
			if meta.Issues[i].Name == missing {
				got = &meta.Issues[i]
			}
		}
		if got == nil || got.Kind != ShardIssueMissing || got.Registered != 5 {
			t.Fatalf("缺失分区应以 missing 标出且带登记条数 5，实际 %+v", meta.Issues)
		}
		if _, err := os.Stat(filepath.Join("data", missing)); !os.IsNotExist(err) {
			t.Fatal("查询缺失分区时在原位置建出了文件")
		}
	})

	t.Run("明确选中缺失分区给出说明", func(t *testing.T) {
		_, _, meta, err := WafLogServiceApp.GetListApiWithMeta(req(missing, "access"))
		if err == nil || !strings.Contains(err.Error(), "已不存在") {
			t.Fatalf("应报存储已不存在，实际 %v", err)
		}
		if len(meta.Issues) != 1 || meta.Issues[0].Kind != ShardIssueMissing {
			t.Fatalf("应带一条 missing 问题，实际 %+v", meta.Issues)
		}
	})

	t.Run("列表标出缺失", func(t *testing.T) {
		list, err := WafShareDbServiceApp.GetAllShareDbWithTiers()
		fatalIf(t, err)
		seen := map[string]bool{}
		for _, s := range list {
			if s.FileName == polluted || s.FileName == missing {
				seen[s.FileName] = s.Missing
			}
		}
		if len(seen) != 2 || seen[polluted] || !seen[missing] {
			t.Fatalf("应只有缺失的那一个标 missing，实际 %+v", seen)
		}
	})

	t.Run("归档文件未被改动", func(t *testing.T) {
		wafdb.CloseManualLogDb(polluted)
		after, err := os.Stat(path)
		fatalIf(t, err)
		if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			t.Fatalf("归档文件被改动：%d/%v → %d/%v", before.Size(), before.ModTime(), after.Size(), after.ModTime())
		}
	})
}
