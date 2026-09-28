//go:build crossdb

// 日志查询的分区扇出与识别码直查（E5）的三库回归。
//
// 这两条路都会「悄悄地错」：扇出翻页算错偏移就是漏行或重复行，用户看不出来；
// 识别码直查要是没忽略时间条件，就会出现「码是对的、却说查不到」。所以必须在真库上按行核对。
// MySQL/PG 的归档分区是同库里的表，建起来就能测；SQLite 的分区是独立文件，
// 这里只验它的实时库那一路（多文件分片由 m3_verify.py 在真实实例上验）。
package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafdb/partition"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"
)

func runLogFanoutCases(t *testing.T, core, logdb *gorm.DB) {
	d := dialect.Get()
	base := model.AccessLogTableName
	now := time.Now()

	// 三段时间，各 3 行；两段进归档分区，一段留在实时表
	keyOld := partition.KeyOf(now.AddDate(0, -2, 0))
	keyMid := partition.KeyOf(now.AddDate(0, -1, 0))
	if keyOld == keyMid {
		t.Skip("跨月边界导致周期键相同，跳过")
	}
	partOld := partition.TableName(base, keyOld)
	partMid := partition.TableName(base, keyMid)
	tag := sfx()
	// 用独一份的站点码把本用例的行圈出来：同一次 crossdb 跑里别的用例也往实时表写 h1 的行
	hostCode := "fanh_" + tag

	mkRow := func(table string, at time.Time, i int) string {
		uid := fmt.Sprintf("fan_%s_%s_%d", tag, at.Format("200601"), i)
		row := model.AccessLog{LogNarrow: model.LogNarrow{
			ReqUUID: uid, TenantId: xtestTenant, UserCode: xtestUser,
			HostCode: hostCode, Host: "fan.test.com", URL: "/p" + fmt.Sprint(i),
			Method: "GET", SRC_IP: "203.0.113.5", ACTION: "放行",
			Day: at.Year()*10000 + int(at.Month())*100 + at.Day(), UNIX_ADD_TIME: at.UnixMilli(),
			CREATE_TIME: at.Format("2006-01-02 15:04:05"),
		}}
		must(t, logdb.Table(table).Create(&row).Error)
		return uid
	}

	cleanup := func() {
		logdb.Table(base).Where("req_uuid like ?", "fan_"+tag+"%").Delete(&model.AccessLog{})
		core.Where("file_name in ?", []string{partOld, partMid}).Delete(&model.ShareDb{})
		if !d.IsFileBased() {
			_ = d.DropPartition(logdb, base, partOld)
			_ = d.DropPartition(logdb, base, partMid)
		}
	}
	cleanup()
	defer cleanup()

	// 实时表里放 3 行（本月）
	var liveUUIDs []string
	for i := 0; i < 3; i++ {
		liveUUIDs = append(liveUUIDs, mkRow(base, now.Add(-time.Duration(i+1)*time.Minute), i))
	}

	multi := !d.IsFileBased()
	var oldestUUID string
	if multi {
		for _, p := range []struct {
			table string
			at    time.Time
		}{{partMid, now.AddDate(0, -1, 0)}, {partOld, now.AddDate(0, -2, 0)}} {
			if err := d.CreatePartition(logdb, base, p.table); err != nil {
				t.Fatalf("建分区 %s 失败: %v", p.table, err)
			}
			for i := 0; i < 3; i++ {
				uid := mkRow(p.table, p.at.Add(-time.Duration(i+1)*time.Minute), i)
				if p.table == partOld {
					oldestUUID = uid
				}
			}
			end := p.at.AddDate(0, 0, 1)
			must(t, core.Create(&model.ShareDb{
				BaseOrm: baseorm.BaseOrm{
					Id: "fanshard_" + tag + "_" + p.table, USER_CODE: xtestUser, Tenant_ID: xtestTenant,
					CREATE_TIME: customtype.JsonTime(time.Now()), UPDATE_TIME: customtype.JsonTime(time.Now()),
				},
				DbLogicType: "log",
				StartTime:   customtype.JsonTime(p.at.AddDate(0, 0, -1)),
				EndTime:     customtype.JsonTime(end),
				FileName:    p.table,
				PeriodKey:   partition.KeyOf(p.at),
				Cnt:         3,
			}).Error)
		}
	}

	baseReq := func() request.WafAttackLogSearch {
		r := request.WafAttackLogSearch{}
		r.PageIndex = 1
		r.PageSize = 10
		r.SortBy = "unix_add_time"
		r.SortDescending = "desc"
		r.HostCode = hostCode
		r.CurrrentDbName = AutoShard
		r.UnixAddTimeBegin = fmt.Sprint(now.AddDate(0, -3, 0).UnixMilli())
		r.UnixAddTimeEnd = fmt.Sprint(now.Add(time.Hour).UnixMilli())
		return r
	}

	t.Run("自动模式按时间范围扇出", func(t *testing.T) {
		rows, total, meta, err := WafLogServiceApp.GetListApiWithMeta(baseReq())
		fatalIf(t, err)
		want := int64(3)
		if multi {
			want = 9
		}
		if total != want {
			t.Fatalf("总数应为 %d（三段各 3 行），实际 %d；覆盖分区 %+v", want, total, meta.Shards)
		}
		if int64(len(rows)) != want {
			t.Fatalf("一页取 10 条应全部返回 %d 行，实际 %d 行", want, len(rows))
		}
		// 时间必须整体倒序：跨分区拼接如果顺序错了，用户看到的就是乱序
		for i := 1; i < len(rows); i++ {
			if rows[i-1].UNIX_ADD_TIME < rows[i].UNIX_ADD_TIME {
				t.Fatalf("第 %d 行比前一行更新，跨分区顺序错了", i)
			}
		}
		if multi && len(meta.Shards) != 3 {
			t.Fatalf("应覆盖 3 个分区，实际 %+v", meta.Shards)
		}
		// 每行都要带上来源分区：界面靠它标注，详情链接靠它直达
		for i, r := range rows {
			if r.ShardName == "" {
				t.Fatalf("第 %d 行没带来源分区", i)
			}
		}
	})

	if multi {
		t.Run("跨分区翻页不漏不重", func(t *testing.T) {
			seen := map[string]int{}
			var order []string
			for page := 1; page <= 5; page++ {
				req := baseReq()
				req.PageSize = 2
				req.PageIndex = page
				rows, total, _, err := WafLogServiceApp.GetListApiWithMeta(req)
				fatalIf(t, err)
				if total != 9 {
					t.Fatalf("每页返回的总数都应是 9，第 %d 页拿到 %d", page, total)
				}
				for _, r := range rows {
					seen[r.REQ_UUID]++
					order = append(order, r.REQ_UUID)
				}
			}
			if len(order) != 9 {
				t.Fatalf("2 条一页翻 5 页应正好取完 9 行，实际 %d 行", len(order))
			}
			for uid, n := range seen {
				if n != 1 {
					t.Fatalf("%s 出现了 %d 次：跨分区偏移算错会重复或漏行", uid, n)
				}
			}
		})

		t.Run("时间范围只落在旧分区时不查实时", func(t *testing.T) {
			req := baseReq()
			at := now.AddDate(0, -2, 0)
			req.UnixAddTimeBegin = fmt.Sprint(at.AddDate(0, 0, -2).UnixMilli())
			req.UnixAddTimeEnd = fmt.Sprint(at.AddDate(0, 0, 1).UnixMilli())
			_, total, meta, err := WafLogServiceApp.GetListApiWithMeta(req)
			fatalIf(t, err)
			if total != 3 {
				t.Fatalf("只该命中最老那段的 3 行，实际 %d（覆盖 %+v）", total, meta.Shards)
			}
		})
	}

	t.Run("重复查询走计数缓存且实时分区不被缓存", func(t *testing.T) {
		_, first, _, err := WafLogServiceApp.GetListApiWithMeta(baseReq())
		fatalIf(t, err)
		_, second, meta, err := WafLogServiceApp.GetListApiWithMeta(baseReq())
		fatalIf(t, err)
		if first != second {
			t.Fatalf("同样的查询两次总数不一致：%d vs %d", first, second)
		}
		if meta.Partial {
			t.Fatal("这点数据量不该触发预算超时")
		}
		// 实时分区的计数绝不能被缓存：新写进来的行必须立刻算得进去
		extra := mkRow(base, now, 99)
		defer logdb.Table(base).Where("req_uuid = ?", extra).Delete(&model.AccessLog{})
		_, third, _, err := WafLogServiceApp.GetListApiWithMeta(baseReq())
		fatalIf(t, err)
		if third != second+1 {
			t.Fatalf("实时分区新增一行后总数应 +1（%d → %d），实时分区被缓存了？", second, third)
		}
	})

	t.Run("识别码直查忽略时间与分区", func(t *testing.T) {
		target := liveUUIDs[0]
		if multi {
			target = oldestUUID // 最老的那个分区，离默认时间范围最远
		}
		req := baseReq()
		req.ReqUuid = target
		// 故意把时间范围设成「今天以后」，证明识别码直查压根不看时间
		req.UnixAddTimeBegin = fmt.Sprint(now.AddDate(0, 0, 1).UnixMilli())
		req.UnixAddTimeEnd = fmt.Sprint(now.AddDate(0, 0, 2).UnixMilli())
		rows, total, meta, err := WafLogServiceApp.GetListApiWithMeta(req)
		fatalIf(t, err)
		if !meta.UuidLookup {
			t.Fatal("填了识别码就该走直查")
		}
		if total != 1 || len(rows) != 1 || rows[0].REQ_UUID != target {
			t.Fatalf("应正好查到 %s，实际 total=%d rows=%d", target, total, len(rows))
		}
		if meta.FoundIn == "" {
			t.Fatal("命中之后要告诉前端是在哪个分区找到的")
		}
		if meta.Scanned < 1 {
			t.Fatal("翻过的分区数要记下来，查不到时界面要用它说明")
		}
	})

	t.Run("识别码查不到不是错误", func(t *testing.T) {
		req := baseReq()
		req.ReqUuid = "fan_" + tag + "_not_exist"
		rows, total, meta, err := WafLogServiceApp.GetListApiWithMeta(req)
		fatalIf(t, err)
		if total != 0 || len(rows) != 0 {
			t.Fatalf("不存在的识别码应返回空，实际 total=%d rows=%d", total, len(rows))
		}
		if !meta.UuidLookup || meta.FoundIn != "" {
			t.Fatalf("没找到时 found_in 必须为空，实际 %+v", meta)
		}
	})

	t.Run("指定分区时只查它", func(t *testing.T) {
		req := baseReq()
		req.CurrrentDbName = "" // 空 = 实时库
		_, total, meta, err := WafLogServiceApp.GetListApiWithMeta(req)
		fatalIf(t, err)
		if total != 3 {
			t.Fatalf("实时库里只有 3 行，实际 %d", total)
		}
		if len(meta.Shards) != 1 {
			t.Fatalf("锁定单分区时覆盖信息应只有一条，实际 %+v", meta.Shards)
		}
	})

	if multi {
		t.Run("详情按识别码自动定位分区", func(t *testing.T) {
			got, err := WafLogServiceApp.GetDetailApi(request.WafAttackLogDetailReq{REQ_UUID: oldestUUID})
			fatalIf(t, err)
			if got.REQ_UUID != oldestUUID {
				t.Fatalf("没给分区标识时详情也该找得到归档里的记录，实际 %q", got.REQ_UUID)
			}
			if got.ShardName == "" {
				t.Fatal("详情要告诉界面这条记录在哪个分区")
			}
		})
	}

	if multi {
		t.Run("主动删除分区", func(t *testing.T) {
			// 用一个专属周期，别动上面几个用例赖以断言的分区
			key := partition.KeyOf(now.AddDate(0, -4, 0))
			name := partition.TableName(base, key)
			tiers := []string{model.AccessLogTableName, model.SecurityEventTableName, model.EventPayloadTableName}
			for _, b := range tiers {
				fatalIf(t, d.CreatePartition(logdb, b, partition.TableName(b, key)))
			}
			must(t, core.Create(&model.ShareDb{
				BaseOrm: baseorm.BaseOrm{
					Id: "delshard_" + tag + "_" + key, USER_CODE: xtestUser, Tenant_ID: xtestTenant,
					CREATE_TIME: customtype.JsonTime(time.Now()), UPDATE_TIME: customtype.JsonTime(time.Now()),
				},
				DbLogicType: "log", FileName: name, PeriodKey: key, Cnt: 0,
				StartTime: customtype.JsonTime(now.AddDate(0, -4, -1)),
				EndTime:   customtype.JsonTime(now.AddDate(0, -4, 1)),
			}).Error)
			defer core.Where("file_name = ?", name).Delete(&model.ShareDb{})

			// 列表要标出这个分区现存哪些层
			infos, err := WafShareDbServiceApp.GetAllShareDbWithTiers()
			fatalIf(t, err)
			found := false
			for _, it := range infos {
				if it.FileName == name {
					found = true
					if len(it.Tiers) != len(tiers) {
						t.Fatalf("应标出 %d 层，实际 %+v", len(tiers), it.Tiers)
					}
				}
			}
			if !found {
				t.Fatal("分片列表里找不到刚建的分区")
			}

			// 实时库与不存在的名字都必须被拒绝——这是不可逆动作，入口要收窄
			if _, err := WafShareDbServiceApp.ForceDeleteShard(wafdb.LiveLogName()); err == nil {
				t.Error("实时库不该被删掉")
			}
			if _, err := WafShareDbServiceApp.ForceDeleteShard(model.AccessLogTableName + "_209912"); err == nil {
				t.Error("share_dbs 里没有登记的名字不该能删")
			}

			// 正常删：三层表与分片记录都要没
			if _, err := WafShareDbServiceApp.ForceDeleteShard(name); err != nil {
				t.Fatalf("删除分区失败: %v", err)
			}
			for _, b := range tiers {
				if d.TableExists(logdb, partition.TableName(b, key)) {
					t.Errorf("%s 应已被丢掉", partition.TableName(b, key))
				}
			}
			var left int64
			must(t, core.Model(&model.ShareDb{}).Where("file_name = ?", name).Count(&left).Error)
			if left != 0 {
				t.Errorf("分片记录应一并删除，实际还有 %d 条（下拉里会留下一个不存在的分区）", left)
			}
			// 实时表一张都不能少
			for _, b := range tiers {
				if !d.TableExists(logdb, b) {
					t.Fatalf("实时表 %s 被误删了", b)
				}
			}
		})
	}

	_ = innerbean.WebLog{}
}
