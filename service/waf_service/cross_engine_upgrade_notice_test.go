//go:build crossdb

// 升级须知（upgrade_notice_record）三库回归：生成幂等、状态流转、列表过滤、降级不生成。
package waf_service

import (
	"SamWaf/model"
	commonreq "SamWaf/model/common/request"
	"SamWaf/model/request"
	"SamWaf/wafupgradenotice"
	"strings"
	"testing"

	"gorm.io/gorm"
)

func runUpgradeNoticeCases(t *testing.T, db *gorm.DB) {
	svc := WafUpgradeNoticeServiceApp

	clean := func() {
		must(t, db.Where("1 = 1").Delete(&model.UpgradeNoticeRecord{}).Error)
	}

	countRecords := func() int64 {
		var n int64
		must(t, db.Model(&model.UpgradeNoticeRecord{}).Count(&n).Error)
		return n
	}

	t.Run("UpgradeNotice_生成与幂等", func(t *testing.T) {
		clean()
		// v1.3.21 -> v1.3.23：应当取到内置清单里 (v1.3.21, v1.3.23] 区间的条目
		want := len(wafupgradenotice.Select("v1.3.21", "v1.3.23", false))
		if want == 0 {
			t.Skip("内置清单在该区间没有条目")
		}
		svc.Generate("v1.3.21", "v1.3.23", "v1.3.21")
		if got := countRecords(); got != int64(want) {
			t.Fatalf("首次生成条数不对: got %d want %d", got, want)
		}
		// 再跑一次（模拟重启）不得重复生成
		svc.Generate("v1.3.21", "v1.3.23", "v1.3.21")
		if got := countRecords(); got != int64(want) {
			t.Fatalf("重复启动产生了重复记录: got %d want %d", got, want)
		}
	})

	t.Run("UpgradeNotice_状态流转不被再次生成覆盖", func(t *testing.T) {
		clean()
		notes := wafupgradenotice.Select("v1.3.21", "v1.3.23", false)
		if len(notes) == 0 {
			t.Skip("内置清单在该区间没有条目")
		}
		svc.Generate("v1.3.21", "v1.3.23", "v1.3.21")

		target := notes[0].Id
		fatalIf(t, svc.SetStatus(target, model.UpgradeNoticeStatusDone, "tester"))

		var bean model.UpgradeNoticeRecord
		firstBy(t, db, &bean, "notice_id = ?", target)
		if bean.Status != model.UpgradeNoticeStatusDone || bean.AppliedUser != "tester" {
			t.Fatalf("状态未落库: %+v", bean)
		}

		// 重新生成不得把已处理改回待处理
		svc.Generate("v1.3.21", "v1.3.23", "v1.3.21")
		firstBy(t, db, &bean, "notice_id = ?", target)
		if bean.Status != model.UpgradeNoticeStatusDone {
			t.Fatalf("重复生成覆盖了用户的处理状态: %+v", bean)
		}

		// 恢复待处理时要把处理人/处理时间清掉
		fatalIf(t, svc.SetStatus(target, model.UpgradeNoticeStatusPending, "tester"))
		firstBy(t, db, &bean, "notice_id = ?", target)
		if bean.Status != model.UpgradeNoticeStatusPending || bean.AppliedUser != "" {
			t.Fatalf("恢复待处理未清理处理人: %+v", bean)
		}
	})

	t.Run("UpgradeNotice_伪造ID被拒", func(t *testing.T) {
		if err := svc.SetStatus("not_in_manifest", model.UpgradeNoticeStatusDone, "tester"); err == nil {
			t.Fatal("清单外的 notice_id 应当被拒绝")
		}
		if err := svc.SetStatus("", model.UpgradeNoticeStatusDone, "tester"); err == nil {
			t.Fatal("空 notice_id 应当被拒绝")
		}
	})

	t.Run("UpgradeNotice_列表与汇总", func(t *testing.T) {
		clean()
		notes := wafupgradenotice.Select("v1.3.21", "v1.3.23", false)
		if len(notes) == 0 {
			t.Skip("内置清单在该区间没有条目")
		}
		svc.Generate("v1.3.21", "v1.3.23", "v1.3.21")

		items, total, err := svc.GetListApi(request.WafUpgradeNoticeSearchReq{
			Status:   model.UpgradeNoticeStatusPending,
			Lang:     "zh_CN",
			PageInfo: commonreq.PageInfo{PageIndex: 1, PageSize: 50},
		})
		fatalIf(t, err)
		if total != int64(len(notes)) || len(items) != len(notes) {
			t.Fatalf("列表条数不对: total=%d items=%d want=%d", total, len(items), len(notes))
		}
		for _, item := range items {
			if item.Title == "" {
				t.Fatalf("条目文案为空(清单未接上): %+v", item)
			}
		}

		// 英文必须给出另一套文案
		enItems, _, err := svc.GetListApi(request.WafUpgradeNoticeSearchReq{
			Status:   model.UpgradeNoticeStatusPending,
			Lang:     "en_US",
			PageInfo: commonreq.PageInfo{PageIndex: 1, PageSize: 50},
		})
		fatalIf(t, err)
		if len(enItems) != len(items) || enItems[0].Title == items[0].Title {
			t.Fatalf("英文文案未生效: zh=%q en=%q", items[0].Title, enItems[0].Title)
		}

		summary := svc.GetSummary("zh_CN")
		if summary.PendingCount != int64(len(notes)) {
			t.Fatalf("汇总待处理数不对: %d want %d", summary.PendingCount, len(notes))
		}
		if summary.HighPendingCount > 0 && !summary.NeedPopup {
			t.Fatal("存在未弹过窗的重要条目时应当需要弹窗")
		}

		// 弹过一次之后不再弹
		fatalIf(t, svc.MarkPopupShown())
		if svc.GetSummary("zh_CN").NeedPopup {
			t.Fatal("弹窗回写后不应再要求弹窗")
		}
	})

	t.Run("UpgradeNotice_降级不生成只给告警", func(t *testing.T) {
		clean()
		svc.Generate("v1.3.24", "v1.3.22", "v1.3.24")
		if got := countRecords(); got != 0 {
			t.Fatalf("降级路径不应生成须知，实际生成了 %d 条", got)
		}
		summary := svc.GetSummary("zh_CN")
		if !summary.Downgrade || summary.DowngradeMsg == "" {
			t.Fatalf("降级运行应当在汇总里给出告警: %+v", summary)
		}
		// 恢复正常状态，避免影响后续用例
		svc.Generate("v1.3.23", "v1.3.23", "v1.3.23")
	})

	// 降级判定必须走"历史最高版本"：last 会被写回成当前这个较低版本，
	// 用 last 判的话重启一次告警就消失，而旧程序+新库的状态还在。
	t.Run("UpgradeNotice_降级判定用最高版本而非上次版本", func(t *testing.T) {
		clean()
		// 模拟"降级后又重启一次"：last 已经被上一轮写成了当前的低版本，只有 maxSeen 还记得高版本
		svc.Generate("v1.3.22", "v1.3.22", "v1.3.24")
		summary := svc.GetSummary("zh_CN")
		if !summary.Downgrade {
			t.Fatal("重启后仍应保留降级告警（证据在 max_run_version 里）")
		}
		if !strings.Contains(summary.DowngradeMsg, "v1.3.24") {
			t.Fatalf("告警应指向历史最高版本 v1.3.24: %s", summary.DowngradeMsg)
		}
		svc.Generate("v1.3.23", "v1.3.23", "v1.3.23")
	})

	t.Run("UpgradeNotice_降级告警确认与复现", func(t *testing.T) {
		clean()
		must(t, db.Where("item = ?", downgradeAckItem).Delete(&model.SystemConfig{}).Error)

		svc.Generate("v1.3.22", "v1.3.22", "v1.3.24")
		if !svc.GetSummary("zh_CN").Downgrade {
			t.Fatal("确认前应有降级告警")
		}
		fatalIf(t, svc.AckDowngrade())
		if svc.GetSummary("zh_CN").Downgrade {
			t.Fatal("确认后不应再显示降级告警")
		}

		// 同一个历史最高版本重启多少次都不再提示
		svc.Generate("v1.3.22", "v1.3.22", "v1.3.24")
		if svc.GetSummary("zh_CN").Downgrade {
			t.Fatal("同一最高版本重启后不应重新提示")
		}

		// 最高版本又变高 = 用户又升级又回退了一次，是新证据，告警必须重新出现
		svc.Generate("v1.3.22", "v1.3.22", "v1.3.25")
		if !svc.GetSummary("zh_CN").Downgrade {
			t.Fatal("历史最高版本变高后应重新提示")
		}

		// 没有告警时确认应当被拒绝
		svc.Generate("v1.3.23", "v1.3.23", "v1.3.23")
		if err := svc.AckDowngrade(); err == nil {
			t.Fatal("没有降级告警时不应允许确认")
		}
		must(t, db.Where("item = ?", downgradeAckItem).Delete(&model.SystemConfig{}).Error)
	})
}
