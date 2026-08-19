package waftask

import (
	"SamWaf/common/uuid"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"net/url"
	"path/filepath"
	"testing"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 真实库落盘验证：UPSERT 的「先累加、影响 0 行再新建」语义必须成立，
// 否则要么第一笔流量丢失（没建行），要么每轮都新建行（重复计数）。
// 无 CGO / 驱动不可用的环境自动跳过，不阻塞普通 go test。
func openTrafficTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "stats.db") + "?_db_key=" + url.QueryEscape("ktest")
	db, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Skipf("打不开 sqlite（缺 CGO？），跳过真实库用例: %v", err)
	}
	if err := db.AutoMigrate(&model.StatsSiteDay{}, &model.StatsSiteHour{}); err != nil {
		t.Skipf("建表失败，跳过真实库用例: %v", err)
	}
	// Windows 上不关连接，t.TempDir 清理会因文件被占用而报错
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			sqlDB.Close()
		}
	})
	return db
}

func TestWriteTrafficStats_CreateThenAccumulate(t *testing.T) {
	db := openTrafficTestDB(t)

	const day = 20260818
	const hour int64 = 1755500400
	snap := func(in, out int64) []global.TrafficSnapshot {
		return []global.TrafficSnapshot{{
			TrafficKey: global.TrafficKey{HostCode: "h1", Host: "a.com", Day: day, HourTime: hour},
			In:         in, Out: out,
		}}
	}

	// 第一轮：表里没有行 → 应新建
	if err := writeTrafficStats(db, snap(100, 1000)); err != nil {
		t.Fatalf("首轮落库失败: %v", err)
	}
	var days []model.StatsSiteDay
	if err := db.Find(&days).Error; err != nil {
		t.Fatal(err)
	}
	if len(days) != 1 {
		t.Fatalf("首轮应新建 1 行天记录，实际 %d 行", len(days))
	}
	if days[0].TrafficIn != 100 || days[0].TrafficOut != 1000 {
		t.Fatalf("首轮天流量 = %d/%d，期望 100/1000", days[0].TrafficIn, days[0].TrafficOut)
	}
	if days[0].TotalCount != 0 {
		t.Fatalf("流量落库不该动 PV 列，实际 total_count = %d", days[0].TotalCount)
	}

	// 第二轮：同一天同整点 → 必须在原行上累加，而不是再插一行
	if err := writeTrafficStats(db, snap(50, 500)); err != nil {
		t.Fatalf("二轮落库失败: %v", err)
	}
	days = nil
	if err := db.Find(&days).Error; err != nil {
		t.Fatal(err)
	}
	if len(days) != 1 {
		t.Fatalf("二轮不该新增行，实际 %d 行（重复计数）", len(days))
	}
	if days[0].TrafficIn != 150 || days[0].TrafficOut != 1500 {
		t.Fatalf("累加后天流量 = %d/%d，期望 150/1500", days[0].TrafficIn, days[0].TrafficOut)
	}

	var hours []model.StatsSiteHour
	if err := db.Find(&hours).Error; err != nil {
		t.Fatal(err)
	}
	if len(hours) != 1 {
		t.Fatalf("小时行应只有 1 行，实际 %d 行", len(hours))
	}
	if hours[0].TrafficIn != 150 || hours[0].TrafficOut != 1500 {
		t.Fatalf("累加后小时流量 = %d/%d，期望 150/1500", hours[0].TrafficIn, hours[0].TrafficOut)
	}
}

// 已有日志聚合建好的行（有 PV 没流量）时，流量落库只能补流量列，不能覆盖 PV
func TestWriteTrafficStats_DoesNotClobberExistingCounts(t *testing.T) {
	db := openTrafficTestDB(t)

	const day = 20260818
	const hour int64 = 1755500400
	// 模拟 CollectStatsFromLogs 先建好行。
	// 租户/用户两列必须与 global 一致：流量 UPSERT 的 WHERE 带了这两列，
	// 对不上就会退化成"再插一行"，天级数据被拆成两行。
	if err := db.Create(&model.StatsSiteDay{
		BaseOrm: baseorm.BaseOrm{
			Id:        uuid.GenUUID(),
			USER_CODE: global.GWAF_USER_CODE,
			Tenant_ID: global.GWAF_TENANT_ID,
		},
		HostCode: "h1", Host: "a.com", Day: day,
		TotalCount: 218, AttackCount: 83, NormalCount: 135,
	}).Error; err != nil {
		t.Fatal(err)
	}

	if err := writeTrafficStats(db, []global.TrafficSnapshot{{
		TrafficKey: global.TrafficKey{HostCode: "h1", Host: "a.com", Day: day, HourTime: hour},
		In:         7, Out: 9,
	}}); err != nil {
		t.Fatal(err)
	}

	var got model.StatsSiteDay
	if err := db.Where("host_code = ? and day = ?", "h1", day).First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.TotalCount != 218 || got.AttackCount != 83 || got.NormalCount != 135 {
		t.Fatalf("流量落库把日志聚合的计数覆盖了: %+v", got)
	}
	if got.TrafficIn != 7 || got.TrafficOut != 9 {
		t.Fatalf("流量列没写上: %d/%d", got.TrafficIn, got.TrafficOut)
	}
}

// 多站点多天一次落库：各行独立，不串账
func TestWriteTrafficStats_MultiHostMultiDay(t *testing.T) {
	db := openTrafficTestDB(t)

	list := []global.TrafficSnapshot{
		{TrafficKey: global.TrafficKey{HostCode: "h1", Host: "a.com", Day: 20260818, HourTime: 1000}, In: 1, Out: 2},
		{TrafficKey: global.TrafficKey{HostCode: "h1", Host: "a.com", Day: 20260818, HourTime: 4600}, In: 3, Out: 4},
		{TrafficKey: global.TrafficKey{HostCode: "h1", Host: "a.com", Day: 20260819, HourTime: 90000}, In: 5, Out: 6},
		{TrafficKey: global.TrafficKey{HostCode: "h2", Host: "b.com", Day: 20260818, HourTime: 1000}, In: 7, Out: 8},
	}
	if err := writeTrafficStats(db, list); err != nil {
		t.Fatal(err)
	}

	var days []model.StatsSiteDay
	if err := db.Order("host_code, day").Find(&days).Error; err != nil {
		t.Fatal(err)
	}
	if len(days) != 3 {
		t.Fatalf("天级应为 3 行，实际 %d", len(days))
	}
	// h1 0818 两个整点合并
	if days[0].HostCode != "h1" || days[0].Day != 20260818 || days[0].TrafficIn != 4 || days[0].TrafficOut != 6 {
		t.Fatalf("h1 0818 天级合并错误: %+v", days[0])
	}
	if days[1].Day != 20260819 || days[1].TrafficIn != 5 {
		t.Fatalf("h1 0819 天级错误: %+v", days[1])
	}
	if days[2].HostCode != "h2" || days[2].TrafficIn != 7 {
		t.Fatalf("h2 天级错误: %+v", days[2])
	}

	var hours []model.StatsSiteHour
	if err := db.Find(&hours).Error; err != nil {
		t.Fatal(err)
	}
	if len(hours) != 4 {
		t.Fatalf("小时级应为 4 行（各整点分开），实际 %d", len(hours))
	}
}

// 事务语义：中途失败必须整笔回滚，避免「一半写进去了」下轮重试造成重复计数
func TestWriteTrafficStats_RollsBackOnError(t *testing.T) {
	db := openTrafficTestDB(t)

	// 先写一笔正常数据
	if err := writeTrafficStats(db, []global.TrafficSnapshot{{
		TrafficKey: global.TrafficKey{HostCode: "h1", Host: "a.com", Day: 20260818, HourTime: 1000},
		In:         10, Out: 10,
	}}); err != nil {
		t.Fatal(err)
	}
	// 把小时表删掉，制造「天表能写、小时表必失败」的场景
	if err := db.Migrator().DropTable(&model.StatsSiteHour{}); err != nil {
		t.Fatal(err)
	}

	err := writeTrafficStats(db, []global.TrafficSnapshot{{
		TrafficKey: global.TrafficKey{HostCode: "h1", Host: "a.com", Day: 20260818, HourTime: 1000},
		In:         999, Out: 999,
	}})
	if err == nil {
		t.Fatal("小时表不存在时应返回错误")
	}

	var got model.StatsSiteDay
	if e := db.Where("host_code = ?", "h1").First(&got).Error; e != nil {
		t.Fatal(e)
	}
	if got.TrafficIn != 10 {
		t.Fatalf("事务没回滚：天表被写成 %d，期望仍是 10（否则退回内存重试会重复计数）", got.TrafficIn)
	}
}
