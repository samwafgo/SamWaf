package waftask

import (
	"SamWaf/global"
	"sort"
	"testing"

	"gorm.io/gorm"
)

// planTrafficUpserts 是落库前的合并逻辑：同一天的多个整点桶要合成一条天级增量，
// 小时级则必须保持分开——写错了就会出现「天总量对、小时曲线错」这种最难查的问题。
func TestPlanTrafficUpserts_MergesDayKeepsHours(t *testing.T) {
	list := []global.TrafficSnapshot{
		{TrafficKey: global.TrafficKey{HostCode: "h1", Host: "a.com", Day: 20260818, HourTime: 1000}, In: 10, Out: 100},
		{TrafficKey: global.TrafficKey{HostCode: "h1", Host: "a.com", Day: 20260818, HourTime: 4600}, In: 5, Out: 50},
		{TrafficKey: global.TrafficKey{HostCode: "h1", Host: "a.com", Day: 20260819, HourTime: 90000}, In: 1, Out: 2},
		{TrafficKey: global.TrafficKey{HostCode: "h2", Host: "b.com", Day: 20260818, HourTime: 1000}, In: 7, Out: 8},
	}

	days, hours := planTrafficUpserts(list)

	if len(days) != 3 {
		t.Fatalf("天级增量应为 3 条(h1两天 + h2一天)，实际 %d: %+v", len(days), days)
	}
	if len(hours) != 4 {
		t.Fatalf("小时级增量应为 4 条(各整点分开)，实际 %d: %+v", len(hours), hours)
	}

	sort.Slice(days, func(i, j int) bool {
		if days[i].HostCode != days[j].HostCode {
			return days[i].HostCode < days[j].HostCode
		}
		return days[i].Day < days[j].Day
	})
	// h1 的 0818：两个整点必须合并成 15/150
	if days[0].HostCode != "h1" || days[0].Day != 20260818 || days[0].In != 15 || days[0].Out != 150 {
		t.Fatalf("同一天的多个整点没合并对: %+v", days[0])
	}
	if days[0].Host != "a.com" {
		t.Fatalf("域名没带上: %+v", days[0])
	}
	if days[1].Day != 20260819 || days[1].In != 1 || days[1].Out != 2 {
		t.Fatalf("跨天的增量被并到一起了: %+v", days[1])
	}
	if days[2].HostCode != "h2" || days[2].In != 7 || days[2].Out != 8 {
		t.Fatalf("不同站点串账: %+v", days[2])
	}
}

// 空桶/无 host_code 的记录不该产生任何写库动作
func TestPlanTrafficUpserts_SkipsEmpty(t *testing.T) {
	list := []global.TrafficSnapshot{
		{TrafficKey: global.TrafficKey{HostCode: "", Host: "a.com", Day: 20260818, HourTime: 1000}, In: 10, Out: 10},
		{TrafficKey: global.TrafficKey{HostCode: "h1", Host: "a.com", Day: 20260818, HourTime: 1000}, In: 0, Out: 0},
	}
	days, hours := planTrafficUpserts(list)
	if len(days) != 0 || len(hours) != 0 {
		t.Fatalf("空桶不该落库，实际 days=%d hours=%d", len(days), len(hours))
	}
}

func TestPlanTrafficUpserts_Empty(t *testing.T) {
	days, hours := planTrafficUpserts(nil)
	if len(days) != 0 || len(hours) != 0 {
		t.Fatalf("空输入应返回空计划")
	}
}

// 库没就绪时绝不能把内存里的增量取走丢掉——必须留着等下个周期
func TestFlushTrafficStats_KeepsDataWhenDBNotReady(t *testing.T) {
	global.DrainTraffic()
	oldDB := global.GWAF_LOCAL_STATS_DB
	global.GWAF_LOCAL_STATS_DB = nil
	defer func() { global.GWAF_LOCAL_STATS_DB = oldDB }()

	global.AddTraffic("h1", "a.com", 20260818, 1000, 123, 456)
	FlushTrafficStats()

	if n := global.PendingTrafficBuckets(); n != 1 {
		t.Fatalf("库未就绪时应保留增量，实际待落库桶数 = %d（数据被丢了）", n)
	}
	global.DrainTraffic()
}

// 切库窗口同理：跳过本轮，不取走
func TestFlushTrafficStats_KeepsDataWhileSwitchingDB(t *testing.T) {
	global.DrainTraffic()
	oldDB := global.GWAF_LOCAL_STATS_DB
	// 必须给个非 nil 的库句柄，否则会在「库未就绪」那道判断就返回，测不到切库分支
	global.GWAF_LOCAL_STATS_DB = &gorm.DB{}
	global.GDATA_CURRENT_CHANGE = true
	defer func() {
		global.GDATA_CURRENT_CHANGE = false
		global.GWAF_LOCAL_STATS_DB = oldDB
	}()

	global.AddTraffic("h1", "a.com", 20260818, 1000, 1, 1)
	FlushTrafficStats()

	if n := global.PendingTrafficBuckets(); n != 1 {
		t.Fatalf("切库时应保留增量，实际待落库桶数 = %d", n)
	}
	global.DrainTraffic()
}
