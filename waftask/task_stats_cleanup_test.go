package waftask

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/wafdb"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// ---------------------------------------------------------------------------
// 辅助：初始化测试环境（复用 task_history_test.go 的模式）
// ---------------------------------------------------------------------------

func initTestEnvForCleanup(t *testing.T) {
	t.Helper()
	currentPath := "../"
	config := viper.New()
	config.AddConfigPath(currentPath + "/conf/")
	config.SetConfigName("config")
	config.SetConfigType("yml")
	if err := config.ReadInConfig(); err != nil {
		t.Fatalf("读取配置文件失败: %v", err)
	}

	//初始化日志
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "json")
	if v := recover(); v != nil {
		zlog.Error("error")
	}

	global.GWAF_USER_CODE = config.GetString("user_code")
	global.GWAF_TENANT_ID = global.GWAF_USER_CODE
	global.GWAF_LOCAL_SERVER_PORT = config.GetInt("local_port")
	global.GWAF_CUSTOM_SERVER_NAME = config.GetString("custom_server_name")
	zlog.Debug("load ini: ", global.GWAF_USER_CODE)

	wafdb.InitCoreDb(currentPath)
	wafdb.InitStatsDb(currentPath)
}

// ---------------------------------------------------------------------------
// 造数据：stats_ip_days
//   - recentDays 条：最近 recentDays 天内，每天 1 条（应被保留）
//   - oldDays   条：距今 oldDaysAgo~(oldDaysAgo+oldDays) 天，每天 1 条（应被清理）
// ---------------------------------------------------------------------------

func seedStatsIPDays(t *testing.T, recentDays, oldDays, oldDaysAgo int) {
	t.Helper()
	db := global.GWAF_LOCAL_STATS_DB
	now := time.Now()

	ips := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8", "1.1.1.1"}
	types := []string{"放行", "禁止", "阻止"}

	inserted := 0

	// 近期数据（应保留）
	for i := 0; i < recentDays; i++ {
		day := now.AddDate(0, 0, -i)
		dayInt := dateToInt(day)
		for _, ip := range ips {
			for _, tp := range types {
				r := &model.StatsIPDay{
					BaseOrm:  newBaseOrm(),
					HostCode: fmt.Sprintf("host_%02d", rand.Intn(3)+1),
					Day:      dayInt,
					Host:     fmt.Sprintf("site%d.example.com", rand.Intn(3)+1),
					IP:       ip,
					Type:     tp,
					Count:    rand.Intn(500) + 1,
				}
				if err := db.Create(r).Error; err != nil {
					t.Logf("插入 stats_ip_days 失败: %v", err)
				} else {
					inserted++
				}
			}
		}
	}

	// 历史旧数据（应被天数清理）
	for i := 0; i < oldDays; i++ {
		day := now.AddDate(0, 0, -(oldDaysAgo + i))
		dayInt := dateToInt(day)
		for _, ip := range ips[:2] { // 只取前两个 IP，减少数据量
			r := &model.StatsIPDay{
				BaseOrm:  newBaseOrm(),
				HostCode: "host_01",
				Day:      dayInt,
				Host:     "old.example.com",
				IP:       ip,
				Type:     types[rand.Intn(len(types))],
				Count:    rand.Intn(100) + 1,
			}
			if err := db.Create(r).Error; err != nil {
				t.Logf("插入旧 stats_ip_days 失败: %v", err)
			} else {
				inserted++
			}
		}
	}

	t.Logf("stats_ip_days: 写入 %d 条（近期 %d 天 × %d IP × %d 类型，旧数据 %d 天 × 2 IP × 随机类型）",
		inserted, recentDays, len(ips), len(types), oldDays)
}

// ---------------------------------------------------------------------------
// 造数据：stats_ip_city_days
// ---------------------------------------------------------------------------

func seedStatsIPCityDays(t *testing.T, recentDays, oldDays, oldDaysAgo int) {
	t.Helper()
	db := global.GWAF_LOCAL_STATS_DB
	now := time.Now()

	cities := []struct{ country, province, city string }{
		{"中国", "广东", "深圳"},
		{"中国", "北京", "北京"},
		{"中国", "上海", "上海"},
		{"美国", "", "Los Angeles"},
		{"日本", "", "Tokyo"},
	}
	types := []string{"放行", "禁止", "阻止"}

	inserted := 0

	for i := 0; i < recentDays; i++ {
		day := now.AddDate(0, 0, -i)
		dayInt := dateToInt(day)
		for _, c := range cities {
			for _, tp := range types {
				r := &model.StatsIPCityDay{
					BaseOrm:  newBaseOrm(),
					HostCode: fmt.Sprintf("host_%02d", rand.Intn(3)+1),
					Day:      dayInt,
					Host:     fmt.Sprintf("site%d.example.com", rand.Intn(3)+1),
					Country:  c.country,
					Province: c.province,
					City:     c.city,
					Type:     tp,
					Count:    rand.Intn(1000) + 1,
				}
				if err := db.Create(r).Error; err != nil {
					t.Logf("插入 stats_ip_city_days 失败: %v", err)
				} else {
					inserted++
				}
			}
		}
	}

	for i := 0; i < oldDays; i++ {
		day := now.AddDate(0, 0, -(oldDaysAgo + i))
		dayInt := dateToInt(day)
		for _, c := range cities[:2] {
			r := &model.StatsIPCityDay{
				BaseOrm:  newBaseOrm(),
				HostCode: "host_01",
				Day:      dayInt,
				Host:     "old.example.com",
				Country:  c.country,
				Province: c.province,
				City:     c.city,
				Type:     types[rand.Intn(len(types))],
				Count:    rand.Intn(200) + 1,
			}
			if err := db.Create(r).Error; err != nil {
				t.Logf("插入旧 stats_ip_city_days 失败: %v", err)
			} else {
				inserted++
			}
		}
	}

	t.Logf("stats_ip_city_days: 写入 %d 条（近期 %d 天 × %d 城市 × %d 类型，旧数据 %d 天 × 2 城市 × 随机类型）",
		inserted, recentDays, len(cities), len(types), oldDays)
}

// ---------------------------------------------------------------------------
// 造数据：ip_tags
// ---------------------------------------------------------------------------

func seedIPTags(t *testing.T, recentCount, oldCount, oldDaysAgo int) {
	t.Helper()
	db := global.GWAF_LOCAL_STATS_DB
	now := time.Now()

	tags := []string{"scanner", "bot", "attacker", "brute-force", "spider"}

	inserted := 0

	// 近期活跃 IP（create_time 在近期，update_time 也较新）
	for i := 0; i < recentCount; i++ {
		createTime := now.AddDate(0, 0, -rand.Intn(30)) // 最近30天内创建
		updateTime := now.AddDate(0, 0, -rand.Intn(7))  // 最近7天内更新（活跃）
		r := &model.IPTag{
			BaseOrm: baseorm.BaseOrm{
				Id:          uuid.GenUUID(),
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(createTime),
				UPDATE_TIME: customtype.JsonTime(updateTime),
			},
			IP:      fmt.Sprintf("10.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256)),
			IPTag:   tags[rand.Intn(len(tags))],
			Cnt:     int64(rand.Intn(10000) + 100),
			Remarks: fmt.Sprintf("近期活跃 IP #%d", i+1),
		}
		if err := db.Create(r).Error; err != nil {
			t.Logf("插入近期 ip_tags 失败: %v", err)
		} else {
			inserted++
		}
	}

	// 历史老旧 IP（create_time 超过 oldDaysAgo 天，update_time 也很老）
	for i := 0; i < oldCount; i++ {
		createTime := now.AddDate(0, 0, -(oldDaysAgo + rand.Intn(30))) // 创建时间很旧
		updateTime := createTime.Add(time.Duration(rand.Intn(24)) * time.Hour)
		r := &model.IPTag{
			BaseOrm: baseorm.BaseOrm{
				Id:          uuid.GenUUID(),
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(createTime),
				UPDATE_TIME: customtype.JsonTime(updateTime),
			},
			IP:      fmt.Sprintf("192.168.%d.%d", rand.Intn(256), rand.Intn(256)),
			IPTag:   tags[rand.Intn(len(tags))],
			Cnt:     int64(rand.Intn(50) + 1),
			Remarks: fmt.Sprintf("历史旧 IP #%d", i+1),
		}
		if err := db.Create(r).Error; err != nil {
			t.Logf("插入旧 ip_tags 失败: %v", err)
		} else {
			inserted++
		}
	}

	t.Logf("ip_tags: 写入 %d 条（近期活跃 %d，旧数据 %d）", inserted, recentCount, oldCount)
}

// ---------------------------------------------------------------------------
// 统计各表行数的辅助函数
// ---------------------------------------------------------------------------

func countTable(t *testing.T, tableName string) int64 {
	t.Helper()
	var cnt int64
	if err := global.GWAF_LOCAL_STATS_DB.Table(tableName).Count(&cnt).Error; err != nil {
		t.Logf("查询 %s 行数失败: %v", tableName, err)
	}
	return cnt
}

// ---------------------------------------------------------------------------
// 测试1：纯造数据，验证写入成功 go test ./waftask/ -run TestSeedStatsData -v
// ---------------------------------------------------------------------------

func TestSeedStatsData(t *testing.T) {
	initTestEnvForCleanup(t)
	rand.Seed(time.Now().UnixNano())

	// 近期 30 天 + 旧数据 120 天（从 100 天前开始往前数）
	seedStatsIPDays(t, 30, 120, 100)
	seedStatsIPCityDays(t, 30, 120, 100)
	seedIPTags(t, 200, 300, 100)

	t.Logf("--- 写入后各表行数 ---")
	t.Logf("stats_ip_days      : %d", countTable(t, "stats_ip_days"))
	t.Logf("stats_ip_city_days : %d", countTable(t, "stats_ip_city_days"))
	t.Logf("ip_tags            : %d", countTable(t, "ip_tags"))
}

// ---------------------------------------------------------------------------
// 测试2：造数据后执行清理，验证清理效果
// ---------------------------------------------------------------------------

func TestSeedAndCleanupStats(t *testing.T) {
	initTestEnvForCleanup(t)
	rand.Seed(time.Now().UnixNano())

	// 造数据：
	//   近期60天（应保留），旧数据150天（从95天前往前推，超过90天阈值，应被清理）
	seedStatsIPDays(t, 60, 150, 95)
	seedStatsIPCityDays(t, 60, 150, 95)
	//   ip_tags：近期100条 + 旧数据200条（create_time 超过 95 天前，应被清理）
	seedIPTags(t, 100, 200, 95)

	t.Log("=== 清理前 ===")
	before := map[string]int64{
		"stats_ip_days":      countTable(t, "stats_ip_days"),
		"stats_ip_city_days": countTable(t, "stats_ip_city_days"),
		"ip_tags":            countTable(t, "ip_tags"),
	}
	for k, v := range before {
		t.Logf("  %-25s : %d", k, v)
	}

	// 执行清理
	TaskStatsDataCleanup()

	t.Log("=== 清理后 ===")
	after := map[string]int64{
		"stats_ip_days":      countTable(t, "stats_ip_days"),
		"stats_ip_city_days": countTable(t, "stats_ip_city_days"),
		"ip_tags":            countTable(t, "ip_tags"),
	}
	for k, v := range after {
		diff := before[k] - v
		t.Logf("  %-25s : %d（清理了 %d 条）", k, v, diff)
	}
}

// ---------------------------------------------------------------------------
// 测试3：仅造大批数据用于压测行数清理路径
// ---------------------------------------------------------------------------

func TestSeedLargeStatsIPDays(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过大数据量测试（使用 -short 标志时）")
	}
	initTestEnvForCleanup(t)
	rand.Seed(time.Now().UnixNano())

	// 造 365 天近期数据（足够多，触发行数清理兜底）
	seedStatsIPDays(t, 365, 0, 0)
	t.Logf("stats_ip_days 当前行数: %d", countTable(t, "stats_ip_days"))
}

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------

func newBaseOrm() baseorm.BaseOrm {
	return baseorm.BaseOrm{
		Id:          uuid.GenUUID(),
		USER_CODE:   global.GWAF_USER_CODE,
		Tenant_ID:   global.GWAF_TENANT_ID,
		CREATE_TIME: customtype.JsonTime(time.Now()),
		UPDATE_TIME: customtype.JsonTime(time.Now()),
	}
}

// dateToInt 将 time.Time 转成 YYYYMMDD 整数
func dateToInt(t time.Time) int {
	y, m, d := t.Date()
	return y*10000 + int(m)*100 + d
}
