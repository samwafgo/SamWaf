//go:build iptagperf

// 风险日志标签查询的性能基准。回答两个问题：
//  1. 把 ACME证书校验 / 静态文件访问成功 加进排除名单后会不会变慢（对照组＝老口径，只排除"正常"）
//  2. 数据量到几十万~百万行时，NOT IN 到底贵不贵、瓶颈在哪
//
// 运行（需要 CGO + mingw）：
//
//	go test -tags iptagperf ./service/waf_service/ -run TestIPTagExcludePerf -v -timeout 30m
//	SAMWAF_IPTAG_PERF_IPS=500000 go test -tags iptagperf ./service/waf_service/ -run TestIPTagExcludePerf -v -timeout 30m
//
// 数据形状按真实实例估：绝大多数 IP 只有「正常 / 静态文件访问成功」这类噪声标签，
// 少数 IP 才带攻击标签——这正是排除名单能省事的场景。
package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/common/request"
	req "SamWaf/model/request"
	"SamWaf/wafdb/dialect"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	perfUser   = "perf_user"
	perfTenant = "perf_tenant"
)

// perfIPCount 独立 IP 数，可用 SAMWAF_IPTAG_PERF_IPS 覆盖（行数约为其 2.1 倍）
func perfIPCount() int {
	if v := os.Getenv("SAMWAF_IPTAG_PERF_IPS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 50000
}

func openPerfIPTagDB(t *testing.T) *gorm.DB {
	t.Helper()
	dialect.Register(&dialect.SQLiteDialect{})
	dsn := filepath.Join(t.TempDir(), "iptag.db") + "?_db_key=" + url.QueryEscape("perf")
	db, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("打开 sqlite 失败: %v", err)
	}
	if err := db.AutoMigrate(&model.IPTag{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	// 与生产迁移一致的两个索引
	db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uni_iptags_full ON ip_tags (user_code, tenant_id, ip, ip_tag)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_iptag_ip ON ip_tags (user_code, tenant_id, ip)")
	// Windows 下不关连接，t.TempDir 清理会因文件占用报错
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
	})
	return db
}

// seedPerfIPTags 造数据：每个 IP 必有「正常」；90% 另有「静态文件访问成功」；
// 每 25 个 IP 里有 1 个带真攻击标签；每 500 个 IP 里有 1 个带 ACME证书校验。
func seedPerfIPTags(t *testing.T, db *gorm.DB, ipCount int) int {
	t.Helper()
	attackTags := []string{"SQL注入", "XSS跨站注入", "扫描工具", "RCE:存在OS命令注入", "OWASP:942100",
		"静态文件安全检查: 文件未找到", "威胁情报IP", "CSRF跨站请求伪造防护"}
	now := customtype.JsonTime(time.Now())
	rows := make([]model.IPTag, 0, 4096)
	total := 0
	flush := func() {
		if len(rows) == 0 {
			return
		}
		if err := db.CreateInBatches(rows, 512).Error; err != nil {
			t.Fatalf("造数据失败: %v", err)
		}
		total += len(rows)
		rows = rows[:0]
	}
	add := func(ip, tag string, cnt int64) {
		rows = append(rows, model.IPTag{
			BaseOrm: baseorm.BaseOrm{
				Id: uuid.GenUUID(), USER_CODE: perfUser, Tenant_ID: perfTenant,
				CREATE_TIME: now, UPDATE_TIME: now,
			},
			IP: ip, IPTag: tag, Cnt: cnt,
		})
		if len(rows) >= 4096 {
			flush()
		}
	}
	for i := 0; i < ipCount; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256)
		add(ip, "正常", int64(3+i%40))
		if i%10 != 0 {
			add(ip, "静态文件访问成功", int64(5+i%200)) // 历史遗留的大噪声标签
		}
		if i%25 == 0 {
			add(ip, attackTags[i%len(attackTags)], int64(1+i%17))
		}
		if i%500 == 0 {
			add(ip, "ACME证书校验", int64(1+i%3))
		}
	}
	flush()
	return total
}

// perfMust：本文件独立于 crossdb 套件，不能复用那边的 fatalIf
func perfMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
}

func timeIt(t *testing.T, name string, rounds int, fn func()) time.Duration {
	t.Helper()
	fn() // 预热，避免首跑把页缓存成本算进来
	start := time.Now()
	for i := 0; i < rounds; i++ {
		fn()
	}
	d := time.Since(start) / time.Duration(rounds)
	t.Logf("%-54s 平均 %v", name, d)
	return d
}

func TestIPTagExcludePerf(t *testing.T) {
	oldUser, oldTenant, oldDB, oldExclude :=
		global.GWAF_USER_CODE, global.GWAF_TENANT_ID, global.GWAF_LOCAL_DB, global.GCONFIG_ATTACK_TAG_EXCLUDE
	defer func() {
		global.GWAF_USER_CODE, global.GWAF_TENANT_ID, global.GWAF_LOCAL_DB, global.GCONFIG_ATTACK_TAG_EXCLUDE =
			oldUser, oldTenant, oldDB, oldExclude
	}()
	global.GWAF_USER_CODE = perfUser
	global.GWAF_TENANT_ID = perfTenant
	global.GDATA_IP_TAG_DB = 0

	db := openPerfIPTagDB(t)
	global.GWAF_LOCAL_DB = db

	ipCount := perfIPCount()
	seedStart := time.Now()
	rows := seedPerfIPTags(t, db, ipCount)
	t.Logf("造数据完成：%d 个 IP / %d 行 ip_tags，用时 %v", ipCount, rows, time.Since(seedStart))

	svc := WafLogService{}
	listReq := req.WafAttackIpTagSearch{PageInfo: request.PageInfo{PageIndex: 1, PageSize: 30}}
	rounds := 5
	if rows > 400000 {
		rounds = 3 // 大数据量下少跑几轮，避免整个用例太久
	}
	benign := []interface{}{"正常", "ACME证书校验", "静态文件访问成功"}

	// ============ ① 隔离测量：<> 与 NOT IN 到底差多少 ============
	// 同样是一次全表扫描 + 计数，只有过滤表达式不同
	t.Run("filter_expr", func(t *testing.T) {
		var n int64
		base := "SELECT COUNT(*) FROM ip_tags WHERE tenant_id=? AND user_code=? AND "
		timeIt(t, "ip_tag <> '正常'（老口径，1 次比较）", rounds, func() {
			perfMust(t, db.Raw(base+"ip_tag <> '正常'", perfTenant, perfUser).Scan(&n).Error)
		})
		timeIt(t, "ip_tag NOT IN (?,?,?)（现口径，3 个参数）", rounds, func() {
			perfMust(t, db.Raw(base+"ip_tag NOT IN (?,?,?)",
				append([]interface{}{perfTenant, perfUser}, benign...)...).Scan(&n).Error)
		})
		timeIt(t, "ip_tag<>? AND ip_tag<>? AND ip_tag<>?（等价展开）", rounds, func() {
			perfMust(t, db.Raw(base+"ip_tag<>? AND ip_tag<>? AND ip_tag<>?",
				append([]interface{}{perfTenant, perfUser}, benign...)...).Scan(&n).Error)
		})
		timeIt(t, "ip_tag NOT IN (20 项)（排除名单被写很长时）", rounds, func() {
			args := []interface{}{perfTenant, perfUser}
			ph := ""
			for i := 0; i < 20; i++ {
				if i > 0 {
					ph += ","
				}
				ph += "?"
				args = append(args, fmt.Sprintf("噪声标签%d", i))
			}
			perfMust(t, db.Raw(base+"ip_tag NOT IN ("+ph+")", args...).Scan(&n).Error)
		})
	})

	// ============ ② 服务层：排除前 vs 排除后 ============
	global.GCONFIG_ATTACK_TAG_EXCLUDE = ""
	baseTag := timeIt(t, "[排除前] 规则标签列表 GetAllAttackIPTagList", rounds, func() {
		if _, err := svc.GetAllAttackIPTagListApi(false); err != nil {
			t.Fatalf("标签列表查询失败: %v", err)
		}
	})
	baseList := timeIt(t, "[排除前] 风险IP列表 GetAttackIpList(第1页)", rounds, func() {
		if _, _, err := svc.GetAttackIpListApi(listReq); err != nil {
			t.Fatalf("IP列表查询失败: %v", err)
		}
	})
	var baseTagCnt, baseIPCnt int
	if l, err := svc.GetAllAttackIPTagListApi(false); err == nil {
		baseTagCnt = len(l)
	}
	if _, total, err := svc.GetAttackIpListApi(listReq); err == nil {
		baseIPCnt = int(total)
	}

	global.GCONFIG_ATTACK_TAG_EXCLUDE = "ACME证书校验,静态文件访问成功"
	newTag := timeIt(t, "[排除后] 规则标签列表 GetAllAttackIPTagList", rounds, func() {
		if _, err := svc.GetAllAttackIPTagListApi(false); err != nil {
			t.Fatalf("标签列表查询失败: %v", err)
		}
	})
	newList := timeIt(t, "[排除后] 风险IP列表 GetAttackIpList(第1页)", rounds, func() {
		if _, _, err := svc.GetAttackIpListApi(listReq); err != nil {
			t.Fatalf("IP列表查询失败: %v", err)
		}
	})
	var newTagCnt, newIPCnt int
	if l, err := svc.GetAllAttackIPTagListApi(false); err == nil {
		newTagCnt = len(l)
	}
	if _, total, err := svc.GetAttackIpListApi(listReq); err == nil {
		newIPCnt = int(total)
	}

	// ============ ③ 拆开看瓶颈：列表查询 vs 每页都跑的 COUNT ============
	t.Run("breakdown", func(t *testing.T) {
		var n int64
		ph := "?,?,?"
		timeIt(t, "[现状] 总数：GROUP BY ip + HAVING 子查询", rounds, func() {
			perfMust(t, db.Raw(`SELECT COUNT(*) FROM (
				SELECT tenant_id,user_code,ip FROM ip_tags WHERE tenant_id=? AND user_code=?
				GROUP BY tenant_id,user_code,ip
				HAVING SUM(CASE WHEN ip_tag NOT IN (`+ph+`) THEN cnt ELSE 0 END) > 0) AS s`,
				append([]interface{}{perfTenant, perfUser}, benign...)...).Scan(&n).Error)
		})
		timeIt(t, "[候选] 总数：COUNT(DISTINCT ip) + WHERE NOT IN", rounds, func() {
			perfMust(t, db.Raw(`SELECT COUNT(DISTINCT ip) FROM ip_tags
				WHERE tenant_id=? AND user_code=? AND ip_tag NOT IN (`+ph+`)`,
				append([]interface{}{perfTenant, perfUser}, benign...)...).Scan(&n).Error)
		})
		var ips []string
		timeIt(t, "[候选] 先取本页 IP：WHERE NOT IN + GROUP BY ip + LIMIT", rounds, func() {
			perfMust(t, db.Raw(`SELECT ip FROM ip_tags
				WHERE tenant_id=? AND user_code=? AND ip_tag NOT IN (`+ph+`)
				GROUP BY ip ORDER BY MAX(update_time) DESC LIMIT 30`,
				append([]interface{}{perfTenant, perfUser}, benign...)...).Scan(&ips).Error)
		})
		t.Logf("候选方案第一步取到 %d 个 IP", len(ips))
	})

	t.Logf("=== 汇总（%d 行 ip_tags）===", rows)
	t.Logf("标签条数 %d -> %d，风险IP总数 %d -> %d", baseTagCnt, newTagCnt, baseIPCnt, newIPCnt)
	t.Logf("标签列表 %v -> %v (%.0f%%)", baseTag, newTag, float64(newTag)/float64(baseTag)*100)
	t.Logf("风险IP列表 %v -> %v (%.0f%%)", baseList, newList, float64(newList)/float64(baseList)*100)

	// 排除后不应该明显更慢：留一倍余量，跑在开发机上也不至于抖动误报
	if newTag > baseTag*2 {
		t.Fatalf("标签列表查询在加排除后明显变慢：%v -> %v", baseTag, newTag)
	}
	if newList > baseList*2 {
		t.Fatalf("风险IP列表查询在加排除后明显变慢：%v -> %v", baseList, newList)
	}
}
