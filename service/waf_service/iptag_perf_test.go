//go:build iptagperf

// 风险日志标签排除的性能对照：回答「把 ACME证书校验 / 静态文件访问成功 加进排除名单后
// 查询会不会变慢」。对照组是老口径（只排除"正常"，等价于加排除之前的 SQL）。
//
// 运行（需要 CGO + mingw）：
//
//	go test -tags iptagperf ./service/waf_service/ -run TestIPTagExcludePerf -v
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
	"path/filepath"
	"testing"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	perfUser   = "perf_user"
	perfTenant = "perf_tenant"
	perfIPs    = 50000 // 独立 IP 数
)

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
func seedPerfIPTags(t *testing.T, db *gorm.DB) int {
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
	for i := 0; i < perfIPs; i++ {
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

func timeIt(t *testing.T, name string, rounds int, fn func()) time.Duration {
	t.Helper()
	fn() // 预热，避免首跑把页缓存成本算进来
	start := time.Now()
	for i := 0; i < rounds; i++ {
		fn()
	}
	d := time.Since(start) / time.Duration(rounds)
	t.Logf("%-46s 平均 %v", name, d)
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

	seedStart := time.Now()
	rows := seedPerfIPTags(t, db)
	t.Logf("造数据完成：%d 个 IP / %d 行 ip_tags，用时 %v", perfIPs, rows, time.Since(seedStart))

	svc := WafLogService{}
	listReq := req.WafAttackIpTagSearch{PageInfo: request.PageInfo{PageIndex: 1, PageSize: 30}}
	const rounds = 8

	// —— 对照组：老口径（只排除"正常"）——
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

	// —— 实验组：加上 ACME证书校验 / 静态文件访问成功 ——
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

	t.Logf("标签条数 %d -> %d，风险IP总数 %d -> %d", baseTagCnt, newTagCnt, baseIPCnt, newIPCnt)
	t.Logf("标签列表 %v -> %v (%.0f%%)", baseTag, newTag, float64(newTag)/float64(baseTag)*100)
	t.Logf("风险IP列表 %v -> %v (%.0f%%)", baseList, newList, float64(newList)/float64(baseList)*100)

	// 排除后不应该更慢：留一倍余量，跑在开发机上也不至于抖动误报
	if newTag > baseTag*2 {
		t.Fatalf("标签列表查询在加排除后明显变慢：%v -> %v", baseTag, newTag)
	}
	if newList > baseList*2 {
		t.Fatalf("风险IP列表查询在加排除后明显变慢：%v -> %v", baseList, newList)
	}
}
