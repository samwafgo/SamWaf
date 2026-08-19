package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"path/filepath"
	"testing"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openTokenTestDB 打开一个临时 sqlite 库，建 token_infos 表，并按生产方式注册租户查询回调。
func openTokenTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlitedriver.Open(filepath.Join(t.TempDir(), "token_test.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("打开 sqlite 测试库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.TokenInfo{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	_ = db.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", func(d *gorm.DB) {
		d.Where("tenant_id = ? and user_code = ?", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
	})
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func seedTokenRow(t *testing.T, db *gorm.DB, account, loginType, token string) {
	t.Helper()
	row := &model.TokenInfo{
		BaseOrm: baseorm.BaseOrm{
			Id:          "old-row-id",
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now().Add(-time.Hour)),
			UPDATE_TIME: customtype.JsonTime(time.Now().Add(-time.Hour)),
		},
		LoginAccount: account,
		AccessToken:  token,
		LoginType:    loginType,
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("预置旧令牌行失败: %v", err)
	}
}

// TestIssue938_旧行残留时签发的令牌与返回给前端的不是同一个
//
// 复现 issue #938："登录成功但立刻被弹回登录页、无限循环、没有任何日志"。
//
// 登录接口的写法是：
//
//	accessToken := utils.Md5String(uuid.GenUUID())          // ① 本地生成
//	tokenInfo := AddApiWithFingerprintAndType(..., accessToken, ...)  // ② 落库后**重新查库**
//	GCACHE_WAFCACHE.SetWithTTl(CACHE_TOKEN+accessToken, ...) // ③ 缓存用 ①
//	response(LoginRep{AccessToken: tokenInfo.AccessToken})   // ④ 返回给前端的是 ②
//
// ③ 和 ④ 是两个不同的来源。只要 ② 查回来的不是刚插入的那一行，
// 前端拿到的令牌就永远不在缓存里 → 每个请求都 401「令牌过期」→ 跳登录 → 死循环。
// 而 401 那条分支没有任何日志，所以现象就是"点登录之后什么日志都没有"。
//
// 本用例用"库里还残留同账号同类型的旧行"来触发（旧行删除失败/删除报错被忽略即会如此），
// 重查用的是 Limit(1) 且**没有 ORDER BY**，返回哪一行由存储引擎决定。
//
// 修复前本用例实测失败，输出为：
//
//	本次签发(写进缓存的)令牌 = NEW_ISSUED_TOKEN
//	重新查库返回(下发给前端的)令牌 = OLD_DEAD_TOKEN
//
// 修复后 AddApiWithFingerprintAndType 直接返回刚插入的记录，不再重查。
func TestIssue938_旧行残留时签发的令牌与返回给前端的不是同一个(t *testing.T) {
	global.GWAF_USER_CODE = "test-user-code"
	global.GWAF_TENANT_ID = "test-tenant"
	db := openTokenTestDB(t)
	old := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = db
	t.Cleanup(func() { global.GWAF_LOCAL_DB = old })

	const account, loginType = "admin", "web"
	seedTokenRow(t, db, account, loginType, "OLD_DEAD_TOKEN")

	const issued = "NEW_ISSUED_TOKEN"
	got, err := WafTokenInfoServiceApp.AddApiWithFingerprintAndType(account, issued, "127.0.0.1", "", loginType, "")
	if err != nil {
		t.Fatalf("签发令牌不应报错: %v", err)
	}

	t.Logf("本次签发(写进缓存的)令牌 = %s", issued)
	t.Logf("接口返回(下发给前端的)令牌 = %s", got.AccessToken)

	if got.AccessToken != issued {
		t.Fatalf("下发给前端的令牌是 %q，而写进缓存的是 %q —— 前端会拿着一个缓存里不存在的令牌，"+
			"之后每个请求都被判「令牌过期」并跳回登录页，且服务端不打任何日志", got.AccessToken, issued)
	}
}

// TestIssue938_落库失败时登录仍然返回空令牌且调用方无从察觉
//
// AddApiWithFingerprintAndType 里 `global.GWAF_LOCAL_DB.Create(bean)` 的返回值被完全忽略，
// 随后的重查在插入失败时自然也查不到 → 返回零值结构体 → 登录接口照样回 200「登录成功」，
// 只是 access_token 是空串。前端 localStorage 存了空值，后续请求不带 X-Token，
// 服务端命中「无 token」分支，回「鉴权失败」——同样没有任何 Error 级日志。
//
// 这解释了报告人说的"偶尔提示鉴权失败、偶尔提示令牌过期"。
func TestIssue938_落库失败时登录仍然返回空令牌且调用方无从察觉(t *testing.T) {
	global.GWAF_USER_CODE = "test-user-code"
	global.GWAF_TENANT_ID = "test-tenant"
	db := openTokenTestDB(t)
	old := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = db
	t.Cleanup(func() { global.GWAF_LOCAL_DB = old })

	// 模拟"写库这一步失败"（真实场景可能是约束冲突、字段不兼容、库不可写等）
	if err := db.Migrator().DropTable(&model.TokenInfo{}); err != nil {
		t.Fatalf("准备失败场景出错: %v", err)
	}

	got, err := WafTokenInfoServiceApp.AddApiWithFingerprintAndType("admin", "NEW_ISSUED_TOKEN", "127.0.0.1", "", "web", "")

	if err == nil {
		t.Fatalf("写库失败必须把 error 返回给调用方，否则登录接口会带着空令牌回「登录成功」。got=%+v", got)
	}
	if got != nil {
		t.Fatalf("写库失败时不应返回半成品令牌记录，got=%+v", got)
	}
	t.Logf("写库失败已被感知: %v", err)
}

// TestIssue938_登录前的旧令牌清理是否真的删掉了旧行
//
// 登录接口在签发新令牌前会走这两步清理旧会话：
//
//	allTokenInfo := GetAllTokenInfoByLoginAccountAndType(account, loginType)
//	for ... { DelApiByAccountAndType(account, loginType) }
//
// 只要这一步没把旧行删干净，就构成上面那个用例的前提条件。
func TestIssue938_登录前的旧令牌清理是否真的删掉了旧行(t *testing.T) {
	global.GWAF_USER_CODE = "test-user-code"
	global.GWAF_TENANT_ID = "test-tenant"
	db := openTokenTestDB(t)
	old := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = db
	t.Cleanup(func() { global.GWAF_LOCAL_DB = old })

	const account, loginType = "admin", "web"
	seedTokenRow(t, db, account, loginType, "OLD_DEAD_TOKEN")

	all := WafTokenInfoServiceApp.GetAllTokenInfoByLoginAccountAndType(account, loginType)
	t.Logf("清理前查到旧行数量 = %d", len(all))
	for i := 0; i < len(all); i++ {
		if all[i].Id != "" {
			err := WafTokenInfoServiceApp.DelApiByAccountAndType(all[i].LoginAccount, all[i].LoginType)
			t.Logf("DelApiByAccountAndType 返回 err = %v", err)
		}
	}

	var left int64
	db.Model(&model.TokenInfo{}).Where("login_account = ?", account).Count(&left)
	t.Logf("清理后剩余行数 = %d", left)
	if left != 0 {
		t.Fatalf("旧行没删掉，剩余 %d 行 —— 这正是上一个用例的前提条件", left)
	}
}
