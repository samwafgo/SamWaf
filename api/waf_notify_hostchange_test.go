package api

// 回归 issue #898：编辑名单时把「所属网站」从 A 切到 B，后端只通知了新网站 B，
// 旧网站 A 的引擎内存快照(HostSafe)永远不刷新 —— 表现为「黑名单都删了怎么还在拦截」。
//
// 这里不启动真实引擎，只断言 API 层往 global.GWAF_CHAN_MSG 投了哪些通知：
// 引擎侧收到 msg 之后做什么，由 wafenginecore/checkdenyip_test.go 覆盖。

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openNotifyTestDB 打开一个临时 sqlite 测试库（用例结束自动关闭）。
func openNotifyTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "notify_test.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("打开 sqlite 测试库失败: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// setupNotifyTestEnv 建表 + 注册与生产一致的租户过滤回调 + 临时替换全局对象。
// 注意 GWAF_CHAN_MSG 也要换成本用例私有的通道：既不污染真实通道，也避免读到别的用例的残留消息。
func setupNotifyTestEnv(t *testing.T, models ...interface{}) {
	t.Helper()
	db := openNotifyTestDB(t)

	// 建表（迁移阶段尚未注册租户回调）
	if err := db.AutoMigrate(models...); err != nil {
		t.Fatalf("AutoMigrate 失败: %v", err)
	}

	// 注册与生产一致的租户过滤回调（迁移之后）
	if err := db.Callback().Query().Before("gorm:query").
		Register("tenant_plugin:before_query", func(d *gorm.DB) {
			d.Where("tenant_id = ? and user_code=? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
		}); err != nil {
		t.Fatalf("注册租户回调失败: %v", err)
	}

	oldDB, oldTenant, oldUser, oldChan := global.GWAF_LOCAL_DB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE, global.GWAF_CHAN_MSG
	global.GWAF_LOCAL_DB = db
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "SamWafCom", "user-uuid-0001"
	global.GWAF_CHAN_MSG = make(chan spec.ChanCommonHost, 10)
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB = oldDB
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
		global.GWAF_CHAN_MSG = oldChan
	})
}

// drainChanMsg 非阻塞排空当前通道里的全部通知。
func drainChanMsg() []spec.ChanCommonHost {
	var msgs []spec.ChanCommonHost
	for {
		select {
		case m := <-global.GWAF_CHAN_MSG:
			msgs = append(msgs, m)
		default:
			return msgs
		}
	}
}

// findMsg 按 HostCode 找通知（不按下标，断言就不会绑定新旧网站的通知顺序）。
func findMsg(msgs []spec.ChanCommonHost, hostCode string) *spec.ChanCommonHost {
	for i := range msgs {
		if msgs[i].HostCode == hostCode {
			return &msgs[i]
		}
	}
	return nil
}

// doJSONPost 用 httptest 直接打一个处理函数。
func doJSONPost(t *testing.T, handler gin.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/t", handler)
	req, err := http.NewRequest(http.MethodPost, "/t", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// notifyCase 描述一个名单模块：怎么种数据、编辑接口是哪个、通知内容怎么数。
type notifyCase struct {
	name string
	// tables 需要建的表
	tables []interface{}
	// seed 在 hostA 上种一条记录，返回其主键 Id
	seed func(t *testing.T) string
	// handler 编辑接口
	handler gin.HandlerFunc
	// editBody 生成编辑请求体：changeHost 为 true 时把网站切到 hostB，否则保持 hostA 只改备注
	editBody func(id string, changeHost bool) string
	// wantType 期望的通道消息类型
	wantType int
	// countContent 断言 Content 类型并返回条目数
	countContent func(t *testing.T, content interface{}) int
}

func seedIdOf(t *testing.T, dst interface{}, where string, args ...interface{}) string {
	t.Helper()
	if err := global.GWAF_LOCAL_DB.Where(where, args...).First(dst).Error; err != nil {
		t.Fatalf("种子数据回查失败: %v", err)
	}
	switch v := dst.(type) {
	case *model.IPBlockList:
		return v.Id
	case *model.IPAllowList:
		return v.Id
	case *model.URLBlockList:
		return v.Id
	case *model.URLAllowList:
		return v.Id
	}
	t.Fatalf("未知的种子类型 %T", dst)
	return ""
}

func notifyCases() []notifyCase {
	return []notifyCase{
		{
			name:   "IP黑名单",
			tables: []interface{}{&model.IPBlockList{}},
			seed: func(t *testing.T) string {
				if err := wafIpBlockService.AddApi(request.WafBlockIpAddReq{HostCode: "hostA", Ip: "1.2.3.4"}); err != nil {
					t.Fatalf("种子新增失败: %v", err)
				}
				return seedIdOf(t, &model.IPBlockList{}, "host_code=? and ip=?", "hostA", "1.2.3.4")
			},
			handler: new(WafBlockIpApi).ModifyBlockIpApi,
			editBody: func(id string, changeHost bool) string {
				host := "hostA"
				if changeHost {
					host = "hostB"
				}
				return `{"id":"` + id + `","host_code":"` + host + `","ip":"1.2.3.4","remarks":"r"}`
			},
			wantType: enums.ChanTypeBlockIP,
			countContent: func(t *testing.T, content interface{}) int {
				list, ok := content.([]model.IPBlockList)
				if !ok {
					t.Fatalf("Content 类型应为 []model.IPBlockList，实际 %T", content)
				}
				return len(list)
			},
		},
		{
			name:   "IP白名单",
			tables: []interface{}{&model.IPAllowList{}},
			seed: func(t *testing.T) string {
				if err := wafIpAllowService.AddApi(request.WafAllowIpAddReq{HostCode: "hostA", Ip: "1.2.3.4"}); err != nil {
					t.Fatalf("种子新增失败: %v", err)
				}
				return seedIdOf(t, &model.IPAllowList{}, "host_code=? and ip=?", "hostA", "1.2.3.4")
			},
			handler: new(WafAllowIpApi).ModifyAllowIpApi,
			editBody: func(id string, changeHost bool) string {
				host := "hostA"
				if changeHost {
					host = "hostB"
				}
				return `{"id":"` + id + `","host_code":"` + host + `","ip":"1.2.3.4","remarks":"r"}`
			},
			wantType: enums.ChanTypeAllowIP,
			countContent: func(t *testing.T, content interface{}) int {
				list, ok := content.([]model.IPAllowList)
				if !ok {
					t.Fatalf("Content 类型应为 []model.IPAllowList，实际 %T", content)
				}
				return len(list)
			},
		},
		{
			name:   "URL黑名单",
			tables: []interface{}{&model.URLBlockList{}},
			seed: func(t *testing.T) string {
				if err := wafUrlBlockService.AddApi(request.WafBlockUrlAddReq{HostCode: "hostA", CompareType: "前缀匹配", Url: "/admin"}); err != nil {
					t.Fatalf("种子新增失败: %v", err)
				}
				return seedIdOf(t, &model.URLBlockList{}, "host_code=? and url=?", "hostA", "/admin")
			},
			handler: new(WafBlockUrlApi).ModifyBlockUrlApi,
			editBody: func(id string, changeHost bool) string {
				host := "hostA"
				if changeHost {
					host = "hostB"
				}
				return `{"id":"` + id + `","host_code":"` + host + `","compare_type":"前缀匹配","url":"/admin","remarks":"r"}`
			},
			wantType: enums.ChanTypeBlockURL,
			countContent: func(t *testing.T, content interface{}) int {
				list, ok := content.([]model.URLBlockList)
				if !ok {
					t.Fatalf("Content 类型应为 []model.URLBlockList，实际 %T", content)
				}
				return len(list)
			},
		},
		{
			name:   "URL白名单",
			tables: []interface{}{&model.URLAllowList{}},
			seed: func(t *testing.T) string {
				if err := wafUrlAllowService.AddApi(request.WafAllowUrlAddReq{HostCode: "hostA", CompareType: "前缀匹配", Url: "/health"}); err != nil {
					t.Fatalf("种子新增失败: %v", err)
				}
				return seedIdOf(t, &model.URLAllowList{}, "host_code=? and url=?", "hostA", "/health")
			},
			handler: new(WafAllowUrlApi).ModifyAllowUrlApi,
			editBody: func(id string, changeHost bool) string {
				host := "hostA"
				if changeHost {
					host = "hostB"
				}
				return `{"id":"` + id + `","host_code":"` + host + `","compare_type":"前缀匹配","url":"/health","remarks":"r"}`
			},
			wantType: enums.ChanTypeAllowURL,
			countContent: func(t *testing.T, content interface{}) int {
				list, ok := content.([]model.URLAllowList)
				if !ok {
					t.Fatalf("Content 类型应为 []model.URLAllowList，实际 %T", content)
				}
				return len(list)
			},
		},
	}
}

// TestModifyApi_ChangeHost_ShouldNotifyOldAndNewHost 编辑时切换网站，必须同时通知新旧两个网站。
// 修复前：只通知新网站，旧网站的内存名单永远是脏的（issue #898）。
func TestModifyApi_ChangeHost_ShouldNotifyOldAndNewHost(t *testing.T) {
	for _, tc := range notifyCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			setupNotifyTestEnv(t, tc.tables...)
			id := tc.seed(t)
			drainChanMsg() // 清掉基线，只看编辑这一步产生的通知

			rec := doJSONPost(t, tc.handler, tc.editBody(id, true))
			if rec.Code != http.StatusOK {
				t.Fatalf("编辑接口应返回 200，实际 %d，响应 %s", rec.Code, rec.Body.String())
			}

			msgs := drainChanMsg()
			if len(msgs) != 2 {
				t.Fatalf("切换网站后期望收到 2 条通知（新网站 hostB + 旧网站 hostA），实际 %d 条：%+v", len(msgs), msgs)
			}

			newMsg := findMsg(msgs, "hostB")
			if newMsg == nil {
				t.Fatalf("没有收到新网站 hostB 的通知：%+v", msgs)
			}
			if newMsg.Type != tc.wantType {
				t.Errorf("新网站通知类型应为 %d，实际 %d", tc.wantType, newMsg.Type)
			}
			if n := tc.countContent(t, newMsg.Content); n != 1 {
				t.Errorf("新网站 hostB 的名单应有 1 条，实际 %d 条", n)
			}

			oldMsg := findMsg(msgs, "hostA")
			if oldMsg == nil {
				t.Fatalf("没有收到旧网站 hostA 的通知，旧网站的引擎缓存不会被刷新（issue #898）：%+v", msgs)
			}
			if oldMsg.Type != tc.wantType {
				t.Errorf("旧网站通知类型应为 %d，实际 %d", tc.wantType, oldMsg.Type)
			}
			if n := tc.countContent(t, oldMsg.Content); n != 0 {
				t.Errorf("旧网站 hostA 的名单应已清空（0 条），实际 %d 条", n)
			}
		})
	}
}

// TestModifyApi_SameHost_ShouldNotifyOnce 不切换网站时只能发一条通知。
// 防止有人把 helper「简化」成无条件双发，让每次普通编辑的通道流量翻倍。
func TestModifyApi_SameHost_ShouldNotifyOnce(t *testing.T) {
	for _, tc := range notifyCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			setupNotifyTestEnv(t, tc.tables...)
			id := tc.seed(t)
			drainChanMsg()

			rec := doJSONPost(t, tc.handler, tc.editBody(id, false))
			if rec.Code != http.StatusOK {
				t.Fatalf("编辑接口应返回 200，实际 %d，响应 %s", rec.Code, rec.Body.String())
			}

			msgs := drainChanMsg()
			if len(msgs) != 1 {
				t.Fatalf("网站没变时应只发 1 条通知，实际 %d 条：%+v", len(msgs), msgs)
			}
			if msgs[0].HostCode != "hostA" {
				t.Errorf("通知的网站应为 hostA，实际 %s", msgs[0].HostCode)
			}
		})
	}
}

// TestDelAllBlockIpApi_ScopedByHost 「清空所有」必须限定在指定网站内。
// 修复前：DelAllApi 忽略 host_code，把当前租户所有网站的 IP 黑名单一起删了。
func TestDelAllBlockIpApi_ScopedByHost(t *testing.T) {
	setupNotifyTestEnv(t, &model.IPBlockList{})

	if err := wafIpBlockService.AddApi(request.WafBlockIpAddReq{HostCode: "hostA", Ip: "1.1.1.1"}); err != nil {
		t.Fatalf("种子新增失败: %v", err)
	}
	if err := wafIpBlockService.AddApi(request.WafBlockIpAddReq{HostCode: "hostB", Ip: "2.2.2.2"}); err != nil {
		t.Fatalf("种子新增失败: %v", err)
	}
	drainChanMsg()

	rec := doJSONPost(t, new(WafBlockIpApi).DelAllBlockIpApi, `{"host_code":"hostA"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("清空接口应返回 200，实际 %d，响应 %s", rec.Code, rec.Body.String())
	}

	var countA, countB int64
	global.GWAF_LOCAL_DB.Model(&model.IPBlockList{}).Where("host_code=?", "hostA").Count(&countA)
	global.GWAF_LOCAL_DB.Model(&model.IPBlockList{}).Where("host_code=?", "hostB").Count(&countB)
	if countA != 0 {
		t.Errorf("hostA 的 IP 黑名单应被清空，实际还剩 %d 条", countA)
	}
	if countB != 1 {
		t.Errorf("只清空 hostA 时 hostB 的记录必须保留，实际剩 %d 条（越权删除）", countB)
	}
}
