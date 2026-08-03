package api

// 回归 issue #898：编辑名单时把「所属网站」从 A 切到 B，后端只通知了新网站 B，
// 旧网站 A 的引擎内存快照(HostSafe)永远不刷新 —— 表现为「黑名单都删了怎么还在拦截」。
//
// 这里不启动真实引擎，只断言 API 层往 global.GWAF_CHAN_MSG 投了哪些通知：
// 引擎侧收到 msg 之后做什么，由 wafenginecore/checkdenyip_test.go 覆盖。

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/spec"
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// notifyCase 描述一个「按网站分组」的配置模块：怎么种数据、编辑接口是哪个、通知内容长什么样。
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
	// checkContent 断言某网站收到的 Content 表示「有 wantCount 条配置」；
	// 为 nil 表示该模块的通知不带内容（如负载均衡只发信号让引擎重建代理）
	checkContent func(t *testing.T, hostCode string, content interface{}, wantCount int)
}

// sliceChecker 生成「Content 是 []T、且长度为 wantCount」的断言器，适用于所有名单/规则类模块。
func sliceChecker[T any]() func(t *testing.T, hostCode string, content interface{}, wantCount int) {
	return func(t *testing.T, hostCode string, content interface{}, wantCount int) {
		t.Helper()
		list, ok := content.([]T)
		if !ok {
			t.Fatalf("%s 的 Content 类型应为 []%T，实际 %T", hostCode, *new(T), content)
		}
		if len(list) != wantCount {
			t.Errorf("%s 的配置应有 %d 条，实际 %d 条", hostCode, wantCount, len(list))
		}
	}
}

// newTestBase 造一条带租户信息的 BaseOrm，供直接 Create 种子数据用。
// 种子一律走 GORM 直写而不走 service.AddApi：本用例只关心「通知发给了谁」，
// 不想被各 service 新增时的副作用（加密、唯一校验、基线学习等）干扰。
func newTestBase(id string) baseorm.BaseOrm {
	return baseorm.BaseOrm{
		Id:          id,
		USER_CODE:   global.GWAF_USER_CODE,
		Tenant_ID:   global.GWAF_TENANT_ID,
		CREATE_TIME: customtype.JsonTime(time.Now()),
		UPDATE_TIME: customtype.JsonTime(time.Now()),
	}
}

// seedRow 直接落一条种子记录，返回其主键。
func seedRow(t *testing.T, bean interface{}, id string) string {
	t.Helper()
	if err := global.GWAF_LOCAL_DB.Create(bean).Error; err != nil {
		t.Fatalf("种子数据写入失败: %v", err)
	}
	return id
}

// hostOf 编辑请求里该填哪个网站：切换时填 hostB，否则维持 hostA。
func hostOf(changeHost bool) string {
	if changeHost {
		return "hostB"
	}
	return "hostA"
}

func notifyCases() []notifyCase {
	return []notifyCase{
		{
			name:   "IP黑名单",
			tables: []interface{}{&model.IPBlockList{}},
			seed: func(t *testing.T) string {
				id := uuid.GenUUID()
				return seedRow(t, &model.IPBlockList{BaseOrm: newTestBase(id), HostCode: "hostA", Ip: "1.2.3.4"}, id)
			},
			handler: new(WafBlockIpApi).ModifyBlockIpApi,
			editBody: func(id string, changeHost bool) string {
				return `{"id":"` + id + `","host_code":"` + hostOf(changeHost) + `","ip":"1.2.3.4","remarks":"r"}`
			},
			wantType:     enums.ChanTypeBlockIP,
			checkContent: sliceChecker[model.IPBlockList](),
		},
		{
			name:   "IP白名单",
			tables: []interface{}{&model.IPAllowList{}},
			seed: func(t *testing.T) string {
				id := uuid.GenUUID()
				return seedRow(t, &model.IPAllowList{BaseOrm: newTestBase(id), HostCode: "hostA", Ip: "1.2.3.4"}, id)
			},
			handler: new(WafAllowIpApi).ModifyAllowIpApi,
			editBody: func(id string, changeHost bool) string {
				return `{"id":"` + id + `","host_code":"` + hostOf(changeHost) + `","ip":"1.2.3.4","remarks":"r"}`
			},
			wantType:     enums.ChanTypeAllowIP,
			checkContent: sliceChecker[model.IPAllowList](),
		},
		{
			name:   "URL黑名单",
			tables: []interface{}{&model.URLBlockList{}},
			seed: func(t *testing.T) string {
				id := uuid.GenUUID()
				return seedRow(t, &model.URLBlockList{BaseOrm: newTestBase(id), HostCode: "hostA", CompareType: "前缀匹配", Url: "/admin"}, id)
			},
			handler: new(WafBlockUrlApi).ModifyBlockUrlApi,
			editBody: func(id string, changeHost bool) string {
				return `{"id":"` + id + `","host_code":"` + hostOf(changeHost) + `","compare_type":"前缀匹配","url":"/admin","remarks":"r"}`
			},
			wantType:     enums.ChanTypeBlockURL,
			checkContent: sliceChecker[model.URLBlockList](),
		},
		{
			name:   "URL白名单",
			tables: []interface{}{&model.URLAllowList{}},
			seed: func(t *testing.T) string {
				id := uuid.GenUUID()
				return seedRow(t, &model.URLAllowList{BaseOrm: newTestBase(id), HostCode: "hostA", CompareType: "前缀匹配", Url: "/health"}, id)
			},
			handler: new(WafAllowUrlApi).ModifyAllowUrlApi,
			editBody: func(id string, changeHost bool) string {
				return `{"id":"` + id + `","host_code":"` + hostOf(changeHost) + `","compare_type":"前缀匹配","url":"/health","remarks":"r"}`
			},
			wantType:     enums.ChanTypeAllowURL,
			checkContent: sliceChecker[model.URLAllowList](),
		},
		{
			name:   "隐私保护URL",
			tables: []interface{}{&model.LDPUrl{}},
			seed: func(t *testing.T) string {
				id := uuid.GenUUID()
				return seedRow(t, &model.LDPUrl{BaseOrm: newTestBase(id), HostCode: "hostA", CompareType: "前缀匹配", Url: "/ldp"}, id)
			},
			handler: new(WafLdpUrlApi).ModifyLdpUrlApi,
			editBody: func(id string, changeHost bool) string {
				return `{"id":"` + id + `","host_code":"` + hostOf(changeHost) + `","compare_type":"前缀匹配","url":"/ldp","remarks":"r"}`
			},
			wantType:     enums.ChanTypeLdp,
			checkContent: sliceChecker[model.LDPUrl](),
		},
		{
			name:   "HTTP认证",
			tables: []interface{}{&model.HttpAuthBase{}},
			seed: func(t *testing.T) string {
				id := uuid.GenUUID()
				return seedRow(t, &model.HttpAuthBase{BaseOrm: newTestBase(id), HostCode: "hostA", UserName: "u1", Password: "p1"}, id)
			},
			handler: new(WafHttpAuthBaseApi).ModifyApi,
			editBody: func(id string, changeHost bool) string {
				return `{"id":"` + id + `","host_code":"` + hostOf(changeHost) + `","user_name":"u1","password":"p1"}`
			},
			wantType:     enums.ChanTypeHttpauth,
			checkContent: sliceChecker[model.HttpAuthBase](),
		},
		{
			name:   "缓存规则",
			tables: []interface{}{&model.CacheRule{}},
			seed: func(t *testing.T) string {
				id := uuid.GenUUID()
				return seedRow(t, &model.CacheRule{BaseOrm: newTestBase(id), HostCode: "hostA", RuleName: "c1",
					RuleType: 1, RuleContent: ".jpg", ParamType: 1, CacheTime: 60, Priority: 1, RequestMethod: "GET"}, id)
			},
			handler: new(WafCacheRuleApi).ModifyApi,
			editBody: func(id string, changeHost bool) string {
				return `{"id":"` + id + `","host_code":"` + hostOf(changeHost) + `","rule_name":"c1","rule_type":1,` +
					`"rule_content":".jpg","param_type":1,"cache_time":60,"priority":1,"request_method":"GET","remarks":"r"}`
			},
			wantType:     enums.ChanTypeCacheRule,
			checkContent: sliceChecker[model.CacheRule](),
		},
		{
			name:   "网页防篡改",
			tables: []interface{}{&model.TamperRule{}},
			seed: func(t *testing.T) string {
				id := uuid.GenUUID()
				return seedRow(t, &model.TamperRule{BaseOrm: newTestBase(id), HostCode: "hostA", Url: "/index.html",
					RuleName: "t1", IsEnable: 1, IgnoreQuery: 1}, id)
			},
			handler: new(WafTamperRuleApi).ModifyApi,
			editBody: func(id string, changeHost bool) string {
				return `{"id":"` + id + `","host_code":"` + hostOf(changeHost) + `","url":"/index.html","rule_name":"t1",` +
					`"is_enable":1,"ignore_query":1,"remarks":"r"}`
			},
			wantType:     enums.ChanTypeTamperRule,
			checkContent: sliceChecker[model.TamperRule](),
		},
		{
			name:   "路径规则",
			tables: []interface{}{&model.HostPathRule{}},
			seed: func(t *testing.T) string {
				id := uuid.GenUUID()
				return seedRow(t, &model.HostPathRule{BaseOrm: newTestBase(id), HostCode: "hostA", RuleName: "p1",
					Path: "/api", MatchType: 1, Priority: 100, TargetType: 1, RemoteHost: "127.0.0.1", RemotePort: 8080}, id)
			},
			handler: new(WafHostPathRuleApi).ModifyApi,
			editBody: func(id string, changeHost bool) string {
				return `{"id":"` + id + `","host_code":"` + hostOf(changeHost) + `","rule_name":"p1","path":"/api",` +
					`"match_type":1,"priority":100,"target_type":1,"remote_host":"127.0.0.1","remote_port":8080,"remarks":"r"}`
			},
			wantType:     enums.ChanTypeHostPathRule,
			checkContent: sliceChecker[model.HostPathRule](),
		},
		{
			name:   "CC防护",
			tables: []interface{}{&model.AntiCC{}},
			seed: func(t *testing.T) string {
				id := uuid.GenUUID()
				return seedRow(t, &model.AntiCC{BaseOrm: newTestBase(id), HostCode: "hostA",
					Rate: 10, Limit: 100, LockIPMinutes: 5, LimitMode: "rate"}, id)
			},
			handler: new(WafAntiCCApi).ModifyAntiCCApi,
			editBody: func(id string, changeHost bool) string {
				return `{"id":"` + id + `","host_code":"` + hostOf(changeHost) + `","rate":10,"limit":100,` +
					`"lock_ip_minutes":5,"limit_mode":"rate","remarks":"r"}`
			},
			wantType: enums.ChanTypeAnticc,
			// CC 防护每站只有一条，Content 是结构体而不是切片：
			// 旧网站的配置被移走后查不到记录，引擎收到零值 AntiCC 就会关掉该站的 CC 防护。
			checkContent: func(t *testing.T, hostCode string, content interface{}, wantCount int) {
				t.Helper()
				bean, ok := content.(model.AntiCC)
				if !ok {
					t.Fatalf("%s 的 Content 类型应为 model.AntiCC，实际 %T", hostCode, content)
				}
				if wantCount > 0 && bean.Id == "" {
					t.Errorf("%s 应收到真实的 CC 配置，实际是零值", hostCode)
				}
				if wantCount == 0 && bean.Id != "" {
					t.Errorf("%s 的 CC 配置已移走，应收到零值以关闭防护，实际 Id=%s", hostCode, bean.Id)
				}
			},
		},
		{
			name:   "负载均衡",
			tables: []interface{}{&model.LoadBalance{}},
			seed: func(t *testing.T) string {
				id := uuid.GenUUID()
				return seedRow(t, &model.LoadBalance{BaseOrm: newTestBase(id), HostCode: "hostA",
					Remote_ip: "127.0.0.1", Remote_port: 8080, Weight: 1}, id)
			},
			handler: new(WafLoadBalanceApi).ModifyApi,
			editBody: func(id string, changeHost bool) string {
				return `{"id":"` + id + `","host_code":"` + hostOf(changeHost) + `","remote_ip":"127.0.0.1","remote_port":8080,"weight":1,"remarks":"r"}`
			},
			wantType: enums.ChanTypeLoadBalance,
			// 负载均衡的通知不带内容，引擎收到后清空该站已建的反向代理并懒重建
			checkContent: nil,
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

			oldMsg := findMsg(msgs, "hostA")
			if oldMsg == nil {
				t.Fatalf("没有收到旧网站 hostA 的通知，旧网站的引擎缓存不会被刷新（issue #898）：%+v", msgs)
			}
			if oldMsg.Type != tc.wantType {
				t.Errorf("旧网站通知类型应为 %d，实际 %d", tc.wantType, oldMsg.Type)
			}

			if tc.checkContent != nil {
				tc.checkContent(t, "新网站 hostB", newMsg.Content, 1)
				tc.checkContent(t, "旧网站 hostA", oldMsg.Content, 0)
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

	idA, idB := uuid.GenUUID(), uuid.GenUUID()
	seedRow(t, &model.IPBlockList{BaseOrm: newTestBase(idA), HostCode: "hostA", Ip: "1.1.1.1"}, idA)
	seedRow(t, &model.IPBlockList{BaseOrm: newTestBase(idB), HostCode: "hostB", Ip: "2.2.2.2"}, idB)
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

// notifyHelperExemptHandlers 允许直接调用单参数 NotifyWaf 的编辑类处理函数白名单。
// 只有「确定不会把记录换到另一个网站」的接口才能进来，加之前先想清楚：
// 一旦这个接口能改 host_code，直接调用 NotifyWaf 就会复现 issue #898。
var notifyHelperExemptHandlers = map[string]string{
	// 编辑的就是网站本身，不存在「换到另一个网站」；且它的 NotifyWaf 已自行接收旧 Host 做对比
	"ModifyHostApi": "编辑网站自身，非按网站分组的子配置",
}

// TestEditHandlersMustUseNotifyHelper 源码级护栏：
// 所有绑定 request.*EditReq 的编辑接口，都必须通过 notifyWafHostChanged 通知引擎，
// 不允许直接调用 w.NotifyWaf(...)——直接调用就等于「只通知新网站」，正是 issue #898 的成因。
//
// 这条用例的价值在于覆盖**将来新增**的模块：新写一个按网站分组的配置功能时，
// 只要照抄了老写法，这里就会红，而不用等用户报障。
func TestEditHandlersMustUseNotifyHelper(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("解析 api 包源码失败: %v", err)
	}

	var bad []string
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				if !bindsEditReq(fn) {
					continue
				}
				if _, exempt := notifyHelperExemptHandlers[fn.Name.Name]; exempt {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					// 只盯「单参数 NotifyWaf(hostCode)」：无参版本(如敏感词)本就与网站无关，
					// 多参版本(如网站自身)另有语义，都不在本护栏范围内。
					if ok && sel.Sel.Name == "NotifyWaf" && len(call.Args) == 1 {
						bad = append(bad, fmt.Sprintf("%s: %s 在 %s",
							filepath.Base(path), fn.Name.Name, fset.Position(call.Pos())))
					}
					return true
				})
			}
		}
	}

	if len(bad) > 0 {
		t.Errorf("下列编辑接口直接调用了 NotifyWaf，编辑时若切换网站会导致旧网站缓存不刷新（issue #898）。\n"+
			"请改成：编辑前 bean := <service>.GetDetailByIdApi(req.Id)，成功后 notifyWafHostChanged(w.NotifyWaf, bean.HostCode, req.HostCode)\n%s",
			strings.Join(bad, "\n"))
	}
}

// bindsEditReq 判断函数体里是否声明了 var req request.XxxEditReq（即这是一个编辑接口）。
func bindsEditReq(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || vs.Type == nil {
			return true
		}
		sel, ok := vs.Type.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if ok && pkgIdent.Name == "request" && strings.HasSuffix(sel.Sel.Name, "EditReq") {
			found = true
			return false
		}
		return true
	})
	return found
}
