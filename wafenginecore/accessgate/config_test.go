package accessgate

import (
	"testing"
	"time"
)

// TestIsAccessEnabled 覆盖三态 × 全局开关的完整矩阵。
//
// 这里最要紧的两条是 ModeInherit 那两行：存量站点的 access_json 是空的，
// 解析出来就是 ModeInherit，而全局默认关闭 —— 所以升级后必须一个请求都不拦。
func TestIsAccessEnabled(t *testing.T) {
	cases := []struct {
		name         string
		mode         int
		globalEnable bool
		want         bool
	}{
		{"继承+全局关=放行(存量站点升级后的默认状态)", ModeInherit, false, false},
		{"继承+全局开=拦截", ModeInherit, true, true},
		{"强制开+全局关=拦截(只保护单个后台站点的场景)", ModeForceOn, false, true},
		{"强制开+全局开=拦截", ModeForceOn, true, true},
		{"强制关+全局关=放行", ModeForceOff, false, false},
		{"强制关+全局开=放行(公开站点豁免)", ModeForceOff, true, false},
		{"非法mode按继承处理+全局关", 99, false, false},
		{"非法mode按继承处理+全局开", -1, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsAccessEnabled(c.mode, c.globalEnable); got != c.want {
				t.Fatalf("IsAccessEnabled(%d, %v) = %v, 期望 %v", c.mode, c.globalEnable, got, c.want)
			}
		})
	}
}

// TestGetNeverNil 快照没发布时也必须能拿到一份「全部关闭」的兜底配置。
// 热路径不做判空，Get 返回 nil 会直接 panic 掉整个 WAF。
func TestGetNeverNil(t *testing.T) {
	SetConfig(nil)
	c := Get()
	if c == nil {
		t.Fatal("Get() 返回了 nil")
	}
	if c.GlobalEnable {
		t.Fatal("兜底配置必须是关闭状态，否则配置加载完成前会整站误拦")
	}
	if c.PathPrefix == "" {
		t.Fatal("兜底配置必须有可用的自服务路径前缀")
	}
}

func TestSetAndGet(t *testing.T) {
	defer SetConfig(nil)
	want := &Config{GlobalEnable: true, PathPrefix: "/x", SessionTTL: time.Hour}
	SetConfig(want)
	if got := Get(); got != want {
		t.Fatalf("Get() 未返回刚发布的快照")
	}
}

func TestBuildExcludePaths(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"空串", "", nil},
		{"只有空白", "  \n\t\n ", nil},
		{"换行分隔并转小写", "/API/Webhook\n/health", []string{"/api/webhook", "/health"}},
		{"逗号分隔", "/a,/b", []string{"/a", "/b"}},
		{"CRLF 与空行混排", "/a\r\n\r\n/b\r\n", []string{"/a", "/b"}},
		{"两侧空白被裁掉", "  /a  \n  /b  ", []string{"/a", "/b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := BuildExcludePaths(c.raw)
			if len(got) != len(c.want) {
				t.Fatalf("BuildExcludePaths(%q) = %v, 期望 %v", c.raw, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("BuildExcludePaths(%q)[%d] = %q, 期望 %q", c.raw, i, got[i], c.want[i])
				}
			}
		})
	}
}

// TestBuildExcludePathsDropsEmpty 空行绝不能变成 "" 前缀。
// 若漏掉这个过滤，用户在白名单框里多敲一个回车就等于把整站认证关掉了 —— 静默、致命。
func TestBuildExcludePathsDropsEmpty(t *testing.T) {
	list := BuildExcludePaths("/a\n\n\n/b")
	for _, item := range list {
		if item == "" {
			t.Fatal("白名单里出现了空前缀，它会匹配所有路径，等于关闭认证")
		}
	}
	if MatchPathPrefix("/secret/admin", list) {
		t.Fatal("/secret/admin 不该命中 [/a /b]")
	}
}

// TestMatchPathPrefix 免认证白名单必须按「路径段边界」匹配，不能是裸字符串前缀。
//
// /healthz 那一条是关键：裸前缀匹配会让一个 /health 白名单顺手把 /healthz 放出去，
// 同理 /admin 会放行 /adminconsole —— 白名单本意是放行一棵子树，不是放行同前缀的兄弟路径。
func TestMatchPathPrefix(t *testing.T) {
	list := []string{"/api/webhook", "/health"}
	cases := []struct {
		p    string
		want bool
	}{
		{"/api/webhook", true},        // 精确命中
		{"/api/webhook/github", true}, // 子路径放行
		{"/health", true},
		{"/healthz", false},           // 同前缀的兄弟路径不能放行
		{"/health-check", false},      //
		{"/api/webhook_admin", false}, //
		{"/api/webhookXYZ", false},    //
		{"/admin", false},
		{"/", false},
	}
	for _, c := range cases {
		if got := MatchPathPrefix(c.p, list); got != c.want {
			t.Fatalf("MatchPathPrefix(%q) = %v, 期望 %v", c.p, got, c.want)
		}
	}
	// 用户按目录习惯写的尾斜杠：子树要放行，同前缀的兄弟路径不放行，
	// 而且「访问目录本身」也必须放行 —— 请求路径进来前已被 path.Clean 去掉尾斜杠，
	// 按字面比会让 /api/ 这条白名单恰好漏掉 /api/ 这个最常见的访问。
	slash := []string{"/static/"}
	if !MatchPathPrefix("/static/a.js", slash) {
		t.Fatal("/static/ 应放行其子路径")
	}
	if !MatchPathPrefix("/static", slash) {
		t.Fatal("/static/ 应放行目录本身(path.Clean 后就是 /static)")
	}
	if MatchPathPrefix("/staticx", slash) {
		t.Fatal("/static/ 不该放行 /staticx")
	}
	// 单个 "/" 是用户显式表达的「整站免认证」，行为保持不变
	if !MatchPathPrefix("/whatever", []string{"/"}) {
		t.Fatal(`"/" 应放行所有路径`)
	}
	// nil 列表必须安全
	if MatchPathPrefix("/anything", nil) {
		t.Fatal("空白名单不该匹配任何路径")
	}
	// 显式空条目也不能匹配一切（BuildExcludePaths 会过滤，这里是第二道保险）
	if MatchPathPrefix("/anything", []string{""}) {
		t.Fatal("空前缀不能匹配所有路径")
	}
}

func TestNormalizePathPrefix(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"", "/samwaf_access"},
		{"/", "/samwaf_access"},
		{"///", "/samwaf_access"},
		{"samwaf_x", "/samwaf_x"},
		{"/samwaf_x/", "/samwaf_x"},
		{"  /SamWaf_X  ", "/samwaf_x"},
	}
	for _, c := range cases {
		if got := NormalizePathPrefix(c.raw); got != c.want {
			t.Fatalf("NormalizePathPrefix(%q) = %q, 期望 %q", c.raw, got, c.want)
		}
	}
}

func TestIsCenterMode(t *testing.T) {
	if (&Config{}).IsCenterMode() {
		t.Fatal("CenterOrigin 为空时 IsCenterMode 必须为 false")
	}
	if (&Config{CenterOrigin: "https://sso.example.com"}).IsCenterMode() {
		t.Fatal("CenterHost 未解析出来时不能当成中心模式，否则会跳到一个拼不出来的地址")
	}
	if !(&Config{CenterOrigin: "https://sso.example.com", CenterHost: "sso.example.com"}).IsCenterMode() {
		t.Fatal("完整配置应判定为中心模式")
	}
	var nilCfg *Config
	if nilCfg.IsCenterMode() {
		t.Fatal("nil 接收者必须安全返回 false")
	}
}
