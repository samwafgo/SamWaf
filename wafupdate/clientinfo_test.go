package wafupdate

import (
	"net/url"
	"runtime"
	"strings"
	"testing"

	"SamWaf/global"
)

// 参数名与顺序是升级源侧日志解析的契约，改了要同步改服务端，故用例锁住
func TestClientQueryShape(t *testing.T) {
	global.GWAF_RELEASE_VERSION = "v1.3.25"
	global.GWAF_USER_CODE = "123456uuid"

	q := buildClientQuery()

	wantPrefix := "v=v1.3.25&u=123456uuid&os=" + runtime.GOOS + "&arch=" + runtime.GOARCH + "&rt="
	if !strings.HasPrefix(q, wantPrefix) {
		t.Fatalf("参数名/顺序变了：\n got  %s\n want %s...", q, wantPrefix)
	}

	values, err := url.ParseQuery(q)
	if err != nil {
		t.Fatalf("拼出来的不是合法查询串: %v", err)
	}
	for _, k := range []string{"v", "u", "os", "arch", "rt"} {
		if values.Get(k) == "" {
			t.Fatalf("缺少参数 %s: %s", k, q)
		}
	}
	// 非容器环境要明确记成 host，不能留空值让日志里出现 rt=
	if rt := values.Get("rt"); rt == "" {
		t.Fatal("rt 不允许为空")
	}
}

// 版本号里的 + / 空格之类必须转义，不能把查询串拼坏
func TestClientQueryEscapes(t *testing.T) {
	global.GWAF_RELEASE_VERSION = "v1.3.25 beta&x=1"
	global.GWAF_USER_CODE = "a b"
	defer func() {
		global.GWAF_RELEASE_VERSION = "v1.0.0"
		global.GWAF_USER_CODE = ""
	}()

	values, err := url.ParseQuery(buildClientQuery())
	if err != nil {
		t.Fatalf("未转义导致查询串非法: %v", err)
	}
	if values.Get("v") != "v1.3.25 beta&x=1" {
		t.Fatalf("版本号被拼坏了: %q", values.Get("v"))
	}
	if values.Get("x") != "" {
		t.Fatal("版本号里的 &x=1 被当成了独立参数，转义失效")
	}
}
