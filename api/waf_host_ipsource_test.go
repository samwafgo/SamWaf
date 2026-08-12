package api

// 真实IP来源配置的入参校验：这是一道安全边界(头名会被当 HTTP 头名使用、可信网段决定信不信任伪造头)，
// 前端传值一律不可信，所以逐条钉死。
//
// 注意：cdn_preset 且未填可信网段的分支会去查中心库(需要 DB)，不在本文件覆盖，
// 这里只测不依赖数据库的路径。

import "testing"

func TestCheckIPSourceConfigRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		cfg  ipSourceConfig
	}{
		{"未知模式", ipSourceConfig{Mode: "whatever"}},
		{"未知CDN厂商", ipSourceConfig{Mode: "cdn_preset", Provider: "not-a-cdn"}},
		{"头名含CRLF", ipSourceConfig{Mode: "header", Header: "X-Real-IP\r\nX-Injected: 1"}},
		{"头名含空格", ipSourceConfig{Mode: "header", Header: "X Real IP"}},
		{"头名含冒号", ipSourceConfig{Mode: "header", Header: "X-Real-IP:1"}},
		{"可信网段非法IP", ipSourceConfig{Mode: "xff_depth", TrustProxies: "1.2.3"}},
		{"可信网段非法CIDR", ipSourceConfig{Mode: "xff_depth", TrustProxies: "10.0.0.0/64"}},
		{"层数越界", ipSourceConfig{Mode: "xff_depth", Depth: 99}},
		{"header模式没填头名", ipSourceConfig{Mode: "header"}},
		{"cdn_preset没选厂商", ipSourceConfig{Mode: "cdn_preset"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := c.cfg
			if err := checkIPSourceConfig(&cfg); err == nil {
				t.Errorf("应当被拒绝，实际通过了: %+v", c.cfg)
			}
		})
	}
}

func TestCheckIPSourceConfigNormalizes(t *testing.T) {
	// 用户常从 CDN 控制台整段粘贴：换行/分号/中文逗号都应规整成英文逗号，空行丢弃
	cfg := ipSourceConfig{
		Mode:         "cdn_preset",
		Provider:     " cloudflare ",
		Header:       "  CF-Connecting-IP  ",
		TrustProxies: "103.21.244.0/22\n 103.22.200.0/22 ;\r\n\n1.2.3.4，10.0.0.0/8",
	}
	if err := checkIPSourceConfig(&cfg); err != nil {
		t.Fatalf("合法配置不该被拒: %v", err)
	}
	if cfg.Provider != "cloudflare" || cfg.Header != "CF-Connecting-IP" {
		t.Errorf("首尾空白未去除: provider=%q header=%q", cfg.Provider, cfg.Header)
	}
	want := "103.21.244.0/22,103.22.200.0/22,1.2.3.4,10.0.0.0/8"
	if cfg.TrustProxies != want {
		t.Errorf("可信网段规整错误\n期望: %s\n实际: %s", want, cfg.TrustProxies)
	}
}

// TestCheckIPSourceConfigCompatModePasses 兼容模式(空)必须畅通无阻，
// 否则存量站点连改个端口都保存不了。
func TestCheckIPSourceConfigCompatModePasses(t *testing.T) {
	cfg := ipSourceConfig{Mode: ""}
	if err := checkIPSourceConfig(&cfg); err != nil {
		t.Errorf("兼容模式不该被拒: %v", err)
	}
}
