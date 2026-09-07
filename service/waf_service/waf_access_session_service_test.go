package waf_service

import (
	"SamWaf/wafenginecore/accessgate"
	"testing"
)

// TestAccessStateMatchBindings 是一条回归测试。
//
// ValidateToken 有两条路径：命中正向缓存的快路径、回数据库的慢路径。
// 缓存键只有 token_code，不含域名。早期版本的快路径直接返回缓存结果，
// 于是三个绑定校验（域名/IP/设备指纹）在缓存有效期内全部失效：
//
//	① 在自己有权限的 a.com 上正常访问一次 → 令牌进入正向缓存
//	② 60 秒内拿同一个 Cookie 带 Host: b.com 请求 → 命中缓存 → 放行了无权访问的站点
//	③ 循环 ①② 即可无限期维持
//
// 同一个洞也让 bind_ip / bind_fingerprint 形同虚设。
// 修复办法是把绑定条件一起放进缓存，两条路径都调用本函数做同一套判定。
func TestAccessStateMatchBindings(t *testing.T) {
	st := &AccessState{
		SessionCode: "sess",
		AccountName: "u",
		Host:        "a.example.com",
		HostCode:    "site-a",
		ClientIP:    "1.2.3.4",
		Fingerprint: "fp-a",
	}

	noBind := &accessgate.Config{}
	bindAll := &accessgate.Config{BindIP: true, BindFingerprint: true}

	cases := []struct {
		name                      string
		host, code, clientIP, fpr string
		cfg                       *accessgate.Config
		want                      bool
	}{
		{"完全匹配", "a.example.com", "site-a", "1.2.3.4", "fp-a", noBind, true},
		{"域名大小写不敏感", "A.Example.Com", "site-a", "1.2.3.4", "fp-a", noBind, true},
		{"跨域名必须拒绝(即便未开IP/指纹绑定)", "b.example.com", "site-a", "1.2.3.4", "fp-a", noBind, false},
		{"未开IP绑定时换IP放行", "a.example.com", "site-a", "9.9.9.9", "fp-a", noBind, true},
		{"开了IP绑定后换IP拒绝", "a.example.com", "site-a", "9.9.9.9", "fp-a", bindAll, false},
		{"未开指纹绑定时换设备放行", "a.example.com", "site-a", "1.2.3.4", "fp-b", noBind, true},
		{"开了指纹绑定后换设备拒绝", "a.example.com", "site-a", "1.2.3.4", "fp-b", bindAll, false},

		// 归一化会让「不同站点记录 → 同一个 host 串」，典型是 oa.x:80(HTTP 站)
		// 与 oa.x:443(HTTPS 站)，浏览器两边都发 Host: oa.x。
		// 只比 host 串的话，A 站点的令牌能直接在 B 站点用。
		{"host 串相同但站点记录不同，必须拒绝", "a.example.com", "site-b", "1.2.3.4", "fp-a", noBind, false},
		{"请求侧拿不到站点码时 fail-closed", "a.example.com", "", "1.2.3.4", "fp-a", noBind, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := st.matchBindings(c.host, c.code, c.clientIP, c.fpr, c.cfg); got != c.want {
				t.Fatalf("matchBindings(%q,%q,%q,%q) = %v, 期望 %v",
					c.host, c.code, c.clientIP, c.fpr, got, c.want)
			}
		})
	}

	// 令牌侧缺站点码（数据被手工改过）同样 fail-closed
	noCode := &AccessState{Host: "a.example.com"}
	if noCode.matchBindings("a.example.com", "site-a", "1.2.3.4", "fp", noBind) {
		t.Fatal("令牌未记录站点码时不应放行")
	}
}

// TestAccessStateMatchBindingsEmptyBinding 令牌签发时若没记录 IP/指纹（老数据、
// 或签发时这两个开关是关的），后来打开开关不应把这些存量会话全部踢掉。
// 空值视为"未绑定"，只有非空才比对。
func TestAccessStateMatchBindingsEmptyBinding(t *testing.T) {
	st := &AccessState{Host: "a.example.com", HostCode: "site-a"}
	cfg := &accessgate.Config{BindIP: true, BindFingerprint: true}
	if !st.matchBindings("a.example.com", "site-a", "1.2.3.4", "fp", cfg) {
		t.Fatal("签发时未记录 IP/指纹的存量令牌，不应在开启绑定后立即失效")
	}
}

// TestHashAccessCode 入库与缓存键用的都是明文的 sha256，明文永不落库。
func TestHashAccessCode(t *testing.T) {
	a := HashAccessCode("plain-token")
	b := HashAccessCode("plain-token")
	if a != b {
		t.Fatal("同一明文的摘要必须稳定，否则缓存与库里的键对不上")
	}
	if a == "plain-token" || len(a) != 64 {
		t.Fatalf("摘要格式不对: %q", a)
	}
	if HashAccessCode("plain-token2") == a {
		t.Fatal("不同明文不应产生相同摘要")
	}
}
