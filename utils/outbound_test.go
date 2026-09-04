package utils

import (
	"strings"
	"testing"

	"SamWaf/global"
)

// 用户可配对外地址的。
// 默认只允许公网；内网源必须由运营方在 config.yml 的 security.outbound_allowed_hosts 带外声明。

func setOutboundAllowHosts(t *testing.T, hosts string) {
	t.Helper()
	old := global.GCONFIG_OUTBOUND_ALLOWED_HOSTS
	global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = hosts
	t.Cleanup(func() { global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = old })
}

func TestIsAllowedOutboundURL_内网与危险目标被拒(t *testing.T) {
	setOutboundAllowHosts(t, "")

	cases := []struct {
		name string
		url  string
	}{
		{"回环IPv4", "http://127.0.0.1/list.txt"},
		{"回环别名", "http://127.127.127.127:8080/list.txt"},
		{"回环IPv6", "http://[::1]/list.txt"},
		{"未指定地址", "http://0.0.0.0/list.txt"},
		{"私网10段", "http://10.0.0.5/list.txt"},
		{"私网172段", "http://172.16.3.9/list.txt"},
		{"私网192段", "http://192.168.1.1/list.txt"},
		{"CGNAT", "http://100.64.0.1/list.txt"},
		{"链路本地", "http://169.254.1.1/list.txt"},
		{"云元数据", "http://169.254.169.254/latest/meta-data/"},
		{"IPv6唯一本地", "http://[fd00::1]/list.txt"},
		{"file协议", "file:///etc/passwd"},
		{"gopher协议", "gopher://127.0.0.1:6379/_INFO"},
		{"缺少主机", "http:///list.txt"},
		{"空字符串", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if ok, _ := IsAllowedOutboundURL(c.url); ok {
				t.Fatalf("期望拒绝 %q，实际放行", c.url)
			}
		})
	}
}

func TestIsAllowedOutboundURL_公网地址放行(t *testing.T) {
	setOutboundAllowHosts(t, "")
	for _, u := range []string{
		"http://8.8.8.8/list.txt",
		"https://1.1.1.1/list.txt",
		"http://[2001:4860:4860::8888]/list.txt",
	} {
		if ok, reason := IsAllowedOutboundURL(u); !ok {
			t.Fatalf("公网地址 %q 应放行，实际被拒: %s", u, reason)
		}
	}
}

func TestIsAllowedOutboundURL_带外清单是唯一的内网逃生门(t *testing.T) {
	// 未声明前拒
	setOutboundAllowHosts(t, "")
	if ok, _ := IsAllowedOutboundURL("http://10.20.30.40/list.txt"); ok {
		t.Fatal("未声明时内网地址必须被拒")
	}
	// 声明具体 IP 后放行
	setOutboundAllowHosts(t, "10.20.30.40")
	if ok, reason := IsAllowedOutboundURL("http://10.20.30.40/list.txt"); !ok {
		t.Fatalf("已声明的内网 IP 应放行，实际被拒: %s", reason)
	}
	// 未声明的邻居 IP 仍然拒（清单不是网段泛化）
	if ok, _ := IsAllowedOutboundURL("http://10.20.30.41/list.txt"); ok {
		t.Fatal("未声明的邻居 IP 必须仍被拒")
	}
	// CIDR 形式
	setOutboundAllowHosts(t, "10.20.30.0/24")
	if ok, reason := IsAllowedOutboundURL("http://10.20.30.41/list.txt"); !ok {
		t.Fatalf("CIDR 覆盖的内网 IP 应放行，实际被拒: %s", reason)
	}
	if ok, _ := IsAllowedOutboundURL("http://10.20.31.1/list.txt"); ok {
		t.Fatal("CIDR 之外的 IP 必须仍被拒")
	}
	// 主机名条目：精确匹配，不做后缀泛化
	setOutboundAllowHosts(t, "mirror.corp.internal")
	if !IsOutboundHostAllowlisted("MIRROR.CORP.INTERNAL") {
		t.Fatal("主机名匹配应大小写不敏感")
	}
	if IsOutboundHostAllowlisted("evil-mirror.corp.internal") {
		t.Fatal("主机名必须精确匹配，不能被后缀拼接绕过")
	}
	if IsOutboundHostAllowlisted("mirror.corp.internal.attacker.com") {
		t.Fatal("主机名必须精确匹配，不能被前缀拼接绕过")
	}
	// 清单里放主机名，不等于放行同名之外的任何内网地址
	if ok, _ := IsAllowedOutboundURL("http://127.0.0.1/list.txt"); ok {
		t.Fatal("清单里只有主机名时，回环地址仍必须被拒")
	}
	// userinfo 不能把判定糊弄过去：真正的主机是 @ 之后那段
	if ok, _ := IsAllowedOutboundURL("http://mirror.corp.internal@127.0.0.1/list.txt"); ok {
		t.Fatal("userinfo 伪装必须无效，真实主机是 127.0.0.1")
	}
}

func TestIsAllowedOutboundURL_IPv6内嵌IPv4写法不能绕过(t *testing.T) {
	setOutboundAllowHosts(t, "")
	// 三种把 IPv4 内网地址包进 IPv6 的写法：v4 映射 / v4 兼容 / NAT64 / 6to4
	cases := []string{
		"http://[::ffff:127.0.0.1]/x", // v4 映射
		"http://[::ffff:10.0.0.1]/x",  // v4 映射私网
		"http://[::127.0.0.1]/x",      // v4 兼容
		"http://[::7f00:1]/x",         // v4 兼容(十六进制写法)
		"http://[64:ff9b::7f00:1]/x",  // NAT64 → 127.0.0.1
		"http://[64:ff9b::a00:1]/x",   // NAT64 → 10.0.0.1
		"http://[2002:7f00:1::]/x",    // 6to4 → 127.0.0.1
		"http://[2002:a9fe:a9fe::]/x", // 6to4 → 169.254.169.254 云元数据
	}
	for _, u := range cases {
		if ok, _ := IsAllowedOutboundURL(u); ok {
			t.Fatalf("期望拒绝 %q，实际放行", u)
		}
	}
	// 真正的公网 IPv6 不能被误伤
	if ok, reason := IsAllowedOutboundURL("http://[2001:4860:4860::8888]/x"); !ok {
		t.Fatalf("公网 IPv6 应放行，实际被拒: %s", reason)
	}
	// 6to4 包着公网 v4 时仍应放行（判的是内嵌地址本身）
	if ok, reason := IsAllowedOutboundURL("http://[2002:0808:0808::]/x"); !ok {
		t.Fatalf("6to4 包公网地址应放行，实际被拒: %s", reason)
	}
}

func TestIsAllowedOutboundURL_IPv4保留段被拒(t *testing.T) {
	setOutboundAllowHosts(t, "")
	for _, u := range []string{
		"http://0.1.2.3/x",         // 0.0.0.0/8
		"http://192.0.0.1/x",       // 192.0.0.0/24 IETF 协议分配
		"http://198.18.0.1/x",      // 198.18.0.0/15 基准测试
		"http://240.0.0.1/x",       // 240.0.0.0/4 保留
		"http://255.255.255.255/x", // 广播
	} {
		if ok, _ := IsAllowedOutboundURL(u); ok {
			t.Fatalf("保留段 %q 必须被拒", u)
		}
	}
}

func TestRedactURLCredentials(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"https://feed.example.com/list.txt", "https://feed.example.com/list.txt"},
		{"/data/import/ip.txt", "/data/import/ip.txt"},
		{"https://user:token@feed.example.com/list.txt", "https://redacted@feed.example.com/list.txt"},
		{"https://user@feed.example.com/list.txt", "https://redacted@feed.example.com/list.txt"},
	}
	for _, c := range cases {
		if got := RedactURLCredentials(c.in); got != c.want {
			t.Fatalf("RedactURLCredentials(%q)=%q 期望 %q", c.in, got, c.want)
		}
	}
	// 无论如何都不能把口令原样留下
	for _, in := range []string{
		"https://user:s3cr3t@feed.example.com/list.txt",
		"://user:s3cr3t@broken",
	} {
		if got := RedactURLCredentials(in); strings.Contains(got, "s3cr3t") {
			t.Fatalf("口令未被抹掉: %q", got)
		}
	}
}

func TestPrecheckOutboundURL_保存阶段的判定(t *testing.T) {
	setOutboundAllowHosts(t, "")
	// 协议/IP 字面量在保存阶段就能定死
	for _, u := range []string{"file:///etc/passwd", "http://127.0.0.1/x", "http://169.254.169.254/x", ""} {
		if ok, _ := PrecheckOutboundURL(u); ok {
			t.Fatalf("保存阶段应拒绝 %q", u)
		}
	}
	// 域名不做强制解析：解析不出来也允许保存，边界留给执行前判定
	if ok, reason := PrecheckOutboundURL("https://this-host-should-not-resolve.invalid/list.txt"); !ok {
		t.Fatalf("无法解析的域名在保存阶段应放行，实际被拒: %s", reason)
	}
	setOutboundAllowHosts(t, "10.20.30.40")
	if ok, reason := PrecheckOutboundURL("http://10.20.30.40/list.txt"); !ok {
		t.Fatalf("已带外声明的内网地址应可保存，实际被拒: %s", reason)
	}
}

// 清单只写 CIDR、URL 用主机名（解析结果落在该 CIDR 内）时也必须放行——
// 与连接期 safeOutboundDialContext 的按 IP 判定保持同口径（issue #990 评审发现的两层口径差）。
func TestIsAllowedOutboundURL_主机名解析进清单CIDR(t *testing.T) {
	// localhost 经 hosts 文件解析到 127.0.0.1，不依赖外部 DNS
	setOutboundAllowHosts(t, "")
	if ok, _ := IsAllowedOutboundURL("http://localhost/x"); ok {
		t.Fatal("未声明时 localhost 必须被拒")
	}
	// localhost 通常同时解析出 127.0.0.1 与 ::1，与连接期"混进一个未声明内网地址就整体拒绝"
	// 同口径：两条解析结果都必须被清单覆盖
	setOutboundAllowHosts(t, "127.0.0.0/8,::1/128")
	if ok, reason := IsAllowedOutboundURL("http://localhost/x"); !ok {
		t.Fatalf("解析结果落在清单 CIDR 内的主机名应放行，实际被拒: %s", reason)
	}
	// 清单之外的网段仍拒
	setOutboundAllowHosts(t, "10.0.0.0/8")
	if ok, _ := IsAllowedOutboundURL("http://localhost/x"); ok {
		t.Fatal("解析结果不在清单内的主机名必须仍被拒")
	}
}
