package utils

import (
	"SamWaf/model"
	"testing"
)

type wantListen struct {
	port    int
	proto   string
	ipv     string
	isMain  bool
	implied bool
}

func assertListens(t *testing.T, name string, got []HostListen, want []wantListen) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: 条数不符 got=%d want=%d, got=%+v", name, len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Port != w.port || g.Protocol != w.proto || g.IPVersion != w.ipv || g.IsMain != w.isMain || g.Implied != w.implied {
			t.Errorf("%s[%d]: got={port:%d proto:%s ipv:%s main:%v implied:%v} want=%+v",
				name, i, g.Port, g.Protocol, g.IPVersion, g.IsMain, g.Implied, w)
		}
		if g.Addr != "" {
			t.Errorf("%s[%d]: Addr 必须恒为空(预留字段), got=%q", name, i, g.Addr)
		}
	}
}

// L1~L5：空表派生必须逐条复刻老规则（含 80+Ssl=1→https 这个 issue #955 的行为本身，
// 升级不改变任何现象是第一硬约束）
func TestResolveLegacyDerive(t *testing.T) {
	// L1
	assertListens(t, "L1",
		ResolveHostListens(model.Hosts{Port: 80, Ssl: 0}),
		[]wantListen{{80, "http", "both", true, false}})
	// L2 忠实复刻 bug 行为
	assertListens(t, "L2",
		ResolveHostListens(model.Hosts{Port: 80, Ssl: 1}),
		[]wantListen{{80, "https", "both", true, false}})
	// L3 副端口 80 硬编码为 http（老副端口规则）
	assertListens(t, "L3",
		ResolveHostListens(model.Hosts{Port: 443, Ssl: 1, BindMorePort: "80"}),
		[]wantListen{{443, "https", "both", true, false}, {80, "http", "both", false, false}})
	// L4 副端口非80且 Ssl=1 → https
	assertListens(t, "L4",
		ResolveHostListens(model.Hosts{Port: 8443, Ssl: 1, BindMorePort: "8080"}),
		[]wantListen{{8443, "https", "both", true, false}, {8080, "https", "both", false, false}})
	// L5 AutoJumpHTTPS 隐式补 80:http（Implied：不注册路由）
	assertListens(t, "L5",
		ResolveHostListens(model.Hosts{Port: 443, Ssl: 1, AutoJumpHTTPS: 1}),
		[]wantListen{{443, "https", "both", true, false}, {80, "http", "both", false, true}})
	// L5b 副端口里已显式写了 80 时：80 是路由副端口(implied=false，副域名:80 也要注册路由)，
	// AutoJump 不再重复补——复刻老代码 ports 集合含 80 的行为
	assertListens(t, "L5b",
		ResolveHostListens(model.Hosts{Port: 443, Ssl: 1, AutoJumpHTTPS: 1, BindMorePort: "80"}),
		[]wantListen{{443, "https", "both", true, false}, {80, "http", "both", false, false}})
	// L5c BindMorePort 含空格/空项/重复/越界，逐条清洗（与老代码 TrimSpace+Atoi 失败跳过一致，越界丢弃为有益差异）
	assertListens(t, "L5c",
		ResolveHostListens(model.Hosts{Port: 443, Ssl: 1, BindMorePort: " 8080 ,, 8080 ,99999, 80"}),
		[]wantListen{{443, "https", "both", true, false}, {8080, "https", "both", false, false}, {80, "http", "both", false, false}})
}

// L6：显式表以声明为准，与 Ssl 字段无关；ipv 缺省 → both
func TestResolveExplicit(t *testing.T) {
	h := model.Hosts{Port: 80, Ssl: 1,
		PortListensJSON: `[{"port":80,"proto":"http"},{"port":443,"proto":"https","ipv":"ipv4"}]`}
	assertListens(t, "L6",
		ResolveHostListens(h),
		[]wantListen{{80, "http", "both", true, false}, {443, "https", "ipv4", false, false}})
}

// L7：显式表缺主端口 → 按老规则补一条并放到首位
func TestResolveExplicitMissingMain(t *testing.T) {
	h := model.Hosts{Port: 443, Ssl: 1,
		PortListensJSON: `[{"port":80,"proto":"https"}]`}
	assertListens(t, "L7",
		ResolveHostListens(h),
		[]wantListen{{443, "https", "both", true, false}, {80, "https", "both", false, false}})
}

// L8：脏数据逐条丢弃/去重，其余生效
func TestResolveExplicitDirtyEntries(t *testing.T) {
	h := model.Hosts{Port: 80, Ssl: 0,
		PortListensJSON: `[{"port":80,"proto":"ftp"},{"port":99999,"proto":"http"},{"port":80,"proto":"http"},{"port":80,"proto":"https"},{"port":8080,"proto":"http"}]`}
	// 80:ftp 丢弃；99999 丢弃；80:http 保留后被 80:https 覆盖（重复端口后者覆盖）
	assertListens(t, "L8",
		ResolveHostListens(h),
		[]wantListen{{80, "https", "both", true, false}, {8080, "http", "both", false, false}})
}

// L9：JSON 整体不合法 → 回落派生，站点不失联（红线 R7）
func TestResolveBrokenJSONFallback(t *testing.T) {
	h := model.Hosts{Port: 80, Ssl: 1, PortListensJSON: `{not-json`}
	assertListens(t, "L9",
		ResolveHostListens(h),
		[]wantListen{{80, "https", "both", true, false}})
	// 全部条目脏 → 同样回落派生
	h2 := model.Hosts{Port: 80, Ssl: 0, PortListensJSON: `[{"port":0,"proto":"http"}]`}
	assertListens(t, "L9b",
		ResolveHostListens(h2),
		[]wantListen{{80, "http", "both", true, false}})
}

// L10：非法 ipv 回落 both
func TestResolveBadIPV(t *testing.T) {
	h := model.Hosts{Port: 80, PortListensJSON: `[{"port":80,"proto":"http","ipv":"v6"}]`}
	assertListens(t, "L10",
		ResolveHostListens(h),
		[]wantListen{{80, "http", "both", true, false}})
}

// L11：addr 预留字段被忽略，仍按通配监听
func TestResolveAddrReserved(t *testing.T) {
	h := model.Hosts{Port: 80, PortListensJSON: `[{"port":80,"proto":"http","addr":"192.168.1.10"}]`}
	got := ResolveHostListens(h)
	assertListens(t, "L11", got, []wantListen{{80, "http", "both", true, false}})
	if got[0].ListenAddr() != ":80" {
		t.Errorf("L11: addr 被忽略后应按通配监听, got=%q", got[0].ListenAddr())
	}
}

// L12：全局站点不产出监听
func TestResolveGlobalHost(t *testing.T) {
	if got := ResolveHostListens(model.Hosts{Port: 0, GLOBAL_HOST: 1}); len(got) != 0 {
		t.Errorf("L12: 全局站点应无监听, got=%+v", got)
	}
}

// L13：Network / UDPNetwork / ListenAddr 映射
func TestNetworkMapping(t *testing.T) {
	cases := []struct {
		ipv, network, udp, addr string
	}{
		{"both", "tcp", "udp", ":80"},
		{"ipv4", "tcp4", "udp4", "0.0.0.0:80"},
		{"ipv6", "tcp6", "udp6", "[::]:80"},
		{"", "tcp", "udp", ":80"},
	}
	for _, c := range cases {
		l := HostListen{Port: 80, IPVersion: c.ipv}
		if l.Network() != c.network || l.UDPNetwork() != c.udp || l.ListenAddr() != c.addr {
			t.Errorf("ipv=%q: got (%s,%s,%s) want (%s,%s,%s)",
				c.ipv, l.Network(), l.UDPNetwork(), l.ListenAddr(), c.network, c.udp, c.addr)
		}
	}
}

// 显式表 + AutoJumpHTTPS：表内已显式含 80 → 以声明为准不覆盖；未含 → 隐式补
func TestResolveExplicitAutoJump(t *testing.T) {
	hExplicit := model.Hosts{Port: 443, AutoJumpHTTPS: 1, Ssl: 1,
		PortListensJSON: `[{"port":443,"proto":"https"},{"port":80,"proto":"https"}]`}
	assertListens(t, "AJ-explicit",
		ResolveHostListens(hExplicit),
		[]wantListen{{443, "https", "both", true, false}, {80, "https", "both", false, false}})

	hImplied := model.Hosts{Port: 443, AutoJumpHTTPS: 1, Ssl: 1,
		PortListensJSON: `[{"port":443,"proto":"https"}]`}
	assertListens(t, "AJ-implied",
		ResolveHostListens(hImplied),
		[]wantListen{{443, "https", "both", true, false}, {80, "http", "both", false, true}})
}

// 派生辅助函数：路由副端口不含主端口与隐式 80；引用计数端口含隐式 80
func TestPortHelpers(t *testing.T) {
	h := model.Hosts{Port: 443, Ssl: 1, AutoJumpHTTPS: 1, BindMorePort: "8443"}
	extra := HostRoutedExtraPorts(h)
	if len(extra) != 1 || extra[0] != 8443 {
		t.Errorf("HostRoutedExtraPorts got=%v want=[8443]", extra)
	}
	all := HostListenPorts(h)
	if len(all) != 3 {
		t.Errorf("HostListenPorts got=%v want 443,80,8443 共3个", all)
	}
	if HostMainProtocol(h) != "https" {
		t.Errorf("HostMainProtocol got=%s want=https", HostMainProtocol(h))
	}
	h2 := model.Hosts{Port: 80, Ssl: 1, PortListensJSON: `[{"port":80,"proto":"http"}]`}
	if HostMainProtocol(h2) != "http" {
		t.Errorf("显式表下 HostMainProtocol 应以声明为准, got=%s", HostMainProtocol(h2))
	}
}
