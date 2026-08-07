package wafhostguard

import (
	"testing"
	"time"
)

// 4625 有源IP：最常见的 RDP 密码爆破
const evt4625WithIP = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System>
  <Provider Name="Microsoft-Windows-Security-Auditing"/>
  <EventID>4625</EventID>
  <TimeCreated SystemTime="2026-08-06T06:55:01.1234567Z"/>
  <EventRecordID>123456</EventRecordID>
  <Channel>Security</Channel>
 </System>
 <EventData>
  <Data Name="TargetUserName">administrator</Data>
  <Data Name="TargetDomainName">WORKGROUP</Data>
  <Data Name="LogonType">10</Data>
  <Data Name="IpAddress">1.2.3.4</Data>
  <Data Name="IpPort">51234</Data>
  <Data Name="WorkstationName">DESKTOP-ATTACK</Data>
  <Data Name="Status">0xc000006d</Data>
 </EventData>
</Event>`

// 4625 无源IP：未知用户名场景，IpAddress 是 "-"
const evt4625NoIP = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System>
  <EventID>4625</EventID>
  <TimeCreated SystemTime="2026-08-06T06:55:02.0000000Z"/>
  <EventRecordID>123457</EventRecordID>
  <Channel>Security</Channel>
 </System>
 <EventData>
  <Data Name="TargetUserName">nosuchuser</Data>
  <Data Name="LogonType">10</Data>
  <Data Name="IpAddress">-</Data>
  <Data Name="IpPort">-</Data>
  <Data Name="WorkstationName">DESKTOP-ATTACK</Data>
 </EventData>
</Event>`

// 4625 本地登录：LogonType=2，本机行为，不该被采集
const evt4625Local = `<Event>
 <System><EventID>4625</EventID><Channel>Security</Channel></System>
 <EventData>
  <Data Name="TargetUserName">user</Data>
  <Data Name="LogonType">2</Data>
  <Data Name="IpAddress">127.0.0.1</Data>
 </EventData>
</Event>`

// 4625 网络登录：LogonType=3(SMB/IPC$)
const evt4625Network = `<Event>
 <System><EventID>4625</EventID><Channel>Security</Channel>
  <TimeCreated SystemTime="2026-08-06T06:55:03.0000000Z"/></System>
 <EventData>
  <Data Name="TargetUserName">baduser</Data>
  <Data Name="LogonType">3</Data>
  <Data Name="IpAddress">5.6.7.8</Data>
  <Data Name="IpPort">44444</Data>
 </EventData>
</Event>`

// 4625 IPv6 源
const evt4625IPv6 = `<Event>
 <System><EventID>4625</EventID><Channel>Security</Channel>
  <TimeCreated SystemTime="2026-08-06T06:55:04.0000000Z"/></System>
 <EventData>
  <Data Name="TargetUserName">root</Data>
  <Data Name="LogonType">10</Data>
  <Data Name="IpAddress">2001:db8::1</Data>
  <Data Name="IpPort">51235</Data>
 </EventData>
</Event>`

// 4625 环回来源：本机自己发起的，封了会伤到自己
const evt4625Loopback = `<Event>
 <System><EventID>4625</EventID><Channel>Security</Channel></System>
 <EventData>
  <Data Name="TargetUserName">user</Data>
  <Data Name="LogonType">10</Data>
  <Data Name="IpAddress">127.0.0.1</Data>
 </EventData>
</Event>`

// RdpCoreTS 140：无法从客户端建立连接
const evtRdp140 = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System>
  <EventID>140</EventID>
  <TimeCreated SystemTime="2026-08-06T06:55:00.5000000Z"/>
  <EventRecordID>888</EventRecordID>
  <Channel>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</Channel>
 </System>
 <UserData>
  <EventXML xmlns="Event_NS"><IPString>9.8.7.6</IPString></EventXML>
 </UserData>
</Event>`

// RdpCoreTS 131：新 TCP 连接，ClientIP 带端口
const evtRdp131 = `<Event>
 <System>
  <EventID>131</EventID>
  <TimeCreated SystemTime="2026-08-06T06:55:00.1000000Z"/>
  <Channel>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational</Channel>
 </System>
 <UserData>
  <EventXML xmlns="Event_NS"><ConnType>TCP</ConnType><ClientIP>11.22.33.44:59876</ClientIP></EventXML>
 </UserData>
</Event>`

func TestParse4625(t *testing.T) {
	now := time.Now()

	t.Run("RDP密码爆破-有源IP", func(t *testing.T) {
		ev, needResolve, ok := Parse4625(evt4625WithIP, now)
		if !ok {
			t.Fatal("应当解析成功")
		}
		if needResolve {
			t.Error("已有源IP，不该要求补齐")
		}
		if ev.IP != "1.2.3.4" {
			t.Errorf("IP = %q, want 1.2.3.4", ev.IP)
		}
		if ev.User != "administrator" {
			t.Errorf("User = %q", ev.User)
		}
		if ev.Port != 51234 {
			t.Errorf("Port = %d", ev.Port)
		}
		if ev.LogonType != "10" {
			t.Errorf("LogonType = %q", ev.LogonType)
		}
		if ev.Source != SourceRDP {
			t.Errorf("Source = %q", ev.Source)
		}
		if !ev.Kind.IsHard() {
			t.Error("RDP 登录失败应当计入阈值")
		}
	})

	t.Run("无源IP必须要求补齐而不是猜", func(t *testing.T) {
		ev, needResolve, ok := Parse4625(evt4625NoIP, now)
		if !ok {
			t.Fatal("应当解析成功(拿到用户名等信息)")
		}
		if !needResolve {
			t.Fatal("IpAddress 为 - 时必须要求补齐")
		}
		if ev.IP != "" {
			t.Errorf("补齐前 IP 必须为空，不能瞎填，got %q", ev.IP)
		}
	})

	t.Run("本地登录不采集", func(t *testing.T) {
		if _, _, ok := Parse4625(evt4625Local, now); ok {
			t.Error("LogonType=2 是本机交互登录，不该被当成远程爆破")
		}
	})

	t.Run("网络登录采集", func(t *testing.T) {
		ev, needResolve, ok := Parse4625(evt4625Network, now)
		if !ok || needResolve {
			t.Fatalf("ok=%v needResolve=%v", ok, needResolve)
		}
		if ev.IP != "5.6.7.8" || ev.LogonType != "3" {
			t.Errorf("ev = %+v", ev)
		}
	})

	t.Run("IPv6源", func(t *testing.T) {
		ev, needResolve, ok := Parse4625(evt4625IPv6, now)
		if !ok || needResolve {
			t.Fatalf("ok=%v needResolve=%v", ok, needResolve)
		}
		if ev.IP != "2001:db8::1" {
			t.Errorf("IP = %q", ev.IP)
		}
	})

	t.Run("环回来源要求补齐而不是直接封本机", func(t *testing.T) {
		_, needResolve, ok := Parse4625(evt4625Loopback, now)
		if !ok {
			t.Fatal("应当解析成功")
		}
		if !needResolve {
			t.Error("环回地址不是可封禁目标，必须走补齐流程")
		}
	})

	t.Run("非4625事件不处理", func(t *testing.T) {
		if _, _, ok := Parse4625(evtRdp140, now); ok {
			t.Error("140 不是 4625")
		}
	})

	t.Run("非法XML不panic", func(t *testing.T) {
		if _, _, ok := Parse4625("not xml at all", now); ok {
			t.Error("非法内容不该解析成功")
		}
	})
}

func TestParseRdpCoreTSIP(t *testing.T) {
	now := time.Now()

	t.Run("140事件IPString", func(t *testing.T) {
		ip, _, ok := ParseRdpCoreTSIP(evtRdp140, now)
		if !ok {
			t.Fatal("应当解析成功")
		}
		if ip != "9.8.7.6" {
			t.Errorf("ip = %q, want 9.8.7.6", ip)
		}
	})

	t.Run("131事件ClientIP带端口需去掉端口", func(t *testing.T) {
		ip, _, ok := ParseRdpCoreTSIP(evtRdp131, now)
		if !ok {
			t.Fatal("应当解析成功")
		}
		if ip != "11.22.33.44" {
			t.Errorf("ip = %q, want 11.22.33.44（端口必须被剥掉）", ip)
		}
	})

	t.Run("非RdpCoreTS事件不处理", func(t *testing.T) {
		if _, _, ok := ParseRdpCoreTSIP(evt4625WithIP, now); ok {
			t.Error("4625 不是 131/140")
		}
	})
}

func TestUsableRemoteIP(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1.2.3.4", true},
		{"2001:db8::1", true},
		{"1.2.3.4:5555", true},
		{"[2001:db8::1]:5555", true},
		{"-", false},         // Windows 表示"未知"
		{"", false},          // 空
		{"127.0.0.1", false}, // 环回，封了伤自己
		{"::1", false},
		{"0.0.0.0", false},     // 未指定地址
		{"not-an-ip", false},   // 垃圾数据
		{"DESKTOP-ABC", false}, // WorkstationName 不是 IP，绝不能当来源
	}
	for _, c := range cases {
		if got := usableRemoteIP(c.in); got != c.want {
			t.Errorf("usableRemoteIP(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.2.3.4", "1.2.3.4"},
		{"1.2.3.4:5555", "1.2.3.4"},
		{"[2001:db8::1]:5555", "2001:db8::1"},
		{"2001:DB8::1", "2001:db8::1"},
	}
	for _, c := range cases {
		if got := normalizeIP(c.in); got != c.want {
			t.Errorf("normalizeIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
