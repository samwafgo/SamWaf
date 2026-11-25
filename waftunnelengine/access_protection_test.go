package waftunnelengine

import (
	"SamWaf/model"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestTunnelAccessPrecedence(t *testing.T) {
	region := model.TunnelRegionProtection{Revision: 1, Enabled: true, Fallback: "deny", Unknown: "deny", Rules: []model.TunnelRegionRule{
		{Enabled: false, Operator: "eq", Country: "CN", Action: "deny"},
		{Enabled: true, Operator: "eq", Country: "CN", Action: "allow"},
		{Enabled: true, Operator: "ne", Country: "US", Action: "deny"},
	}}
	now := time.Unix(1000, 0)
	rt, run := testRuntime(t)
	tunnel := testTunnel(t, "x", 1, testBinding("binding", "ipv4"))
	tunnel.DenyIp = "::ffff:8.8.4.0/120"
	tunnel.AllowIp = "8.8.4.4,1.1.1.0/24"
	tunnel.RegionProtection = testJSON(t, region)
	rt.update(tunnel, now)
	testRound(t, rt, run, now, "binding", testAnswer("8.8.4.4", now.Add(time.Hour)))
	for _, tc := range []struct {
		ip, country string
		reason      tunnelAccessDenial
		query       bool
	}{
		{ip: "", reason: denyInvalidPeer},
		{ip: "8.8.4.4", country: "CN", reason: denyFixedList},
		{ip: "::ffff:8.8.4.4", country: "CN", reason: denyFixedList},
		{ip: "127.0.0.1", reason: denyWhitelistMiss},
		{ip: "1.1.1.1", country: "CN", query: true},
		{ip: "1.1.1.1", country: "JP", reason: denyRegionRule, query: true},
		{ip: "1.1.1.1", country: "US", reason: denyRegionFallback, query: true},
		{ip: "1.1.1.1", reason: denyRegionUnknown, query: true},
	} {
		lookedUp := false
		country := func(string) string { lookedUp = true; return tc.country }
		if got := testSnapshot(t, rt, "x").denial(tc.ip, now, country); got != tc.reason || lookedUp != tc.query {
			t.Fatalf("ip=%s country=%s reason=%q lookup=%t, want %q/%t", tc.ip, tc.country, got, lookedUp, tc.reason, tc.query)
		}
	}
	for _, tc := range []struct {
		schedule string
		reason   tunnelAccessDenial
	}{
		{schedule: "invalid-range", reason: denyInvalidSchedule},
		{schedule: "10:00-11:00", reason: denyOutsideSchedule},
	} {
		tunnel.AllowedTimeRanges = tc.schedule
		rt.update(tunnel, now)
		if got := testSnapshot(t, rt, "x").denial("1.1.1.1", now.UTC(), func(string) string {
			t.Fatal("time restriction must run before geography")
			return "CN"
		}); got != tc.reason {
			t.Fatalf("schedule %q: reason=%q, want %q", tc.schedule, got, tc.reason)
		}
	}
	region.Unknown = "allow"
	if tunnelRegionDenial(region, "") != "" {
		t.Fatal("unknown source incorrectly matched a country inequality")
	}
}

func TestTunnelAccessLocalPeerWithActiveDDNS(t *testing.T) {
	rt, run := testRuntime(t)
	now := time.Unix(1000, 0)
	tunnel := testTunnel(t, "x", 0)
	rt.update(tunnel, now)
	denial := func(ip string) tunnelAccessDenial {
		return testSnapshot(t, rt, tunnel.Id).denial(ip, now, tunnelCountry)
	}
	if got := denial("127.0.0.1"); got != "" {
		t.Fatalf("legacy tunnel rejected a loopback source: %s", got)
	}

	tunnel = testTunnel(t, "x", 1, testBinding("binding", "ipv4"))
	rt.update(tunnel, now)
	testRound(t, rt, run, now, "binding", testAnswer("1.1.1.1", now.Add(time.Minute)))
	if got := denial("1.1.1.1"); got != "" {
		t.Fatalf("tunnel rejected the active dynamic address: %s", got)
	}
	if got := denial("127.0.0.1"); got != denyWhitelistMiss {
		t.Fatalf("loopback rejection reason = %q, want %q", got, denyWhitelistMiss)
	}

	tunnel.AllowIp = "127.0.0.1"
	rt.update(tunnel, now)
	for _, ip := range []string{"127.0.0.1", "1.1.1.1"} {
		if got := denial(ip); got != "" {
			t.Fatalf("combined allowlist rejected %s: %s", ip, got)
		}
	}
}

func TestTunnelTransportAppliesDDNSOnlyPolicyToNextAccess(t *testing.T) {
	waf := NewWafTunnelEngine()
	waf.ReloadActiveTunnel() // An inactive engine must not read the database or start a scheduler.
	waf.active = true
	waf.starts = make(map[string]*tunnelListenerStart)
	defer waf.CloseTunnel()

	tcpUpstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpUpstream.Close()
	go func() {
		for {
			conn, err := tcpUpstream.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()

	udpUpstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpUpstream.Close()
	upstreamPackets := make(chan string, 4)
	go func() {
		var buf [64]byte
		for {
			n, addr, err := udpUpstream.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			upstreamPackets <- string(buf[:n])
			_, _ = udpUpstream.WriteToUDP(buf[:n], addr)
		}
	}()

	tcp := testTunnel(t, "tcp-test", 1, testBinding("binding", "ipv4"))
	tcp.Port, tcp.IpVersion, tcp.AllowIp, tcp.StartStatus = "0", "ipv4", "127.0.0.1", 1
	tcp.RemoteIp, tcp.RemotePort = "127.0.0.1", tcpUpstream.Addr().(*net.TCPAddr).Port
	udp := testTunnel(t, "udp-test", 1, testBinding("binding", "ipv4"))
	udp.Protocol, udp.Port, udp.IpVersion, udp.AllowIp, udp.StartStatus = "udp", "0", "ipv4", "127.0.0.1", 1
	udp.RemoteIp, udp.RemotePort, udp.ConnTimeout = "127.0.0.1", udpUpstream.LocalAddr().(*net.UDPAddr).Port, 2
	for _, cfg := range []model.Tunnel{tcp, udp} {
		for _, runtime := range waf.LoadTunnel(cfg) {
			waf.StartTunnelServer(runtime)
		}
	}

	tcpEntry := testListenerAddress(t, waf, "tcp")
	tcpClient, err := net.DialTimeout("tcp4", tcpEntry, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpClient.Close()
	udpEntry := testListenerAddress(t, waf, "udp")
	udpClient, err := net.DialTimeout("udp4", udpEntry, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()

	testEcho(t, tcpClient, "tcp-before")
	testEcho(t, udpClient, "udp-before")
	if got := <-upstreamPackets; got != "udp-before" {
		t.Fatalf("unexpected UDP upstream data %q", got)
	}

	for _, old := range []model.Tunnel{tcp, udp} {
		updated := old
		updated.AllowIp = "" // Still a whitelist: the DDNS binding is enabled but pending.
		if restart := waf.EditTunnel(old, updated); len(restart) != 0 {
			t.Fatal("access policy hot update restarted a listener")
		}
	}
	testEcho(t, tcpClient, "existing-tcp-after")
	newTCP, err := net.DialTimeout("tcp4", tcpEntry, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer newTCP.Close()
	_ = newTCP.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = newTCP.Write([]byte("new-tcp-after"))
	var buf [64]byte
	if n, err := newTCP.Read(buf[:]); n != 0 || err == nil {
		t.Fatalf("new TCP connection reached upstream after whitelist update: %q (%v)", buf[:n], err)
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("denied TCP connection was not closed: %v", err)
	}
	if _, err := udpClient.Write([]byte("udp-after")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-upstreamPackets:
		t.Fatalf("UDP datagram from existing peer bypassed the updated whitelist: %q", got)
	case <-time.After(150 * time.Millisecond):
	}
}

func testListenerAddress(t *testing.T, waf *WafTunnelEngine, protocol string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime, ok := waf.NetListerOnline.Get(protocol + "0"); ok {
			var addr net.Addr
			switch socket := runtime.Svr.(type) {
			case net.Listener:
				addr = socket.Addr()
			case *net.UDPConn:
				addr = socket.LocalAddr()
			}
			if addr != nil {
				_, port, err := net.SplitHostPort(addr.String())
				if err != nil {
					t.Fatal(err)
				}
				if p, err := strconv.Atoi(port); err == nil && p > 0 {
					return net.JoinHostPort("127.0.0.1", port)
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("listener %s did not publish", protocol)
	return ""
}

func testEcho(t *testing.T, conn net.Conn, data string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(data))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != data {
		t.Fatalf("unexpected echo %q, %v", buf, err)
	}
}
