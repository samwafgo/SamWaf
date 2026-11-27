//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// TestEBPFKeyIsolation 检查地址族、CIDR 与端口编码，确保 /32 和 /128 不互相覆盖。
func TestEBPFKeyIsolation(t *testing.T) {
	v4, canonical, err := makeRuleKey("192.0.2.17/24", 443)
	if err != nil || canonical != "192.0.2.0/24" || v4.Prefix != 88 || v4.Port != [2]byte{1, 187} {
		t.Fatalf("bad IPv4 key: %+v %s %v", v4, canonical, err)
	}
	v6, _, err := makeRuleKey("2001:db8::/32", 443)
	if err != nil || v6.Family == v4.Family || v6.Prefix != 96 {
		t.Fatalf("bad IPv6 key: %+v %v", v6, err)
	}
	for _, ip := range []string{"0.0.0.0/0", "::/0", "not-an-ip", "fe80::1%eth0"} {
		if _, _, err = makeRuleKey(ip, 0); err == nil {
			t.Fatalf("accepted %q", ip)
		}
	}
}

// TestEBPFKernelDataplane 仅在显式隔离的网络命名空间中执行，实际发送报文验证内核 DROP。
func TestEBPFKernelDataplane(t *testing.T) {
	if os.Getenv("SAMWAF_TEST_EBPF") != "isolated-netns" {
		t.Skip("run in an isolated netns with SAMWAF_TEST_EBPF=isolated-netns")
	}
	t.Setenv("SAMWAF_BPF_STATE_DIR", t.TempDir())
	t.Setenv("SAMWAF_BPF_PIN_ROOT", filepath.Join("/sys/fs/bpf", fmt.Sprintf("samwaf-test-%d", time.Now().UnixNano())))
	b, err := getBPFBackend()
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("verifier details:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// 只摘除本测试明确创建的两条链接及固定对象名，不扫描其他服务的 bpffs。
		for _, name := range []string{"input2", "input10"} {
			l, e := link.LoadPinnedLink(filepath.Join(b.pins, name), nil)
			if e == nil {
				_ = l.Unpin()
				_ = l.Close()
			}
		}
		_ = b.groups.Unpin()
		_ = b.active.Unpin()
		_ = b.drops.Unpin()
		_ = os.Remove(filepath.Join(b.pins, "program_input"))
		b.collection.Close()
		_ = os.Remove(b.pins)
		_ = os.Remove(os.Getenv("SAMWAF_BPF_PIN_ROOT"))
	})
	fw := &FireWallEngine{}
	t.Run("fragment-reassembly", func(t *testing.T) { testKernelFragments(t, fw) })
	// IPv4 与 IPv6 都经过 LOCAL_IN，不能只验证 map 写入成功。
	for _, test := range []struct{ name, network, server, source string }{{"v4", "udp4", "127.0.0.1:0", "127.0.0.2:0"}, {"v6", "udp6", "[::1]:0", "[fd00:57::2]:0"}} {
		t.Run(test.name, func(t *testing.T) {
			listener, e := net.ListenPacket(test.network, test.server)
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			local, e := net.ResolveUDPAddr(test.network, test.source)
			if e != nil {
				t.Fatal(e)
			}
			remote, e := net.ResolveUDPAddr(test.network, listener.LocalAddr().String())
			if e != nil {
				t.Fatal(e)
			}
			client, e := net.DialUDP(test.network, local, remote)
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			send := func(want bool) {
				t.Helper()
				_ = listener.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
				if _, e := client.Write([]byte("probe")); e != nil {
					t.Fatal(e)
				}
				buf := make([]byte, 16)
				_, _, e := listener.ReadFrom(buf)
				if (e == nil) != want {
					t.Fatalf("delivery=%v want %v: %v", e == nil, want, e)
				}
			}
			source := local.IP.String()
			send(true)
			if e = fw.BlockIP(source, "test"); e != nil {
				t.Fatal(e)
			}
			send(false)
			if e = fw.UnblockIP(source); e != nil {
				t.Fatal(e)
			}
			send(true)
			if e = fw.RestoreIPSet("other", []string{source}); e != nil {
				t.Fatal(e)
			}
			if e = fw.BlockIP(source, "test"); e != nil {
				t.Fatal(e)
			}
			if e = fw.UnblockIP(source); e != nil {
				t.Fatal(e)
			}
			send(false)
			if e = fw.FlushIPSet("other"); e != nil {
				t.Fatal(e)
			}
			send(true)
		})
	}
	t.Run("tcp-port-scope-and-atomic-rejection", func(t *testing.T) {
		first, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer first.Close()
		second, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		for _, listener := range []net.Listener{first, second} {
			go func(l net.Listener) {
				for {
					connection, err := l.Accept()
					if err != nil {
						return
					}
					connection.Close()
				}
			}(listener)
		}
		dial := func(address string, want bool) {
			t.Helper()
			d := net.Dialer{Timeout: 150 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
			c, err := d.Dial("tcp4", address)
			if c != nil {
				c.Close()
			}
			if (err == nil) != want {
				t.Fatalf("TCP %s delivery=%v want %v: %v", address, err == nil, want, err)
			}
		}
		dial(first.Addr().String(), true)
		dial(second.Addr().String(), true)
		port := first.Addr().(*net.TCPAddr).Port
		if err = fw.ApplyIPSetPortScope("ports", []int{port}); err != nil {
			t.Fatal(err)
		}
		if err = fw.RestoreIPSet("ports", []string{"127.0.0.2"}); err != nil {
			t.Fatal(err)
		}
		dial(first.Addr().String(), false)
		dial(second.Addr().String(), true)
		if err = fw.RestoreIPSet("ports", []string{"invalid"}); err == nil {
			t.Fatal("invalid replacement accepted")
		}
		dial(first.Addr().String(), false)
		// TCP 端口限制不能顺带拦截同端口 UDP。
		probe := newKernelUDPProbe(t, "udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), "127.0.0.2:0")
		probe(true)
		if err = fw.DestroyIPSet("ports"); err != nil {
			t.Fatal(err)
		}
		dial(first.Addr().String(), true)
	})
	t.Run("expiry-without-controller-cleanup", func(t *testing.T) {
		probe := newKernelUDPProbe(t, "udp4", "127.0.0.1:0", "127.0.0.2:0")
		probe(true)
		if err = fw.BlockIPWithExpiry("127.0.0.2", "test", time.Now().Add(2*time.Second).Unix()); err != nil {
			t.Fatal(err)
		}
		probe(false)
		// 等待期间没有调用控制器或清理函数，放行只能来自内核的期限判定。
		time.Sleep(2100 * time.Millisecond)
		probe(true)
	})
	t.Run("pinned-reopen-from-another-process", func(t *testing.T) {
		probe := newKernelUDPProbe(t, "udp4", "127.0.0.1:0", "127.0.0.2:0")
		if err = fw.BlockIP("127.0.0.2", "test"); err != nil {
			t.Fatal(err)
		}
		probe(false)
		child := exec.Command(os.Args[0], "-test.run=^TestEBPFChildOpen$")
		child.Env = append(os.Environ(), "SAMWAF_EBPF_CHILD=1")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("second controller: %v %s", err, output)
		}
		probe(false)
		if err = fw.UnblockIP("127.0.0.2"); err != nil {
			t.Fatal(err)
		}
		probe(true)
	})
	t.Run("kernel-expiry-with-overlap", func(t *testing.T) {
		if err := fw.RestoreTimedIPSet("expiry", map[string]int64{"127.0.0.0/8": 0, "127.0.0.2": time.Now().Add(time.Second).Unix()}); err != nil {
			t.Fatal(err)
		}
		// 等到精确 IP 到期，较短永久网段仍必须生效，不能被过期长前缀遮蔽。
		time.Sleep(1100 * time.Millisecond)
		listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		local, _ := net.ResolveUDPAddr("udp4", "127.0.0.2:0")
		remote, _ := net.ResolveUDPAddr("udp4", listener.LocalAddr().String())
		client, err := net.DialUDP("udp4", local, remote)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		_ = listener.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
		_, _ = client.Write([]byte("probe"))
		_, _, err = listener.ReadFrom(make([]byte, 16))
		if err == nil {
			t.Fatal("expired exact entry masked permanent CIDR")
		}
		if err = fw.FlushIPSet("expiry"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing-ledger-preserves-kernel", func(t *testing.T) {
		probe := newKernelUDPProbe(t, "udp4", "127.0.0.1:0", "127.0.0.2:0")
		if err := fw.BlockIP("127.0.0.2", "test"); err != nil {
			t.Fatal(err)
		}
		probe(false)
		path := filepath.Join(b.dir, "state.json")
		saved := filepath.Join(b.dir, "state.saved")
		if err := os.Rename(path, saved); err != nil {
			t.Fatal(err)
		}
		defer os.Rename(saved, path)
		if _, err := fw.IsIPBlocked("127.0.0.2"); err == nil {
			t.Fatal("missing ledger was interpreted as an empty policy")
		}
		child := exec.Command(os.Args[0], "-test.run=^TestEBPFChildOpen$")
		child.Env = append(os.Environ(), "SAMWAF_EBPF_CHILD=1", "SAMWAF_EBPF_EXPECT_MISSING_LEDGER=1")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("reopen with missing ledger: %v %s", err, output)
		}
		probe(false)
		if err := os.Rename(saved, path); err != nil {
			t.Fatal(err)
		}
		if err := fw.UnblockIP("127.0.0.2"); err != nil {
			t.Fatal(err)
		}
		probe(true)
	})
	t.Run("status-and-scoped-rollback", func(t *testing.T) {
		if err := fw.BlockIP("127.0.0.2", "rollback test"); err != nil {
			t.Fatal(err)
		}
		status, err := BPFStatus()
		if err != nil || !status.Loaded || status.Hook != "LOCAL_IN" || status.DroppedPackets == 0 {
			t.Fatalf("status=%+v err=%v", status, err)
		}
		if err = DetachBPF(false); err == nil {
			t.Fatal("active source detached without explicit confirmation")
		}
		if err = DetachBPF(true); err != nil {
			t.Fatal(err)
		}
		status, err = BPFStatus()
		if err != nil || status.Loaded {
			t.Fatalf("dataplane still attached: %+v %v", status, err)
		}
		if _, err = os.Stat(filepath.Join(b.dir, "state.json")); err != nil {
			t.Fatal("rollback destroyed the durable state")
		}
	})
}

// newKernelUDPProbe 返回实际网络收包断言，用来区分“写表成功”与内核确实执行了策略。
func newKernelUDPProbe(t *testing.T, network, server, source string) func(bool) {
	t.Helper()
	listener, err := net.ListenPacket(network, server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	local, err := net.ResolveUDPAddr(network, source)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := net.ResolveUDPAddr(network, listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP(network, local, remote)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return func(want bool) {
		t.Helper()
		_ = listener.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
		if _, err := client.Write([]byte("probe")); err != nil {
			t.Fatal(err)
		}
		_, _, err := listener.ReadFrom(make([]byte, 16))
		if (err == nil) != want {
			t.Fatalf("UDP delivery=%v want %v: %v", err == nil, want, err)
		}
	}
}

// TestEBPFChildOpen 用独立进程重开共享对象，确认初始化不会用空模板覆盖第一个有效来源。
func TestEBPFChildOpen(t *testing.T) {
	if os.Getenv("SAMWAF_EBPF_CHILD") != "1" {
		t.Skip("helper process only")
	}
	if os.Getenv("SAMWAF_EBPF_EXPECT_MISSING_LEDGER") == "1" {
		if _, err := getBPFBackend(); err == nil {
			t.Fatal("reopened active kernel bans without a ledger")
		}
		return
	}
	var fw FireWallEngine
	active, err := fw.IsIPBlocked("127.0.0.2")
	if err != nil || !active {
		t.Fatalf("pinned state lost: %v %v", active, err)
	}
}
