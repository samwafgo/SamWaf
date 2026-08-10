package wafenginecore

// 回归 issue #916：「开启HTTP3功能不生效，UDP端口未被监听」。
//
// 该 issue 里叠了三个独立缺陷，本文件逐个钉死：
//  1. h3.QUICConfig 是 *quic.Config，零值 nil；老代码直接写 h3.QUICConfig.Congestion
//     会空指针 panic，且 panic 发生在 TCP 监听之前，连带把同端口的 HTTPS 一起搞挂。
//  2. h3 沿用了面向 TCP 的 ssl_max_version：quic-go 会把 MinVersion 顶到 TLS 1.3 却不动
//     MaxVersion，一旦 MaxVersion < 1.3 就每次握手都失败(而 HTTPS/TCP 完全正常)。
//  3. quic-go 对 Serve(PacketConn) 传入的 socket 记 createdConn=false，
//     Shutdown/Close 只停读不关 fd —— 不自己 Close 就是 UDP 端口泄漏。

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/wafenginmodel"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// ---------------------------------------------------------------------------
// 缺陷 1：AST 护栏 —— 任何 http3.Server 复合字面量都必须显式带 QUICConfig
// ---------------------------------------------------------------------------

func TestHTTP3ServerLiteralMustInitQUICConfig(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("读取包目录失败: %v", err)
	}

	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", e.Name(), err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "Server" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "http3" {
				return true
			}
			checked++
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "QUICConfig" {
					return true
				}
			}
			t.Errorf("%s:%d 构造 http3.Server 时没有初始化 QUICConfig。\n"+
				"QUICConfig 的类型是 *quic.Config，零值为 nil；后续任何 h3.QUICConfig.Xxx = ... "+
				"都会空指针 panic，而且 panic 发生在 TCP 监听建立之前，会连带把同端口的 HTTPS 一起搞挂(issue #916)。\n"+
				"请显式写成 QUICConfig: &quic.Config{...}。",
				fset.Position(lit.Pos()).Filename, fset.Position(lit.Pos()).Line)
			return true
		})
	}

	if checked == 0 {
		t.Fatal("没有在本包里找到任何 http3.Server 字面量，护栏失效——请检查用例是否需要同步调整")
	}
}

// 直接跑一次带 BBR 的构造路径，确保不会 panic（老代码在这里必崩）。
func TestStartHTTP3WithBBRDoesNotPanic(t *testing.T) {
	restore := setHTTP3Config(t, 1, 1)
	defer restore()

	waf := newCertOnlyEngine(t)
	holder := &innerbean.H3Holder{}
	port := freeUDPPort(t)

	waf.startHTTP3(port, holder)
	defer waf.stopHTTP3(port, holder)

	if holder.Server() == nil {
		t.Fatal("开启 BBR 时 HTTP/3 没能启动（老代码会在 h3.QUICConfig.Congestion 处空指针 panic）")
	}
	if holder.BBR != 1 {
		t.Fatalf("holder.BBR = %d, 期望 1", holder.BBR)
	}
}

// ---------------------------------------------------------------------------
// 缺陷 2：ssl_max_version 低于 TLS 1.3 时，HTTP/3 仍必须能握手
// ---------------------------------------------------------------------------

func TestHTTP3HandshakeIgnoresSSLMaxVersionConfig(t *testing.T) {
	// 这些值都会让 utils.ParseTLSVersion 得到 < TLS1.3 的结果
	// （最后两个是拼写不匹配，ParseTLSVersion 一律兜底成 TLS 1.2）
	for _, maxVer := range []string{"TLS 1.2", "TLS 1.3", "TLS1.3", ""} {
		maxVer := maxVer
		t.Run("ssl_max_version="+maxVer, func(t *testing.T) {
			restore := setHTTP3Config(t, 1, 0)
			defer restore()
			oldMax := global.GCONFIG_RECORD_SSLMaxVerson
			oldMin := global.GCONFIG_RECORD_SSLMinVerson
			global.GCONFIG_RECORD_SSLMaxVerson = maxVer
			global.GCONFIG_RECORD_SSLMinVerson = "TLS 1.2"
			defer func() {
				global.GCONFIG_RECORD_SSLMaxVerson = oldMax
				global.GCONFIG_RECORD_SSLMinVerson = oldMin
			}()

			waf := newCertOnlyEngine(t)
			holder := &innerbean.H3Holder{}
			port := freeUDPPort(t)

			waf.startHTTP3(port, holder)
			defer waf.stopHTTP3(port, holder)
			if holder.Server() == nil {
				t.Fatal("HTTP/3 未能启动")
			}

			if err := h3Handshake(t, port); err != nil {
				t.Fatalf("HTTP/3 握手失败: %v\n"+
					"HTTP/3 按 RFC 9001 强制使用 TLS 1.3，不能沿用面向 TCP 的 ssl_max_version；"+
					"否则 quic-go 把 MinVersion 顶到 1.3 而 MaxVersion 仍是 1.2，"+
					"每次握手都会 CRYPTO_ERROR 0x146 protocol version not supported(issue #916)", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 缺陷 3：停止 HTTP/3 必须真正关闭 UDP socket
// ---------------------------------------------------------------------------

func TestStopHTTP3ReleasesUDPSocket(t *testing.T) {
	restore := setHTTP3Config(t, 1, 0)
	defer restore()

	waf := newCertOnlyEngine(t)
	holder := &innerbean.H3Holder{}
	port := freeUDPPort(t)

	waf.startHTTP3(port, holder)
	pconn := holder.Conn
	if pconn == nil {
		t.Fatal("启动后 holder.Conn 为空")
	}

	waf.stopHTTP3(port, holder)

	if holder.Server() != nil {
		t.Error("停止后 holder.Server() 仍非空，Alt-Svc 会继续广告一个已关闭的端口")
	}
	if holder.Conn != nil {
		t.Error("停止后 holder.Conn 未清空")
	}
	// quic-go 不会替我们关这个 socket，关不掉就是 UDP 端口泄漏。
	// 用 SetReadDeadline 探测：socket 已关返回 net.ErrClosed，未关返回 nil（不会阻塞）。
	if err := pconn.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("UDP socket 未被关闭(err=%v)。quic-go 对 Serve(PacketConn) 传入的连接记 createdConn=false，"+
			"Shutdown/Close 只停读不关 fd，必须由我们自己 Close，否则关掉 HTTP/3 后 UDP 端口依然被占着(issue #916)", err)
	}
}

// 关掉全局开关后，ReconcileHTTP3 必须把已有的 QUIC 监听停掉。
func TestReconcileHTTP3StartsAndStops(t *testing.T) {
	restore := setHTTP3Config(t, 1, 0)
	defer restore()

	waf := newCertOnlyEngine(t)
	port := freeUDPPort(t)
	holder := &innerbean.H3Holder{}
	waf.ServerOnline.Set(port, innerbean.ServerRunTime{
		ServerType: "https",
		Port:       port,
		Status:     0,
		H3:         holder,
	})

	waf.ReconcileHTTP3()
	if holder.Server() == nil {
		t.Fatal("http3=1 时 reconcile 没有启动 QUIC 监听")
	}

	// 幂等：再对齐一次不应该重建
	srv := holder.Server()
	waf.ReconcileHTTP3()
	if holder.Server() != srv {
		t.Error("reconcile 不幂等：同样配置下重建了 h3 实例")
	}

	global.GCONFIG_ENABLE_HTTP3 = 0
	waf.ReconcileHTTP3()
	if holder.Server() != nil {
		t.Error("http3=0 时 reconcile 没有停止 QUIC 监听")
	}
	if holder.Conn != nil {
		t.Error("http3=0 时 UDP socket 未释放")
	}
}

// 正在关停的 Worker 不能再把 QUIC 拉起来（升级排空期的保护）。
func TestReconcileHTTP3SkippedWhenShuttingDown(t *testing.T) {
	restore := setHTTP3Config(t, 1, 0)
	defer restore()

	oldSignal := global.GWAF_SHUTDOWN_SIGNAL
	global.GWAF_SHUTDOWN_SIGNAL = true
	defer func() { global.GWAF_SHUTDOWN_SIGNAL = oldSignal }()

	waf := newCertOnlyEngine(t)
	holder := &innerbean.H3Holder{}
	waf.ServerOnline.Set(443, innerbean.ServerRunTime{
		ServerType: "https", Port: 443, Status: 0, H3: holder,
	})

	waf.ReconcileHTTP3()
	if holder.Server() != nil {
		t.Error("系统正在关停时不应该再启动 QUIC 监听")
	}
}

// ---------------------------------------------------------------------------
// Alt-Svc 包装器：holder 未启用时不得下发 Alt-Svc
// ---------------------------------------------------------------------------

func TestAltSvcHandlerOnlyAdvertisesWhenH3Active(t *testing.T) {
	waf := newCertOnlyEngine(t)
	holder := &innerbean.H3Holder{}

	rec := &headerOnlyRecorder{header: http.Header{}}
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Host = "example.com"

	waf.altSvcHandler(holder, "443").ServeHTTP(rec, req)

	if got := rec.header.Get("Alt-Svc"); got != "" {
		t.Errorf("HTTP/3 未启用时不应下发 Alt-Svc，实际=%q", got)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// setHTTP3Config 设置 http3/http3_bbr 全局开关，返回还原函数。
func setHTTP3Config(t *testing.T, enable, bbr int64) func() {
	t.Helper()
	oldEnable := global.GCONFIG_ENABLE_HTTP3
	oldBBR := global.GCONFIG_ENABLE_HTTP3_BBR
	oldDrain := global.GCONFIG_RECORD_DRAIN_TIMEOUT
	global.GCONFIG_ENABLE_HTTP3 = enable
	global.GCONFIG_ENABLE_HTTP3_BBR = bbr
	global.GCONFIG_RECORD_DRAIN_TIMEOUT = 2
	return func() {
		global.GCONFIG_ENABLE_HTTP3 = oldEnable
		global.GCONFIG_ENABLE_HTTP3_BBR = oldBBR
		global.GCONFIG_RECORD_DRAIN_TIMEOUT = oldDrain
	}
}

// newCertOnlyEngine 造一个只带自签证书的引擎，够 QUIC 握手用。
func newCertOnlyEngine(t *testing.T) *WafEngine {
	t.Helper()
	waf := &WafEngine{
		ServerOnline:   wafenginmodel.NewSafeServerMap(),
		AllCertificate: AllCertificate{Map: map[string]*tls.Certificate{}},
	}
	waf.AllCertificate.Map["localhost"] = selfSignedCert(t)
	waf.AllCertificate.Map["127.0.0.1"] = waf.AllCertificate.Map["localhost"]
	return waf
}

func selfSignedCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// freeUDPPort 取一个当前空闲的 UDP 端口号。
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}

// h3Handshake 只做一次真实的 QUIC(ALPN=h3) 握手。
//
// 刻意不发 HTTP 请求：本用例要验证的是握手层的 TLS 版本协商，
// 走完整请求会落到 waf.ServeHTTP，牵扯一堆测试环境里没初始化的全局对象。
func h3Handshake(t *testing.T, port int) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, "127.0.0.1:"+strconv.Itoa(port), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		NextProtos:         []string{"h3"},
	}, nil)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")

	if proto := conn.ConnectionState().TLS.NegotiatedProtocol; proto != "h3" {
		return errors.New("ALPN 协商结果不是 h3，实际=" + proto)
	}
	return nil
}

// headerOnlyRecorder 只收集响应头，够 Alt-Svc 断言用。
type headerOnlyRecorder struct {
	header http.Header
}

func (r *headerOnlyRecorder) Header() http.Header         { return r.header }
func (r *headerOnlyRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *headerOnlyRecorder) WriteHeader(int)             {}
