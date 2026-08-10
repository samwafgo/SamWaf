package wafenginecore

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/utils"
	"SamWaf/wafnet"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// 本文件集中处理 HTTP/3(QUIC) 的起停与热生效。
//
// 背景(issue #916)：HTTP/3 原先只在 StartProxyServer 内联创建一次，而 StartProxyServer 对
// 已在监听的端口(Status==0)直接 return，导致【改配置永远不生效，只能重启进程】；
// 且 h3 沿用了面向 TCP 的 TLS 版本区间，MaxVersion 低于 1.3 时 QUIC 握手必然失败。

// newH3TLSConfig 构造 HTTP/3 专用的 TLS 配置。
//
// 有意【不挂 GetConfigForClient】：h2 那份回调返回的 NextProtos 是 h2/http1.1，
// 虽然 quic-go 的 ConfigureTLSConfig 会递归修正回 "h3"，但这里没有按 SNI 定制 ALPN 的需求，
// 保持最小面即可(h3 与 h2 是独立 ALPN，互不影响)。
//
// 版本区间【不能】沿用 ssl_min_version / ssl_max_version：
// QUIC 按 RFC 9001 强制使用 TLS 1.3，quic-go 内部会把 MinVersion 顶到 1.3
// (internal/handshake/tls_config.go)，却不会动 MaxVersion。一旦 MaxVersion 低于 1.3
// —— 包括 utils.ParseTLSVersion 对空值/拼写错误(如 "TLS1.3")一律兜底成 TLS 1.2 的情况 ——
// 就会出现 Min(1.3) > Max(1.2)，每一次 QUIC 握手都以
// CRYPTO_ERROR 0x146 "tls: protocol version not supported" 失败；
// 而 HTTPS(TCP) 用同一对配置跑 TLS 1.2 完全正常，于是表现为
// 「Alt-Svc 有、UDP 也在监听，就是连不上 HTTP/3」且无任何日志(issue #916)。
func (waf *WafEngine) newH3TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: waf.GetCertificateFunc,
		MinVersion:     tls.VersionTLS13,
		MaxVersion:     tls.VersionTLS13,
	}
}

// altSvcHandler 是所有 HTTPS 端口【固定】安装的处理器。
//
// 只有当该端口当前存在活跃的 HTTP/3 实例时才追加 Alt-Svc，因此 http3 开关可以热生效，
// 而不必在运行期改写 http.Server.Handler(改写 Handler 与在途请求存在数据竞争)。
func (waf *WafEngine) altSvcHandler(holder *innerbean.H3Holder, port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h3 := holder.Server(); h3 != nil {
			// 关了 h2 的站点不广告 h3(Alt-Svc)：原生 WebSocket 客户端同样不能走 h3，
			// 避免其被诱导升级到 h3 后再次握手失败，让该站点彻底只走 http/1.1。
			reqDomain := r.Host
			if idx := strings.IndexByte(reqDomain, ':'); idx >= 0 {
				reqDomain = reqDomain[:idx]
			}
			if !waf.isHTTP2DisabledForServerName(reqDomain, port) {
				// 监听器尚未就绪时返回 ErrNoAltSvcPort，忽略即可(下一次请求自然会带上)
				_ = h3.SetQUICHeaders(w.Header())
			}
		}
		waf.ServeHTTP(w, r)
	})
}

// ReconcileHTTP3 把所有在线 HTTPS 端口的 QUIC 监听状态对齐到当前全局配置。
//
// 幂等：启动、零空档重载、配置热变更都可以重复调用。
func (waf *WafEngine) ReconcileHTTP3() {
	if waf == nil || waf.ServerOnline == nil {
		return
	}
	if global.GWAF_SHUTDOWN_SIGNAL {
		// 正在关停/排空的 Worker 不要再把 QUIC 拉起来
		return
	}
	defer func() {
		if e := recover(); e != nil {
			zlog.Warn("[HTTP3] reconcile recover ", e)
		}
	}()

	want := global.GCONFIG_ENABLE_HTTP3 == 1
	var skipped []string
	waf.ServerOnline.Range(func(port int, v innerbean.ServerRunTime) bool {
		if v.H3 == nil {
			// 只有 https 端口才会建 holder。这里落到的是 http 端口 / 尚未起监听的端口。
			if want && v.Status == 0 && v.ServerType != "" {
				skipped = append(skipped, strconv.Itoa(port)+"("+v.ServerType+")")
			}
			return true
		}
		if want {
			waf.startHTTP3(port, v.H3)
		} else {
			waf.stopHTTP3(port, v.H3)
		}
		return true
	})
	if want && len(skipped) > 0 {
		// 以前 http3 对非 https 端口静默不生效，用户完全看不出来
		zlog.Info("[HTTP3] 已开启 http3，但下列端口不是 HTTPS 端口，不会监听 UDP" +
			"(HTTP/3 必须基于 TLS，请把站点设为 SSL): " + strings.Join(skipped, ","))
	}
}

// startHTTP3 幂等地为某个 HTTPS 端口启动 QUIC(UDP) 监听。
//
// 独立 recover：QUIC 侧任何异常都不能拖垮同端口的 HTTPS(TCP) 监听 ——
// 这正是 issue #916 里 QUICConfig 空指针 panic 连带把 HTTPS 也搞挂的次生故障。
func (waf *WafEngine) startHTTP3(port int, holder *innerbean.H3Holder) {
	if holder == nil {
		return
	}
	defer func() {
		if e := recover(); e != nil {
			zlog.Error("[HTTP3] 启动异常(HTTPS/TCP 不受影响) port="+strconv.Itoa(port), e)
		}
	}()
	holder.Mu.Lock()
	defer holder.Mu.Unlock()

	bbr := global.GCONFIG_ENABLE_HTTP3_BBR
	if holder.Server() != nil {
		if holder.BBR == bbr {
			// 已经是期望状态
			return
		}
		zlog.Info("[HTTP3] 拥塞算法配置变更，重建端口 " + strconv.Itoa(port) + " 的 QUIC 监听")
		waf.stopHTTP3Locked(port, holder)
	}

	addr := ":" + strconv.Itoa(port)
	// 先绑定成功再宣告：老代码把「启动HTTPS 3 服务器」打在 bind 之前，端口被占时日志会说谎。
	// 用端口复用的 UDP PacketConn，使升级重叠期新旧 Worker 同端口并存。
	pconn, perr := wafnet.ReusePortPacketConn(addr)
	if perr != nil {
		zlog.Error("[HTTP3] UDP 监听失败 " + addr + " : " + perr.Error())
		waf.logH3SysError("HTTP3(UDP)监听失败: " + addr + " 原因:" + perr.Error() +
			" ，请检查该UDP端口是否被占用或被防火墙/安全组拦截")
		return
	}

	h3 := &http3.Server{
		Addr:      addr,
		Handler:   waf,
		TLSConfig: waf.newH3TLSConfig(),
		// QUICConfig 必须显式初始化：它是 *quic.Config，零值为 nil，
		// 直接写 h3.QUICConfig.Congestion 会空指针 panic，且 panic 发生在 TCP 监听之前，
		// 会连带把同端口的 HTTPS 一起搞挂(issue #916)。
		QUICConfig: &quic.Config{Allow0RTT: true},
	}
	if bbr == 1 {
		h3.QUICConfig.Congestion = func() quic.SendAlgorithmWithDebugInfos { return quic.NewBBRv1(nil) }
	}

	holder.Conn = pconn
	holder.BBR = bbr
	holder.SetServer(h3)

	go func() {
		defer func() {
			if e := recover(); e != nil {
				zlog.Warn("[HTTP3] serve recover ", e)
			}
		}()
		err := h3.Serve(pconn)
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			zlog.Info("[HTTP3] 端口 " + strconv.Itoa(port) + " QUIC 监听已停止")
			return
		}
		zlog.Error("[HTTP3] 端口 " + strconv.Itoa(port) + " QUIC 服务异常退出: " + err.Error())
		waf.logH3SysError("HTTP3服务异常退出: " + strconv.Itoa(port) + " 原因:" + err.Error())
	}()

	// 真正绑定成功之后才宣告，并带上实际的 UDP 地址
	zlog.Info("[HTTP3] 已启动 HTTP/3(QUIC) 监听 udp " + pconn.LocalAddr().String() +
		" bbr=" + strconv.FormatInt(bbr, 10) + " ，请确认防火墙/安全组已放行该 UDP 端口")

	// 配置与实际行为不一致时给出提示，避免再次出现「配置写着 TLS 1.2 却跑 1.3」的疑惑
	if utils.ParseTLSVersion(global.GCONFIG_RECORD_SSLMaxVerson) < tls.VersionTLS13 {
		zlog.Info("[HTTP3] 当前【SSL最大版本】为 " + global.GCONFIG_RECORD_SSLMaxVerson +
			" ，低于 TLS 1.3；HTTP/3 按 RFC 9001 强制使用 TLS 1.3，不受该配置限制(HTTPS/TCP 仍按该配置执行)")
	}
}

// stopHTTP3 停止某端口的 QUIC 监听并释放 UDP socket。
func (waf *WafEngine) stopHTTP3(port int, holder *innerbean.H3Holder) {
	if holder == nil {
		return
	}
	holder.Mu.Lock()
	defer holder.Mu.Unlock()
	waf.stopHTTP3Locked(port, holder)
}

// stopHTTP3Locked 调用方必须持有 holder.Mu。
func (waf *WafEngine) stopHTTP3Locked(port int, holder *innerbean.H3Holder) {
	h3 := holder.Server()
	if h3 == nil {
		// 可能存在只建了 socket 没建 server 的残留，一并释放
		if holder.Conn != nil {
			_ = holder.Conn.Close()
			holder.Conn = nil
		}
		return
	}
	// 先摘 Alt-Svc：新响应立刻不再把客户端引导到即将关闭的 UDP 端口
	holder.SetServer(nil)

	timeout := time.Duration(global.GCONFIG_RECORD_DRAIN_TIMEOUT) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	if err := h3.Shutdown(ctx); err != nil {
		_ = h3.Close()
	}
	cancel()

	// quic-go 对 Serve(PacketConn) 传入的 socket 记为 createdConn=false，
	// Shutdown/Close 只停读不关 fd —— 不自己 Close，UDP 端口会一直被占着。
	if holder.Conn != nil {
		_ = holder.Conn.Close()
		holder.Conn = nil
	}
	zlog.Info("[HTTP3] 端口 " + strconv.Itoa(port) + " 的 QUIC 监听已关闭，UDP socket 已释放")
}

// logH3SysError 把 HTTP/3 的失败写进管理端【系统日志】。
// 以前 HTTP/3 失败只有 zlog.Error，管理端页面上什么都看不到。
func (waf *WafEngine) logH3SysError(content string) {
	if global.GQEQUE_LOG_DB == nil {
		return
	}
	global.GQEQUE_LOG_DB.Enqueue(&model.WafSysLog{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		OpType:    "系统运行错误",
		OpContent: content,
	})
}
