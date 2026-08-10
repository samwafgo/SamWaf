package innerbean

import (
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go/http3"
)

// H3Holder 持有某个端口当前的 HTTP/3(QUIC) 运行实例。
//
// 做成独立对象、并在 ServerRunTime 里以【指针】保存(同 Conns *int64 的用意)：
// ServerRunTime 是按值存进 SafeServerMap 的，值拷贝之间必须共享同一份 h3 状态，
// 否则热开关只会改到某个副本上。
type H3Holder struct {
	// Mu 串行化同一端口上的 启动/停止/重建；写 Conn / BBR 之前必须持有。
	Mu sync.Mutex
	// srv 当前对外服务的 h3.Server；nil 表示该端口未启用 HTTP/3。
	// 用 atomic.Pointer 持有：HTTPS 端口的 Alt-Svc 包装处理器每个请求都要无锁读它，
	// 非 nil 才追加 Alt-Svc 头。这样开关 HTTP/3 不需要在运行期改写 http.Server.Handler
	// (运行期改写 Handler 与在途请求存在数据竞争)。
	srv atomic.Pointer[http3.Server]
	// Conn 我们自己创建的 UDP socket。
	// 注意：quic-go 对 Serve(PacketConn) 传进去的连接标记 createdConn=false，
	// Shutdown/Close 只会停止读取，【不会关闭 fd】，必须由我们自己 Close，
	// 否则关了 HTTP/3 之后 UDP 端口依然被占着(ss -lunp 仍能看到)。
	Conn net.PacketConn
	// BBR 当前实例创建时使用的拥塞算法开关，用于判断配置变更后是否需要重建。
	BBR int64
}

// Server 返回当前活跃的 h3 实例；holder 为 nil 或未启用时返回 nil。
func (h *H3Holder) Server() *http3.Server {
	if h == nil {
		return nil
	}
	return h.srv.Load()
}

// SetServer 原子替换当前活跃的 h3 实例(nil 表示停用)。
func (h *H3Holder) SetServer(s *http3.Server) {
	h.srv.Store(s)
}

type ServerRunTime struct {
	//tcp http https
	ServerType string
	Port       int
	Status     int // 0 是启动完成 ，1 是新增，2 是编辑 3，是删除
	Svr        *http.Server
	// H3 该端口的 HTTP/3 运行状态持有者(仅 https 端口非空)，支持运行期热起停。
	H3 *H3Holder
	// Conns 当前该端口打开的连接数(原子计数)。由 http.Server.ConnState 维护：
	// StateNew +1 ；StateClosed / StateHijacked -1 。用于升级排空时观测"还剩多少连接"。
	// 为指针以便随 ServerRunTime 值在 SafeServerMap 间复制时仍共享同一计数。
	Conns *int64
}
