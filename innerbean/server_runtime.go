package innerbean

import (
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

type ServerRunTime struct {
	//tcp http https
	ServerType string
	Port       int
	Status     int // 0 是启动完成 ，1 是新增，2 是编辑 3，是删除
	Svr        *http.Server
	H3         *http3.Server
	// Conns 当前该端口打开的连接数(原子计数)。由 http.Server.ConnState 维护：
	// StateNew +1 ；StateClosed / StateHijacked -1 。用于升级排空时观测"还剩多少连接"。
	// 为指针以便随 ServerRunTime 值在 SafeServerMap 间复制时仍共享同一计数。
	Conns *int64
}
