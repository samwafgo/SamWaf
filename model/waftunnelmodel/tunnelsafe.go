package waftunnelmodel

import (
	"SamWaf/model"
	"sync"
)

// TunnelSafe 隧道安全配置
type TunnelSafe struct {
	Mux    sync.Mutex //互斥锁
	Tunnel model.Tunnel
}
