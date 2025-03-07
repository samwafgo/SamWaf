package wafenginmodel

import "sync"

type HostStatus struct {
	Mux           sync.Mutex              //状态情况互斥锁
	HealthyStatus map[string]*HostHealthy // hostCode -> status
}
