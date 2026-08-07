package wafhostguard

import (
	"net"
	"sync"
	"time"
)

// 本机地址枚举。放进白名单是"绝不把自己封掉"的基础一环：
// 服务器出网时源地址往往就是自己的某块网卡地址，某些 NAT/回环场景下
// 自己发起的连接在日志里会以本机地址出现，封了就等于自己打自己。

var (
	localAddrMu      sync.RWMutex
	localAddrCache   []string
	localAddrLoadAt  time.Time
	localAddrCacheGC = 5 * time.Minute
)

// LocalAddrs 返回本机所有网卡上的 IP(含 IPv6)，带 5 分钟缓存。
// 加缓存是因为 net.Interfaces() 要遍历系统网卡表，而白名单判定在爆破高峰下
// 每秒会被调用几十上百次。
func LocalAddrs() []string {
	localAddrMu.RLock()
	if localAddrCache != nil && time.Since(localAddrLoadAt) < localAddrCacheGC {
		addrs := localAddrCache
		localAddrMu.RUnlock()
		return addrs
	}
	localAddrMu.RUnlock()

	localAddrMu.Lock()
	defer localAddrMu.Unlock()
	// 双检：可能有别的 goroutine 在等锁期间已经刷新过了
	if localAddrCache != nil && time.Since(localAddrLoadAt) < localAddrCacheGC {
		return localAddrCache
	}

	addrs := make([]string, 0, 8)
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			ias, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range ias {
				var ip net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil {
					continue
				}
				addrs = append(addrs, ip.String())
			}
		}
	}
	localAddrCache = addrs
	localAddrLoadAt = time.Now()
	return addrs
}

// InvalidateLocalAddrs 丢弃缓存，下次调用重新枚举(网卡变更/手工刷新时用)
func InvalidateLocalAddrs() {
	localAddrMu.Lock()
	localAddrCache = nil
	localAddrMu.Unlock()
}
