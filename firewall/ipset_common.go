//go:build linux || windows || darwin

package firewall

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// parseIpsetEntryCount 从 `ipset list -t <name>` 的输出里取 "Number of entries"。
// ok=false 表示没解析出来(集合不存在、命令失败、格式变了)，调用方应按"需要重建"处理。
// 放在这个跨平台文件里是为了能在任意平台跑单测——解析本身是纯字符串逻辑。
func parseIpsetEntryCount(out string) (int, bool) {
	const key = "Number of entries:"
	for _, line := range strings.Split(out, "\n") {
		idx := strings.Index(line, key)
		if idx < 0 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(line[idx+len(key):]))
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// splitByIPVersion 把混合 IP/CIDR 列表按版本分流为 v4、v6 两组(供各平台分别灌入对应集合)。
// 判定优先用 net 解析，无法解析时退化为"含冒号即 v6"。非法项被丢弃。
func splitByIPVersion(items []string) (v4 []string, v6 []string) {
	for _, raw := range items {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		isV6, ok := ipItemIsV6(s)
		if !ok {
			continue
		}
		if isV6 {
			v6 = append(v6, s)
		} else {
			v4 = append(v4, s)
		}
	}
	return v4, v6
}

// ipItemIsV6 判断单个 IP 或 CIDR 是否为 IPv6；ok=false 表示非法项
func ipItemIsV6(s string) (isV6 bool, ok bool) {
	if strings.Contains(s, "/") {
		ip, _, err := net.ParseCIDR(s)
		if err != nil {
			return false, false
		}
		return ip.To4() == nil, true
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false, false
	}
	return ip.To4() == nil, true
}

// ---- SupportsIPSet 探测结果缓存(与 CheckAvailable 一致的 30s TTL) ----

var (
	ipsetSupportMu      sync.Mutex
	ipsetSupportCheckAt time.Time
	ipsetSupportChecked bool
	ipsetSupportErr     error
)

// cachedSupportsIPSet 带缓存地调用各平台 supportsIPSet()，供 SupportsIPSet() 复用
func cachedSupportsIPSet(fw *FireWallEngine) error {
	ipsetSupportMu.Lock()
	defer ipsetSupportMu.Unlock()

	if ipsetSupportChecked && time.Since(ipsetSupportCheckAt) < availableCacheTTL {
		return ipsetSupportErr
	}
	ipsetSupportErr = fw.supportsIPSet()
	ipsetSupportCheckAt = time.Now()
	ipsetSupportChecked = true
	return ipsetSupportErr
}
