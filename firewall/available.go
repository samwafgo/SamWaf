//go:build linux || windows || darwin

package firewall

import (
	"sync"
	"time"
)

// availableCacheTTL 能力探测结果的缓存时长，避免批量封禁时反复 exec 外部命令
const availableCacheTTL = 30 * time.Second

var (
	availableMu       sync.Mutex
	availableCheckAt  time.Time
	availableChecked  bool
	availableCheckErr error
)

// CheckAvailable 检测当前运行环境是否具备系统防火墙封禁能力。
// 返回 nil 表示可用；否则返回可直接展示给用户的中文原因。
// 结果在 availableCacheTTL 内复用，实际探测逻辑由各平台的 checkAvailable 实现。
func (fw *FireWallEngine) CheckAvailable() error {
	availableMu.Lock()
	defer availableMu.Unlock()

	if availableChecked && time.Since(availableCheckAt) < availableCacheTTL {
		return availableCheckErr
	}

	availableCheckErr = fw.checkAvailable()
	availableCheckAt = time.Now()
	availableChecked = true
	return availableCheckErr
}
