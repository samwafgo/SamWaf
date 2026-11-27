//go:build windows || darwin

package firewall

// BlockIPWithExpiry 保留原生平台行为；这些平台由现有到期清理服务撤销规则。
func (fw *FireWallEngine) BlockIPWithExpiry(ip, reason string, expiry int64) error {
	return fw.BlockIP(ip, reason)
}

// RestoreTimedIPSet 在非 Linux 平台复用其原生集合 API，期限仍由数据库维护。
func (fw *FireWallEngine) RestoreTimedIPSet(name string, entries map[string]int64) error {
	ips := make([]string, 0, len(entries))
	for ip := range entries {
		ips = append(ips, ip)
	}
	return fw.RestoreIPSet(name, ips)
}

// AddTimedToIPSet 保持原有增量语义，不改变非 Linux 平台的防火墙实现。
func (fw *FireWallEngine) AddTimedToIPSet(name string, entries map[string]int64) error {
	ips := make([]string, 0, len(entries))
	for ip := range entries {
		ips = append(ips, ip)
	}
	return fw.AddToIPSet(name, ips)
}

// SyncTimedBlocks 保持原平台逐条恢复规则的方式；不会删除其他服务持有的规则。
func (fw *FireWallEngine) SyncTimedBlocks(entries map[string]int64) error {
	for ip, expiry := range entries {
		if err := fw.BlockIPWithExpiry(ip, "startup restore", expiry); err != nil {
			return err
		}
	}
	return nil
}
