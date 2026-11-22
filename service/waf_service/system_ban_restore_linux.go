//go:build linux

package waf_service

import "context"

// RestoreSystemBansOnStartup 在监听前恢复 PostgreSQL 账本，有状态但恢复失败时终止启动。
func RestoreSystemBansOnStartup() error {
	return PeriodicSystemBanReconcile(context.Background(), true)
}
