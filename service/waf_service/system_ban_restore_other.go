//go:build !linux

package waf_service

// RestoreSystemBansOnStartup 非 Linux 平台保留原生规则的生命周期，不应用 eBPF 迁移。
func RestoreSystemBansOnStartup() error { return nil }
