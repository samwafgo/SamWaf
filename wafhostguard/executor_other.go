//go:build !linux

package wafhostguard

import "SamWaf/model"

// 非 Linux 平台继续使用原生防火墙执行器。
func platformExecMode() string { return "" }

// applyPlatform 表示本平台继续走已有增量/分片规则路径。
func (e *BanExecutor) applyPlatform(add, del []string) (bool, error) { return false, nil }

// replayPlatform 表示本平台继续走已有启动恢复逻辑。
func (e *BanExecutor) replayPlatform(bans []model.HostGuardBan) (bool, error) { return false, nil }

// platformContains 让原实现继续读取自身镜像。
func (e *BanExecutor) platformContains(ip string) (bool, bool) { return false, false }
