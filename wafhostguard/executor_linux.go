//go:build linux

package wafhostguard

import (
	"errors"
	"time"

	"SamWaf/global"
	"SamWaf/model"
)

// platformExecMode 明确报告实际后端，保留旧配置值不等于继续运行系统命令。
func platformExecMode() string { return "ebpf" }

// applyPlatform 先从持久账本取期限，再一次交换内核来源表；成功前不改本进程去重镜像。
func (e *BanExecutor) applyPlatform(add, del []string) (bool, error) {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	entries := map[string]int64{}
	if len(add) > 0 {
		if global.GWAF_LOCAL_DB == nil {
			return true, errors.New("host ban ledger is unavailable")
		}
		var rows []model.HostGuardBan
		if err := global.GWAF_LOCAL_DB.Where("ip IN ? AND status = ? AND (expire_time=0 OR expire_time>?)", add, model.HostBanStatusActive, time.Now().Unix()).Find(&rows).Error; err != nil {
			return true, err
		}
		for _, row := range rows {
			old, ok := entries[row.IP]
			if !ok || row.ExpireTime == 0 || old != 0 && row.ExpireTime > old {
				entries[row.IP] = row.ExpireTime
			}
		}
		for _, ip := range add {
			if _, ok := entries[ip]; !ok {
				return true, errors.New("host ban has no active durable intent")
			}
		}
	}
	start := time.Now()
	if err := e.fw.ChangeTimedIPSet(BanSetName, entries, del); err != nil {
		return true, err
	}
	e.mu.Lock()
	for ip := range entries {
		e.current[ip] = struct{}{}
	}
	for _, ip := range del {
		delete(e.current, ip)
	}
	e.mu.Unlock()
	e.recordSync(start)
	return true, nil
}

// replayPlatform 把未到期记录连同原期限恢复；空账本也会清理该来源遗留规则。
func (e *BanExecutor) replayPlatform(bans []model.HostGuardBan) (bool, error) {
	entries := map[string]int64{}
	for _, ban := range bans {
		old, ok := entries[ban.IP]
		if !ok || ban.ExpireTime == 0 || old != 0 && ban.ExpireTime > old {
			entries[ban.IP] = ban.ExpireTime
		}
	}
	start := time.Now()
	if err := e.fw.RestoreTimedIPSet(BanSetName, entries); err != nil {
		return true, err
	}
	e.mu.Lock()
	e.current = map[string]struct{}{}
	for ip := range entries {
		e.current[ip] = struct{}{}
	}
	e.mu.Unlock()
	e.recordSync(start)
	return true, nil
}

// platformContains 用共享账本去重，避免一个 Worker 误用另一个 Worker 已撤销的本地镜像。
func (e *BanExecutor) platformContains(ip string) (bool, bool) {
	entries, err := e.fw.ReadTimedIPSet(BanSetName)
	if err != nil {
		return true, false
	}
	_, exists := entries[ip]
	return true, exists
}
