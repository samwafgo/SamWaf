package global

import (
	"SamWaf/model"
	"sync"
	"time"
)

// GWAF_IP_WATCH 重点 IP 观察名单的内存缓存。写入路径每条日志都要问一次，不能逐条查库；
// 名单是人工维护的、条数很小，全量放内存，定期重载兜底，增删后由服务层调 Reload 立即生效。
var GWAF_IP_WATCH = &ipWatchCache{ips: map[string]int64{}}

const ipWatchReloadInterval = 30 * time.Second

type ipWatchCache struct {
	mu        sync.RWMutex
	ips       map[string]int64 // ip -> 到期 unix 秒
	loadedAt  time.Time
}

// Has 该 IP 当前是否在观察名单内（未到期）。DB 未初始化时一律视为不在。
func (c *ipWatchCache) Has(ip string) bool {
	if ip == "" {
		return false
	}
	c.reloadIfDue(false)
	c.mu.RLock()
	exp, ok := c.ips[ip]
	c.mu.RUnlock()
	return ok && exp > time.Now().Unix()
}

// Reload 名单增删后立即重载。
func (c *ipWatchCache) Reload() {
	c.reloadIfDue(true)
}

func (c *ipWatchCache) reloadIfDue(force bool) {
	if GWAF_LOCAL_DB == nil {
		return
	}
	c.mu.RLock()
	due := time.Since(c.loadedAt) > ipWatchReloadInterval
	c.mu.RUnlock()
	if !force && !due {
		return
	}
	var rows []model.IPWatchlist
	if err := GWAF_LOCAL_DB.Select("ip", "expire_at").
		Where("expire_at > ?", time.Now().Unix()).Find(&rows).Error; err != nil {
		return
	}
	m := make(map[string]int64, len(rows))
	for _, r := range rows {
		m[r.IP] = r.ExpireAt
	}
	c.mu.Lock()
	c.ips = m
	c.loadedAt = time.Now()
	c.mu.Unlock()
}
