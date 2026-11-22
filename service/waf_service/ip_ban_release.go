package waf_service

import (
	"SamWaf/cache"
	"SamWaf/enums"
	"SamWaf/model"
)

// ReleaseCCIP 解除该 IP 各作用域的 CC 封禁，并在同一后端事务中重置它的共享 CC 额度。
// clearFailure 用于失败统计页，保留其原本“清失败记录和 CC 状态”的范围，不隐式删除独立规则封禁。
func ReleaseCCIP(store cache.CacheStore, ip string, clearFailure bool) error {
	keys, err := cache.KeysE(store, enums.CACHE_CCVISITBAN_PRE)
	if err != nil {
		return err
	}
	remove := []string{}
	for key := range keys {
		if _, _, value, ok := model.ParseCCBanKey(key); ok && value == ip {
			remove = append(remove, key)
		}
	}
	if clearFailure {
		remove = append(remove, enums.CACHE_IP_FAILURE_PRE+ip)
	}
	return cache.ReleaseE(store, remove, ip)
}
