package wafenginecore

import (
	"context"
	"net/http"

	"SamWaf/cache"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
)

// ipBanState 保存一次批量读取的结果；CC 保持全局/本站/旧格式的原有优先级。
type ipBanState struct{ ClientIP, CCKey, RuleKey string }

// lookupIPBans 把原先四次串行 PostgreSQL 往返合为一次，错误不再按未封禁处理。
func lookupIPBans(ctx context.Context, hostCode, netIP, sourceIP, mode string) (ipBanState, error) {
	state := ipBanState{ClientIP: model.GetClientIPByMode(mode, netIP, sourceIP)}
	if state.ClientIP == "" {
		return state, nil
	}
	ccKeys := append(model.CCBanLookupKeys(hostCode, state.ClientIP), model.LegacyCCBanKey(state.ClientIP))
	ruleKey := model.BuildRuleBanKey(hostCode, state.ClientIP)
	keys := append(append([]string(nil), ccKeys...), ruleKey)
	hits, err := cache.ExistsKeysE(ctx, global.GCACHE_WAFCACHE, keys)
	if err != nil {
		return state, err
	}
	for _, key := range ccKeys {
		if hits[key] {
			state.CCKey = key
			break
		}
	}
	if hits[ruleKey] {
		state.RuleKey = ruleKey
	}
	return state, nil
}

// securityBackendUnavailable 返回服务故障而不是“IP 已封禁”，不发送攻击提醒、不记入失败计数。
func securityBackendUnavailable(w http.ResponseWriter, r *http.Request, log *innerbean.WebLog) {
	w.Header().Set("Retry-After", "1")
	http.Error(w, "防护状态暂不可用，请稍后重试", http.StatusServiceUnavailable)
	if log != nil && global.GQEQUE_LOG_DB != nil {
		record := ruleBanLog(log, http.StatusServiceUnavailable)
		record.RULE = "防护后端不可用"
		record.ACTION = "服务不可用"
		record.STATUS = "服务暂不可用"
		record.RISK_LEVEL = 0
		record.SkipFailureCount = true
		global.GQEQUE_LOG_DB.Enqueue(record)
	}
}
