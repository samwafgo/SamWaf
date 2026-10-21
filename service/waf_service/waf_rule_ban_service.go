package waf_service

import (
	"SamWaf/cache"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"errors"
	"fmt"
	"strconv"
)

type WafRuleBanService struct{}

var WafRuleBanServiceApp = new(WafRuleBanService)

func (s *WafRuleBanService) GetConfigApi() response2.RuleBanConfigResp {
	return response2.RuleBanConfigResp{Mode: global.GCONFIG_RULE_BAN_MODE}
}

func (s *WafRuleBanService) SetConfigApi(req request.WafRuleBanSetConfigReq) error {
	if err := WafSystemConfigServiceApp.ModifyByItemApi(request.WafSystemConfigEditByItemReq{
		Item:  "rule_ban_mode",
		Value: strconv.FormatInt(req.Mode, 10),
	}); err != nil {
		return err
	}
	global.GCONFIG_RULE_BAN_MODE = req.Mode
	return nil
}

func (s *WafRuleBanService) GetBanIpListApi() ([]response2.RuleBanIpResp, error) {
	return ruleBanIPList(global.GCACHE_WAFCACHE, func(hostCode string) string {
		return WafHostServiceApp.GetDetailByCodeApi(hostCode).Host
	})
}

func ruleBanIPList(store cache.CacheStore, hostName func(string) string) ([]response2.RuleBanIpResp, error) {
	keys := store.ListAvailableKeysWithPrefix(enums.CACHE_RULE_BAN_PRE)
	beans := make([]response2.RuleBanIpResp, 0, len(keys))
	for key, duration := range keys {
		hostCode, ip, ok := model.ParseRuleBanKey(key)
		if !ok || ip == "" {
			continue
		}
		var minutes int64
		if err := store.GetAs(key, &minutes); err != nil {
			if errors.Is(err, cache.ErrCacheMiss) {
				continue
			}
			return nil, err
		}

		var remaining string
		totalMinutes := int(duration.Minutes())
		if totalMinutes < 1 {
			remaining = fmt.Sprintf("%d秒", int(duration.Seconds()))
		} else if hours := int(duration.Hours()); hours > 0 {
			remaining = fmt.Sprintf("%d时%02d分", hours, totalMinutes%60)
		} else {
			remaining = fmt.Sprintf("%d分", totalMinutes)
		}

		beans = append(beans, response2.RuleBanIpResp{
			IP:         ip,
			HostCode:   hostCode,
			HostName:   hostName(hostCode),
			BanMinutes: minutes,
			RemainTime: remaining,
			Region:     fmt.Sprintf("%v", utils.GetCountry(ip)),
		})
	}
	return beans, nil
}

func (s *WafRuleBanService) RemoveBanIpApi(req request.WafRuleBanRemoveBanIpReq) {
	removeRuleBanIP(global.GCACHE_WAFCACHE, req.HostCode, req.Ip)
}

func removeRuleBanIP(store cache.CacheStore, hostCode, ip string) {
	if hostCode != "" {
		store.Remove(model.BuildRuleBanKey(hostCode, ip))
		return
	}
	for key := range store.ListAvailableKeysWithPrefix(enums.CACHE_RULE_BAN_PRE) {
		if _, banIP, ok := model.ParseRuleBanKey(key); ok && banIP == ip {
			store.Remove(key)
		}
	}
}
