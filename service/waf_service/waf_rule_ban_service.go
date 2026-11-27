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
	keys, listErr := cache.KeysE(store, enums.CACHE_RULE_BAN_PRE)
	if listErr != nil {
		return nil, listErr
	}
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

// RemoveBanIpApi 只有后端确认删除后才允许管理接口返回成功。
func (s *WafRuleBanService) RemoveBanIpApi(req request.WafRuleBanRemoveBanIpReq) error {
	return removeRuleBanIP(global.GCACHE_WAFCACHE, req.HostCode, req.Ip)
}

// removeRuleBanIP 保留本站/全部站点作用域，并传播枚举或删除失败。
func removeRuleBanIP(store cache.CacheStore, hostCode, ip string) error {
	if hostCode != "" {
		return cache.ReleaseE(store, []string{model.BuildRuleBanKey(hostCode, ip)}, "")
	}
	keys, err := cache.KeysE(store, enums.CACHE_RULE_BAN_PRE)
	if err != nil {
		return err
	}
	remove := []string{}
	for key := range keys {
		if _, banIP, ok := model.ParseRuleBanKey(key); ok && banIP == ip {
			remove = append(remove, key)
		}
	}
	return cache.ReleaseE(store, remove, "")
}
