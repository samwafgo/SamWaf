package wafenginecore

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafbot"
	"net/http"
	"net/url"
	"time"
)

/*
*
检测爬虫
*/
func (waf *WafEngine) CheckBot(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	//检查是否是正常IP已经cache
	isNormalCacheExist := global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_DNS_NORMAL_IP + weblogbean.SRC_IP)

	if isNormalCacheExist {
		return result
	}
	//检查是否是bot已经cache
	isBotCacheExist := global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_DNS_BOT_IP + weblogbean.SRC_IP)
	botResult := wafbot.BotResult{}
	if !isBotCacheExist {
		botResult = wafbot.DetermineNormalSearch(weblogbean.USER_AGENT, weblogbean.SRC_IP)
	} else {
		botResult = global.GCACHE_WAFCACHE.Get(enums.CACHE_DNS_BOT_IP + weblogbean.SRC_IP).(wafbot.BotResult)
	}
	if botResult.IsBot == true {
		weblogbean.IsBot = 1
		if botResult.IsNormalBot {
			weblogbean.GUEST_IDENTIFICATION = botResult.BotName
		} else {
			weblogbean.GUEST_IDENTIFICATION = botResult.BotName
			weblogbean.RISK_LEVEL = 1

			if global.GCONFIG_RECORD_SPIDER_DENY == 1 {
				result.IsBlock = true
			} else {
				result.IsBlock = false
			}
			result.Title = botResult.BotName
			result.Content = "请正确访问"

			if !isBotCacheExist && botResult.BotName != "查询超时" && botResult.BotName != "查询失败" {
				//如果是bot 加入cache里面（排除查询超时和查询失败的情况）
				global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_DNS_BOT_IP+weblogbean.SRC_IP, botResult, time.Duration(global.GCONFIG_RECORD_DNS_BOT_EXPIRE_HOURS)*time.Hour)
			}
			return result
		}

		if !isBotCacheExist && botResult.BotName != "查询超时" && botResult.BotName != "查询失败" {
			//如果是正常爬虫，也保存结果（排除查询超时和查询失败的情况）
			global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_DNS_BOT_IP+weblogbean.SRC_IP, botResult, time.Duration(global.GCONFIG_RECORD_DNS_BOT_EXPIRE_HOURS)*time.Hour)
		}

	} else {
		//如果不是bot 加入到正常cache里面
		global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_DNS_NORMAL_IP+weblogbean.SRC_IP, weblogbean.SRC_IP, time.Duration(global.GCONFIG_RECORD_DNS_NORMAL_EXPIRE_HOURS)*time.Hour)

	}

	return result
}
