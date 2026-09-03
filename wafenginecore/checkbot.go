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

// botDNSFailCacheSeconds 「查询超时 / 查询失败」这类结果的负缓存时长。
//
// 这类结果原先完全不入缓存，导致 DNS 查不通的 IP 每来一个请求就重查一次；
// 补上正向解析后就是每请求两次查询。用一个远短于正常结果的 TTL 缓存它：
// 太长会把一次 DNS 抖动的错误结论锁住很久，不存则等于持续空转。
const botDNSFailCacheSeconds = 60

// isDNSUncertain 判断是不是「没查出结论」的那两种结果
func isDNSUncertain(name string) bool {
	return name == "查询超时" || name == "查询失败"
}

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
		if err := global.GCACHE_WAFCACHE.GetAs(enums.CACHE_DNS_BOT_IP+weblogbean.SRC_IP, &botResult); err != nil {
			botResult = wafbot.DetermineNormalSearch(weblogbean.USER_AGENT, weblogbean.SRC_IP)
		}
	}
	if botResult.IsBot == true {
		weblogbean.IsBot = 1
		if botResult.StrongVerified {
			weblogbean.BotVerifyStrong = 1
		}
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

			if !isBotCacheExist {
				cacheBotResult(weblogbean.SRC_IP, botResult)
			}
			return result
		}

		if !isBotCacheExist {
			cacheBotResult(weblogbean.SRC_IP, botResult)
		}

	} else {
		//如果不是bot 加入到正常cache里面
		global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_DNS_NORMAL_IP+weblogbean.SRC_IP, weblogbean.SRC_IP, time.Duration(global.GCONFIG_RECORD_DNS_NORMAL_EXPIRE_HOURS)*time.Hour)

	}

	return result
}

// cacheBotResult 写入爬虫判定缓存。
// 有结论的按正常有效期存；没查出结论的（超时/失败）只存很短一段时间，
// 既避免每请求重复查询，也不会把一次 DNS 抖动的结论长期钉死。
func cacheBotResult(ip string, botResult wafbot.BotResult) {
	if ip == "" || global.GCACHE_WAFCACHE == nil {
		return
	}
	ttl := time.Duration(global.GCONFIG_RECORD_DNS_BOT_EXPIRE_HOURS) * time.Hour
	if isDNSUncertain(botResult.BotName) {
		ttl = botDNSFailCacheSeconds * time.Second
	}
	global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_DNS_BOT_IP+ip, botResult, ttl)
}
