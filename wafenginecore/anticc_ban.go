package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"strings"
	"time"
)

// ccBanNotifyThrottle 同一封禁键的提醒推送间隔。
// 被封 IP 会持续重试，逐请求推送会把消息队列刷爆（反向代理环路告警用的是同一套节流思路）。
const ccBanNotifyThrottle = 5 * time.Minute

// matchCCBan 判断该站点的这个客户端当前是否处于 CC 封禁期。
// 依次查全局作用域、本站点作用域，以及升级前写入的旧格式键；命中返回具体的键，便于取时长与做节流。
func matchCCBan(hostCode, netSrcIP, srcIP, ipMode string) (hitKey string, clientIP string) {
	if global.GCACHE_WAFCACHE == nil {
		return "", ""
	}
	clientIP = model.GetClientIPByMode(ipMode, netSrcIP, srcIP)
	if clientIP == "" {
		return "", ""
	}
	keys := append(model.CCBanLookupKeys(hostCode, clientIP), model.LegacyCCBanKey(clientIP))
	for _, key := range keys {
		if global.GCACHE_WAFCACHE.IsKeyExist(key) {
			return key, clientIP
		}
	}
	return "", clientIP
}

// notifyCCBanOnce 推送 CC 封禁提醒，同一封禁键在节流窗口内只推一条。
func notifyCCBanOnce(hitKey, clientIP string, region []string) {
	throttleKey := "cc_ban_notify_" + hitKey
	if global.GCACHE_WAFCACHE.IsKeyExist(throttleKey) {
		return
	}
	global.GCACHE_WAFCACHE.SetWithTTl(throttleKey, "1", ccBanNotifyThrottle)

	serverName := global.GWAF_CUSTOM_SERVER_NAME
	if serverName == "" {
		serverName = "未命名服务器"
	}
	banDuration, _ := global.GCACHE_WAFCACHE.GetInt(hitKey)
	remainingSeconds := 0
	if expireTime, err := global.GCACHE_WAFCACHE.GetExpireTime(hitKey); err == nil {
		if r := int(time.Until(expireTime).Seconds()); r > 0 {
			remainingSeconds = r
		}
	}
	global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.IPBanMessageInfo{
		BaseMessageInfo: innerbean.BaseMessageInfo{
			OperaType: "CC封禁提醒",
			Server:    serverName,
		},
		Ip:               clientIP + " (" + strings.Join(region, ",") + ")",
		Reason:           "CC攻击，访问频次过高",
		Duration:         banDuration,
		RemainingSeconds: remainingSeconds,
		Time:             time.Now().Format("2006-01-02 15:04:05"),
	})
}
