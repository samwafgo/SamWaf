package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"time"
)

// matchRuleBan 判断该站点的这个客户端当前是否处于规则封禁期（自定义规则 RF.Ban 写入）。
func matchRuleBan(hostCode, netSrcIP, srcIP, ipMode string) (hitKey string, clientIP string) {
	if global.GCACHE_WAFCACHE == nil {
		return "", ""
	}
	clientIP = model.GetClientIPByMode(ipMode, netSrcIP, srcIP)
	if clientIP == "" {
		return "", ""
	}
	key := model.BuildRuleBanKey(hostCode, clientIP)
	if global.GCACHE_WAFCACHE.IsKeyExist(key) {
		return key, clientIP
	}
	return "", clientIP
}

// echoRuleBanBlock 按全局配置执行规则封禁拦截：
// rule_ban_mode=1 直接断开连接（444），0 返回拦截页；无法劫持连接时降级为拦截页。
func echoRuleBanBlock(w http.ResponseWriter, r *http.Request, weblogbean *innerbean.WebLog, hostTarget *wafenginmodel.HostSafe, globalHostSafe *wafenginmodel.HostSafe) int {
	if global.GCONFIG_RULE_BAN_MODE == 1 {
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				conn.Close()
				return 444
			}
		}
	}
	return EchoErrorInfo(w, r, weblogbean, "规则封禁", "当前IP已被规则临时封禁", hostTarget, globalHostSafe, false, "")
}

// ruleBanLog 规则封禁拦截的窄行日志（仿 ccBanLog：不含报文与请求体）
func ruleBanLog(log *innerbean.WebLog, responseCode int) *innerbean.WebLog {
	recorded := *log
	recorded.SkipPayloadStore = true
	recorded.HEADER = ""
	recorded.BODY = ""
	recorded.RES_BODY = ""
	recorded.COOKIES = ""
	recorded.POST_FORM = ""
	recorded.ResHeader = ""
	recorded.SrcByteBody = nil
	recorded.SrcByteResBody = nil
	recorded.SrcURL = nil
	recorded.BodyDecoded = ""
	recorded.CookiesDecoded = ""
	recorded.BodyValues = nil
	recorded.BodyFields = nil
	recorded.BodyHash = ""
	recorded.RULE = "规则封禁"
	recorded.ACTION = "阻止"
	recorded.STATUS = "阻止访问"
	if responseCode == 444 {
		recorded.STATUS = "连接关闭"
	}
	recorded.STATUS_CODE = responseCode
	recorded.TASK_FLAG = 1
	recorded.RISK_LEVEL = 1
	recorded.GUEST_IDENTIFICATION = "可疑用户"
	recorded.TimeSpent = time.Now().UnixMilli() - recorded.UNIX_ADD_TIME
	return &recorded
}
