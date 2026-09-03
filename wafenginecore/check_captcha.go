package wafenginecore

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/wafenginecore/wafcaptcha"
	"net/http"
	"strings"
)

// hasCaptchaPass 该请求是否持有有效的验证码通行凭证。
//
// 与 checkCaptchaToken 的区别：后者还会因为"良性爬虫""证书申请路径"等原因放行，
// 那些都不代表人机验证通过，不能用来判定 CC 的人机验证动作是否已被满足。
func hasCaptchaPass(r *http.Request, clientIP string) bool {
	if global.GCACHE_WAFCACHE == nil || clientIP == "" {
		return false
	}
	if cookie, err := r.Cookie("samwaf_captcha_token"); err == nil && cookie.Value != "" {
		if global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_CAPTCHA_PASS + cookie.Value + clientIP) {
			return true
		}
	}
	if token := r.Header.Get("X-SamWaf-Captcha-Token"); token != "" {
		if global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_CAPTCHA_PASS + token + clientIP) {
			return true
		}
	}
	return false
}

// checkCaptchaToken 返回false 要验证信息 ，true 不验证信息
func (waf *WafEngine) checkCaptchaToken(r *http.Request, webLog innerbean.WebLog, captchaConfig model.CaptchaConfig, ipMode string) bool {
	// 根据IP模式选择使用的IP（从 Host 级别传入）
	clientIP := model.GetClientIPByMode(ipMode, webLog.NetSrcIp, webLog.SRC_IP)

	// 首先从Cookie中获取验证标识
	cookie, err := r.Cookie("samwaf_captcha_token")
	if err == nil && cookie.Value != "" {
		// 检查缓存中是否存在该标识
		if global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_CAPTCHA_PASS + cookie.Value + clientIP) {
			return true
		}
	}

	// 如果Cookie中没有或无效，则检查请求头
	token := r.Header.Get("X-SamWaf-Captcha-Token")
	if token != "" {
		// 检查缓存中是否存在该标识
		if global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_CAPTCHA_PASS + token + clientIP) {
			return true
		}
	}
	//是bot而且危险程度是0，那么不用进行验证码挑战
	if webLog.IsBot == 1 {
		if webLog.RISK_LEVEL == 0 {
			return true
		} else {
			if webLog.GUEST_IDENTIFICATION == "查询超时" || webLog.GUEST_IDENTIFICATION == "查询失败" {
				return true
			}
			//伪爬虫是否开启图形验证
			if global.GCONFIG_RECORD_FAKE_SPIDER_CAPTCHA == 0 {
				return true
			}
		}
	}
	//如果是证书申请情况 也跳过
	if strings.HasPrefix(webLog.URL, global.GSSL_HTTP_CHANGLE_PATH) {
		return true
	}
	return false
}

// 处理验证码
func (waf *WafEngine) handleCaptchaRequest(w http.ResponseWriter, r *http.Request, log *innerbean.WebLog, captchaConfig model.CaptchaConfig, pathPrefix string, ipMode string) {
	// 使用验证码服务处理请求
	captchaService := wafcaptcha.GetService()
	captchaService.HandleCaptchaRequest(w, r, log, captchaConfig, pathPrefix, ipMode)
}
