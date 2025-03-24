package wafenginecore

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/wafenginecore/wafcaptcha"
	"net/http"
)

// checkCaptchaToken 返回false 要验证信息 ，true 不验证信息
func (waf *WafEngine) checkCaptchaToken(r *http.Request, log innerbean.WebLog) bool {
	// 首先从Cookie中获取验证标识
	cookie, err := r.Cookie("samwaf_captcha_token")
	if err == nil && cookie.Value != "" {
		// 检查缓存中是否存在该标识
		if global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_CAPTCHA_PASS + cookie.Value) {
			return true
		}
	}

	// 如果Cookie中没有或无效，则检查请求头
	token := r.Header.Get("X-SamWaf-Captcha-Token")
	if token != "" {
		// 检查缓存中是否存在该标识
		if global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_CAPTCHA_PASS + token) {
			return true
		}
	}
	//是bot而且危险程度是0，那么不用进行验证码挑战
	if log.IsBot == 1 {
		if log.RISK_LEVEL == 0 {
			return true
		} else {
			if log.GUEST_IDENTIFICATION == "查询超时" || log.GUEST_IDENTIFICATION == "查询失败" {
				return true
			}
			//伪爬虫是否开启图形验证
			if global.GCONFIG_RECORD_FAKE_SPIDER_CAPTCHA == 0 {
				return true
			}
		}

	}
	return false
}

// 处理验证码
func (waf *WafEngine) handleCaptchaRequest(w http.ResponseWriter, r *http.Request, expireTime int, log innerbean.WebLog) {
	// 使用验证码服务处理请求
	captchaService := wafcaptcha.GetService()
	captchaService.HandleCaptchaRequest(w, r, expireTime, log)
}
