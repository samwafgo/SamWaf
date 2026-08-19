package middleware

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafhostguard"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	wafTokenInfoService = waf_service.WafTokenInfoServiceApp
	wafOtpService       = waf_service.WafOtpServiceApp
)

// TokenOnlyAuth 仅允许后台 Token 登录访问，拒绝 OpenAPI Key 方式
// 用于保护「开放平台管理」类接口（Key管理、调用日志、API文档），防止通过 API Key 自行操作
func TokenOnlyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("X-API-Key") != "" {
			response.AuthFailWithMessage("该接口不允许通过 API Key 访问，请使用后台账号登录", c)
			c.Abort()
			return
		}
		// 复用 Token 校验逻辑
		Auth()(c)
	}
}

// Auth 鉴权中间件
func Auth() gin.HandlerFunc {
	innerName := "Auth"
	return func(c *gin.Context) {
		// 优先检查 OpenAPI Key（X-API-Key）
		apiKey := c.GetHeader("X-API-Key")
		if apiKey != "" {
			_, ok := ValidateOpenApiKey(c, apiKey)
			if !ok {
				c.Abort()
				return
			}
			c.Next()
			return
		}

		// 获取请求头中 token，实际是一个完整被签名过的 token；a complete, signed token
		tokenStr := ""
		loginType := c.GetHeader("X-Login-Type")

		if c.Request.RequestURI == "/api/v1/ws" {
			tokenStr = c.GetHeader("Sec-WebSocket-Protocol")
		} else if strings.HasPrefix(c.Request.RequestURI, "/api/v1/waflog/attack/download") {
			tokenStr = c.Query("X-Token")
		} else {
			// 根据登录类型获取不同的token头部
			if loginType == "mobile" {
				tokenStr = c.GetHeader("X-Mobile-Token")
			} else {
				tokenStr = c.GetHeader("X-Token")
			}
		}
		if tokenStr == "" {
			zlog.Debug("无token")

			response.AuthFailWithMessage("鉴权失败", c)
			c.Abort()
			return
		} else {
			//检查是否存在
			isTokenExist := global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_TOKEN + tokenStr)
			if !isTokenExist {
				// 这条分支以前一行日志都没有，用户遇到"登录后无限跳登录页"时服务端完全是黑盒（issue #938）。
				// 令牌只打前 8 位，避免把可用凭证写进日志。
				zlog.Debug(fmt.Sprintf("令牌不在缓存中(已过期/进程重启/与签发进程不是同一个) token:%v... path:%v 来源IP:%v",
					utils.TruncateString(tokenStr, 8), c.Request.URL.Path, utils.GetManageClientIP(c)))
				response.AuthFailWithMessage("令牌过期", c)
				c.Abort()
				return
			} else {
				var tokenInfo model.TokenInfo
				if err := global.GCACHE_WAFCACHE.GetAs(enums.CACHE_TOKEN+tokenStr, &tokenInfo); err != nil {
					zlog.Error(fmt.Sprintf("令牌缓存内容解析失败 token:%v... err:%v", utils.TruncateString(tokenStr, 8), err))
					response.AuthFailWithMessage("令牌解析失败", c)
					c.Abort()
					return
				}

				// IP检查逻辑
				currentIP := utils.GetManageClientIP(c)
				ipMatched := false

				// 如果启用严格IP绑定，进行严格IP检查
				if global.GCONFIG_ENABLE_STRICT_IP_BINDING == 1 {
					if tokenInfo.LoginIp == currentIP {
						ipMatched = true
					} else {
						ipMatched = false
					}
				} else {
					ipMatched = true
				}

				// 指纹检查逻辑
				// 豁免路径：WebSocket 握手、SSE、带查询串令牌的下载。这三类请求由浏览器直接发起，
				// Accept-Encoding/Accept-Language 与普通 XHR 并不一致，参与指纹比对必然误判。
				fingerprintMatched := true
				if global.GCONFIG_ENABLE_DEVICE_FINGERPRINT == 1 && tokenInfo.DeviceFingerprint != "" &&
					!isFingerprintExemptPath(c) {
					currentFingerprint := utils.GenerateFingerprint(c.Request)
					if tokenInfo.DeviceFingerprint == currentFingerprint {
						fingerprintMatched = true
					} else {
						fingerprintMatched = false
					}
				}

				// 如果指纹不匹配，则拒绝请求
				// 只拒本次请求，不再直接删令牌：反向代理/CDN 改写请求头、浏览器升级等都会造成一次性不匹配，
				// 一次不匹配就作废整个会话会让用户莫名其妙被登出（issue #938/#930）。
				// 连续 bindFailThreshold 次不匹配才判定为真的异常并作废会话。
				if !fingerprintMatched {
					zlog.Error(fmt.Sprintf("设备指纹不匹配，请求拒绝。原IP:%v 当前IP:%v 原指纹:%v 当前指纹:%v",
						tokenInfo.LoginIp, currentIP, tokenInfo.DeviceFingerprint, utils.GenerateFingerprint(c.Request)))
					if bumpTokenBindFailure(tokenStr) {
						global.GCACHE_WAFCACHE.Remove(enums.CACHE_TOKEN + tokenStr)
						response.AuthFailWithMessage("设备验证失败，需要重新登录", c)
					} else {
						response.AuthFailWithMessage("设备验证失败，请重试", c)
					}
					c.Abort()
					return
				}

				// N11 修复
				// 开启严格IP绑定即要求令牌与登录时的真实 IP 一致，IP 变化需重新登录。
				// 同样改为"连续多次不匹配才作废"：动态IP、双栈 IPv4/IPv6 交替、多出口 NAT 都会偶发不匹配。
				if !ipMatched {
					zlog.Warn(fmt.Sprintf("严格IP绑定不匹配，请求拒绝。原IP:%v 当前IP:%v", tokenInfo.LoginIp, currentIP))
					if bumpTokenBindFailure(tokenStr) {
						global.GCACHE_WAFCACHE.Remove(enums.CACHE_TOKEN + tokenStr)
						response.AuthFailWithMessage("登录环境已变化(IP)，需要重新登录", c)
					} else {
						response.AuthFailWithMessage("登录环境已变化(IP)，请重试", c)
					}
					c.Abort()
					return
				}

				// 走到这说明绑定校验全过，清掉之前累计的失败次数，避免跨越很长时间的零星失败被累加成作废
				clearTokenBindFailure(tokenStr)

				// 记录"当前正在使用管理端的IP"，供主机防爆破豁免。
				// 这是防误封的最后一道保险：只要你还在用管理端，你的出口IP就永远进不了封禁名单，
				// 哪怕白名单一个字都没配。放在这里是因为走到这说明令牌、指纹、IP绑定都已校验通过。
				wafhostguard.TouchAdminIP(currentIP)

				//刷新token时间
				if global.GWAF_RELEASE == "false" {
					tokenList := global.GCACHE_WAFCACHE.ListAvailableKeysWithPrefix(enums.CACHE_TOKEN)

					for _, duration := range tokenList {
						remainTime := fmt.Sprintf("%02d时%02d分", int(duration.Hours()), int(duration.Minutes())%60)
						zlog.Debug(fmt.Sprintf("%v 当前token有效缓存剩余时间 %v", innerName, remainTime))
					}
				}
				expireTime, err := global.GCACHE_WAFCACHE.GetExpireTime(enums.CACHE_TOKEN + tokenStr)
				if err == nil {
					remainingTime := time.Until(expireTime) // 计算剩余有效时间
					if remainingTime > 0 && remainingTime < 2*time.Minute {
						zlog.Debug(fmt.Sprintf("%v 当前token有效缓存剩余时间 %v  小于2分钟进行缓存可用时间延期处理", innerName, expireTime))
						global.GCACHE_WAFCACHE.SetWithTTlRenewTime(enums.CACHE_TOKEN+tokenStr, tokenInfo, time.Duration(global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES)*time.Minute)
					}
				}

				//强制改密门：需改密的令牌只放行改密/注销/ws，其余一律拦截（默认口令/被重置账号在改密前拿不到其他权限）
				if tokenInfo.NeedChangePassword == 1 {
					p := c.Request.URL.Path
					if p != "/api/v1/account/changemypwd" && p != "/api/v1/logout" && p != "/api/v1/ws" {
						zlog.Debug(fmt.Sprintf("令牌处于强制改密状态，拦截其他接口 账号:%v path:%v", tokenInfo.LoginAccount, p))
						response.NeedChangePwdWithMessage("请先修改初始/重置密码后再进行其他操作", c)
						c.Abort()
						return
					}
				}

				//检测是否强制2Fa绑定
				if global.GCONFIG_RECORD_FORCE_BIND_2FA == 1 && c.Request.RequestURI != "/api/v1/ws" && c.Request.RequestURI != "/api/v1/logout" {
					otpBean := wafOtpService.GetDetailByUserNameApi(tokenInfo.LoginAccount)
					if otpBean.UserName == "" {
						//需要强制跳转2fa绑定界面
						response.NeedBind2FAWithMessage("系统已开启强制 【双因素认证】 ，请进行绑定", c)
						c.Abort()
						return
					}
				}

				// 将登录账号写入 context，供下游（变更记录、安全审计）取用
				c.Set("loginAccount", tokenInfo.LoginAccount)
				c.Set("loginIP", currentIP)
				// 写入角色，供 RBAC 鉴权中间件判定（空角色兜底为超级管理员，向后兼容）
				c.Set("userRole", enums.NormalizeRole(tokenInfo.Role))
			}
		}

		// 这里执行路由 HandlerFunc
		c.Next()
	}
}

// bindFailThreshold 令牌绑定校验(设备指纹/严格IP)连续失败多少次后作废会话。
const bindFailThreshold = 3

// bindFailCounterMaxTTL 绑定失败计数的存活上限。
// 计数只是为了识别"短时间内连续失败"，不需要跟令牌同寿命：
// 令牌有效期可以被设成不限制(按1年封顶)，计数若也活一年，早已失效的令牌会在内存里留一年垃圾。
const bindFailCounterMaxTTL = 30 * time.Minute

// bindFailCounterTTL 取"令牌有效期"与上限中的较小者
func bindFailCounterTTL() time.Duration {
	ttl := time.Duration(global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES) * time.Minute
	if ttl <= 0 || ttl > bindFailCounterMaxTTL {
		return bindFailCounterMaxTTL
	}
	return ttl
}

// isFingerprintExemptPath 判断当前请求是否豁免设备指纹比对。
// WebSocket 握手、SSE(text/event-stream)、带查询串令牌的下载都由浏览器按各自的规则发头，
// 与页面里 XHR 的 Accept-Encoding/Accept-Language 天然不同，参与比对只会误杀。
func isFingerprintExemptPath(c *gin.Context) bool {
	if strings.EqualFold(c.GetHeader("Upgrade"), "websocket") {
		return true
	}
	if strings.Contains(strings.ToLower(c.GetHeader("Accept")), "text/event-stream") {
		return true
	}
	uri := c.Request.RequestURI
	if uri == "/api/v1/ws" || strings.HasPrefix(uri, "/api/v1/waflog/attack/download") {
		return true
	}
	return false
}

// bumpTokenBindFailure 累加该令牌的绑定校验失败次数，返回是否已达阈值(达到则调用方作废会话)。
// 计数带 TTL，跟令牌有效期同寿命，过期自然清零。
func bumpTokenBindFailure(tokenStr string) bool {
	key := enums.CACHE_TOKEN_BINDFAIL + tokenStr
	count := 0
	if global.GCACHE_WAFCACHE.IsKeyExist(key) {
		if v, err := global.GCACHE_WAFCACHE.GetInt(key); err == nil {
			count = v
		}
	}
	count++
	if count >= bindFailThreshold {
		global.GCACHE_WAFCACHE.Remove(key)
		return true
	}
	global.GCACHE_WAFCACHE.SetWithTTlRenewTime(key, count, bindFailCounterTTL())
	return false
}

// clearTokenBindFailure 绑定校验通过后清零失败计数
func clearTokenBindFailure(tokenStr string) {
	key := enums.CACHE_TOKEN_BINDFAIL + tokenStr
	if global.GCACHE_WAFCACHE.IsKeyExist(key) {
		global.GCACHE_WAFCACHE.Remove(key)
	}
}
