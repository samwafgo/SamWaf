package api

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

type WafLoginApi struct {
}

func (w *WafLoginApi) LoginApi(c *gin.Context) {
	var req request.WafLoginReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		if len(req.LoginAccount) == 0 {
			response.FailWithMessage("帐号为空", c)
			return
		}
		// 默认管理员由程序启动初始化时按"账户表为空"判定并创建(见 cmd/samwaf/main.go)，此处不再惰性创建
		bean := wafAccountService.GetInfoByLoginApi(req)
		if bean.Id != "" {
			clientIP := utils.GetManageClientIP(c)
			clientCountry := utils.GetCountry(clientIP)
			// 检查客户端的登录错误次数
			cacheKey := enums.CACHE_LOGIN_ERROR + clientIP
			hitCounter := 0

			if global.GCACHE_WAFCACHE.IsKeyExist(cacheKey) {
				hitCounter, err = global.GCACHE_WAFCACHE.GetInt(cacheKey)
				if err != nil {
					// 获取失败，重置计数
					hitCounter = 0
				}
			}

			// 如果大于某个数就不让登录了
			if hitCounter >= int(global.GCONFIG_RECORD_LOGIN_MAX_ERROR_TIME) {
				response.FailWithMessage("登录超限请稍后重试", c)
				return
			}

			// 校验密码是否正确（bcrypt，兼容存量 MD5）
			if !wafAccountService.VerifyPassword(bean.LoginPassword, req.LoginPassword) {
				// 密码错误，增加错误计数
				hitCounter++
				global.GCACHE_WAFCACHE.SetWithTTl(cacheKey, hitCounter, time.Duration(global.GCONFIG_RECORD_LOGIN_LIMIT_MINTUTES)*time.Minute)

				clientCountryStr := strings.Join(clientCountry, ",")
				loginError := fmt.Sprintf("输入密码错误超过次数限制，IP:%s 归属地区：%s", clientIP, clientCountryStr)
				wafSysLog := model.WafSysLog{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.GenUUID(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: customtype.JsonTime(time.Now()),
						UPDATE_TIME: customtype.JsonTime(time.Now()),
					},
					OpType:    "登录信息",
					OpContent: loginError,
				}
				global.GQEQUE_LOG_DB.Enqueue(&wafSysLog)

				// 使用新的系统错误消息格式
				serverName := global.GWAF_CUSTOM_SERVER_NAME
				if serverName == "" {
					serverName = "未命名服务器"
				}
				global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.SystemErrorMessageInfo{
					BaseMessageInfo: innerbean.BaseMessageInfo{
						OperaType: "登录错误",
						Server:    serverName,
					},
					ErrorType: "登录失败",
					ErrorMsg:  fmt.Sprintf("密码错误超限，IP:%s (%s)", clientIP, clientCountryStr),
					Time:      time.Now().Format("2006-01-02 15:04:05"),
				})
				response.FailWithMessage("登录密码错误", c)
				return
			}
			// 如果开启了二次登录校验 需要进行输入
			otpBean := wafOtpService.GetDetailByUserNameApi(req.LoginAccount)
			if otpBean.UserName != "" {
				// N6：OTP 失败限流。，
				otpCacheKey := enums.CACHE_OTP_ERROR + req.LoginAccount
				otpErrCount := 0
				if global.GCACHE_WAFCACHE.IsKeyExist(otpCacheKey) {
					if v, e := global.GCACHE_WAFCACHE.GetInt(otpCacheKey); e == nil {
						otpErrCount = v
					}
				}
				if otpErrCount >= int(global.GCONFIG_RECORD_LOGIN_MAX_ERROR_TIME) {
					response.SecretCodeFailWithMessage("安全码错误次数过多，请稍后重试", c)
					return
				}
				valid := totp.Validate(req.LoginOtpSecretCode, otpBean.Secret)
				if !valid {
					otpErrCount++
					global.GCACHE_WAFCACHE.SetWithTTl(otpCacheKey, otpErrCount, time.Duration(global.GCONFIG_RECORD_LOGIN_LIMIT_MINTUTES)*time.Minute)
					response.SecretCodeFailWithMessage("请正确输入您的安全码", c)
					return
				}
				// OTP 正确，清除 OTP 错误计数
				global.GCACHE_WAFCACHE.Remove(otpCacheKey)
			}

			// 密码正确，清除错误计数
			global.GCACHE_WAFCACHE.Remove(cacheKey)

			// 透明升级：命中旧 MD5 的口令，登录成功后重算为 bcrypt 落库
			if !utils.IsBcryptHash(bean.LoginPassword) {
				wafAccountService.UpgradePasswordHash(bean.LoginAccount, req.LoginPassword)
			}

			// 口令强制改密判定：首次登录/被重置(NeedChangePassword) 或 口令已过有效期（提前计算，用于写入令牌与响应）
			needChangePwd := false
			changePwdReason := ""
			if bean.NeedChangePassword == 1 {
				needChangePwd = true
				changePwdReason = "首次登录或密码已被重置，请立即修改密码"
			} else if utils.IsPasswordExpired(bean.PwdUpdateTime, int(global.GCONFIG_PWD_EXPIRE_DAYS), time.Now()) {
				needChangePwd = true
				changePwdReason = "密码已超过有效期，请修改密码"
			}

			// 获取登录类型
			loginType := c.GetHeader("X-Login-Type")
			if loginType == "" {
				loginType = "web" // 默认为web类型
			}

			//如果存在旧的状态删除 相同帐号和登录类型 只允许一个
			allTokenInfo := wafTokenInfoService.GetAllTokenInfoByLoginAccountAndType(req.LoginAccount, loginType)
			if allTokenInfo != nil {
				for i := 0; i < len(allTokenInfo); i++ {
					oldTokenInfo := allTokenInfo[i]
					if oldTokenInfo.Id != "" {
						wafTokenInfoService.DelApiByAccountAndType(oldTokenInfo.LoginAccount, oldTokenInfo.LoginType)
						global.GCACHE_WAFCACHE.Remove(enums.CACHE_TOKEN + oldTokenInfo.AccessToken)
					}
				}
			}

			//生成设备指纹
			deviceFingerprint := ""
			if global.GCONFIG_ENABLE_DEVICE_FINGERPRINT == 1 {
				deviceFingerprint = utils.GenerateFingerprint(c.Request)
			}

			//记录状态
			accessToken := utils.Md5String(uuid.GenUUID())
			tokenInfo := wafTokenInfoService.AddApiWithFingerprintAndType(bean.LoginAccount, accessToken, utils.GetManageClientIP(c), deviceFingerprint, loginType, bean.Role)

			// 强制改密标记随令牌下发，供鉴权中间件拦截未改密令牌（缓存副本即可，Auth 从缓存读取）
			if needChangePwd {
				tokenInfo.NeedChangePassword = 1
			}

			//令牌记录到cache里
			global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_TOKEN+accessToken, *tokenInfo, time.Duration(global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES)*time.Minute)

			//通知信息（使用新的消息格式，通过队列统一处理）
			currentTime := time.Now().Format("2006-01-02 15:04:05")
			clientCountryStr := strings.Join(clientCountry, ",")
			noticeStr := fmt.Sprintf("登录IP:%s 归属地区：%s", clientIP, clientCountryStr)

			// 将用户登录信息加入消息队列（新格式）
			serverName := global.GWAF_CUSTOM_SERVER_NAME
			if serverName == "" {
				serverName = "未命名服务器"
			}
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.UserLoginMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{
					OperaType: "登录信息",
					Server:    serverName,
				},
				Username: bean.LoginAccount,
				Ip:       clientIP + " (" + clientCountryStr + ")",
				Time:     currentTime,
			})

			// 记录系统日志
			wafSysLog := model.WafSysLog{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   global.GWAF_USER_CODE,
					Tenant_ID:   global.GWAF_TENANT_ID,
					CREATE_TIME: customtype.JsonTime(time.Now()),
					UPDATE_TIME: customtype.JsonTime(time.Now()),
				},
				OpType:    "登录信息",
				OpContent: noticeStr,
			}
			global.GQEQUE_LOG_DB.Enqueue(&wafSysLog)

			response.OkWithDetailed(response2.LoginRep{
				AccessToken:          tokenInfo.AccessToken,
				NeedChangePassword:   needChangePwd,
				ChangePasswordReason: changePwdReason,
			}, "登录成功", c)

			return
		} else {
			response.FailWithMessage("登录异常", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafLoginApi) LoginOutApi(c *gin.Context) {
	var req request.WafLoginOutReq
	err := c.ShouldBind(&req)
	if err == nil {
		// 根据登录类型获取不同的token头部
		loginType := c.GetHeader("X-Login-Type")
		var tokenStr string

		if loginType == "mobile" {
			tokenStr = c.GetHeader("X-Mobile-Token")
		} else {
			tokenStr = c.GetHeader("X-Token")
		}

		bean := wafTokenInfoService.GetInfoByAccessToken(tokenStr)
		if bean.Id != "" {
			wafTokenInfoService.DelApi(bean.LoginAccount, bean.AccessToken)
			global.GCACHE_WAFCACHE.Remove(enums.CACHE_TOKEN + bean.AccessToken)
			response.OkWithDetailed("json", "注销成功"+tokenStr, c)
			return
		} else {
			response.FailWithMessage("注销异常", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
