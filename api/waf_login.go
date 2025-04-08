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
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"time"
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
		accountCount, _ := wafAccountService.GetAccountCountApi()
		if accountCount == 0 {
			wafAccountService.AddApi(request.WafAccountAddReq{
				LoginAccount:  global.GWAF_DEFAULT_ACCOUNT,
				LoginPassword: global.GWAF_DEFAULT_ACCOUNT_PWD,
				Role:          "superAdmin",
				Status:        0,
				Remarks:       "密码生成",
			})
		}
		bean := wafAccountService.GetInfoByLoginApi(req)
		if bean.Id != "" {
			clientIP := c.ClientIP()
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

			// 校验密码是否正确
			if bean.LoginPassword != utils.Md5String(req.LoginPassword+global.GWAF_DEFAULT_ACCOUNT_SALT) {
				// 密码错误，增加错误计数
				hitCounter++
				global.GCACHE_WAFCACHE.SetWithTTl(cacheKey, hitCounter, time.Duration(global.GCONFIG_RECORD_LOGIN_LIMIT_MINTUTES)*time.Minute)

				loginError := fmt.Sprintf("输入密码错误超过次数限制，IP:%s 归属地区：%s", clientIP, clientCountry)
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
				global.GQEQUE_LOG_DB.Enqueue(wafSysLog)

				global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
					BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "登录错误"},
					OperaCnt:        loginError,
				})
				response.FailWithMessage("登录密码错误", c)
				return
			}
			// 如果开启了二次登录校验 需要进行输入
			otpBean := wafOtpService.GetDetailByUserNameApi(req.LoginAccount)
			if otpBean.UserName != "" {
				valid := totp.Validate(req.LoginOtpSecretCode, otpBean.Secret)
				if !valid {
					response.SecretCodeFailWithMessage("请正确输入您的安全码", c)
					return
				}
			}

			// 密码正确，清除错误计数
			global.GCACHE_WAFCACHE.Remove(cacheKey)

			//如果存在旧的状态删除 相同帐号 只允许一个
			allTokenInfo := wafTokenInfoService.GetAllTokenInfoByLoginAccount(req.LoginAccount)
			if allTokenInfo != nil {
				for i := 0; i < len(allTokenInfo); i++ {
					oldTokenInfo := allTokenInfo[i]
					if oldTokenInfo.Id != "" {
						wafTokenInfoService.DelApiByAccount(oldTokenInfo.LoginAccount)
						global.GCACHE_WAFCACHE.Remove(enums.CACHE_TOKEN + oldTokenInfo.AccessToken)
					}
				}
			}

			//记录状态
			accessToken := utils.Md5String(uuid.GenUUID())
			tokenInfo := wafTokenInfoService.AddApi(bean.LoginAccount, accessToken, c.ClientIP())

			//令牌记录到cache里
			global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_TOKEN+accessToken, *tokenInfo, time.Duration(global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES)*time.Minute)

			//通知信息
			noticeStr := fmt.Sprintf("登录IP:%s 归属地区：%s", clientIP, clientCountry)
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "登录信息"},
				OperaCnt:        noticeStr,
			})

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
			global.GQEQUE_LOG_DB.Enqueue(wafSysLog)

			response.OkWithDetailed(response2.LoginRep{
				AccessToken: tokenInfo.AccessToken,
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
		tokenStr := c.GetHeader("X-Token")
		bean := wafTokenInfoService.GetInfoByAccessToken(tokenStr)
		if bean.Id != "" {
			wafTokenInfoService.DelApi(bean.LoginAccount, bean.AccessToken)
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
