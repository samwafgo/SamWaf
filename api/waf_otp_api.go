package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/utils"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

type WafOtpApi struct {
}

func (w *WafOtpApi) InitOtpApi(c *gin.Context) {
	tokenStr := c.GetHeader("X-Token")
	tokenInfo := wafTokenInfoService.GetInfoByAccessToken(tokenStr)
	if tokenInfo.LoginAccount == "" {
		response.FailWithMessage("token可能已经失效", c)
		return
	} else {
		otpBean := wafOtpService.GetDetailByUserNameApi(tokenInfo.LoginAccount)
		if otpBean.UserName == "" {
			// 生成默认的 Issuer
			defaultIssuer := "SamWaf-" + global.GWAF_CUSTOM_SERVER_NAME
			secret, url, err := utils.GenOtpSecret(tokenInfo.LoginAccount, defaultIssuer)
			if err != nil {
				response.FailWithMessage(err.Error(), c)
				return
			}
			otpReq := request.WafOtpBindReq{
				UserName: tokenInfo.LoginAccount,
				Url:      url,
				Secret:   secret,
				Issuer:   defaultIssuer,
				Remarks:  "",
			}
			//首次需要绑定得情况
			response.OkWithData(otpReq, c)
		} else {
			//已经绑定后了 前端需要看是否有ID就知道是否是已经绑定过了得 解绑得时候需要安全码
			otpBean = wafOtpService.GetDetailByUserNameApi(tokenInfo.LoginAccount)
			otpBean.Secret = ""
			otpBean.Url = ""
			otpBean.UserName = ""
			response.OkWithData(otpBean, c)
		}

	}
}
func (w *WafOtpApi) BindApi(c *gin.Context) {
	var req request.WafOtpBindReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		tokenStr := c.GetHeader("X-Token")
		tokenInfo := wafTokenInfoService.GetInfoByAccessToken(tokenStr)
		if tokenInfo.LoginAccount == "" {
			response.FailWithMessage("token可能已经失效", c)
			return
		}

		if req.UserName != tokenInfo.LoginAccount {
			response.FailWithMessage("请使用本帐号操作", c)
			return
		}

		// 如果用户修改了 Issuer，需要重新生成 URL
		if req.Issuer != "" && req.Issuer != "SamWaf-"+global.GWAF_CUSTOM_SERVER_NAME {
			// 重新生成带有新 Issuer 的 URL
			_, newUrl, genErr := utils.GenOtpSecret(req.UserName, req.Issuer)
			if genErr == nil {
				req.Url = newUrl
			}
		}

		valid := totp.Validate(req.SecretCode, req.Secret)
		if !valid {
			response.FailWithMessage("验证失败", c)
			return
		}
		err = wafOtpService.BindApi(req)
		if err != nil {
			response.FailWithMessage("设置发生错误"+err.Error(), c)
		} else {
			response.OkWithMessage("绑定成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafOtpApi) UnBindApi(c *gin.Context) {
	var req request.WafOtpUnBindReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		tokenStr := c.GetHeader("X-Token")
		tokenInfo := wafTokenInfoService.GetInfoByAccessToken(tokenStr)
		if tokenInfo.LoginAccount == "" {
			response.FailWithMessage("token可能已经失效", c)
			return
		}
		otpBean := wafOtpService.GetDetailByUserNameApi(tokenInfo.LoginAccount)
		if otpBean.UserName == "" {
			response.FailWithMessage("OTP获取用户失败", c)
			return
		}
		valid := totp.Validate(req.SecretCode, otpBean.Secret)
		if valid {
			//删除信息
			wafOtpService.DelApi(request.WafOtpDelReq{Id: otpBean.Id})
			response.OkWithMessage("解绑成功", c)
			return
		} else {
			response.FailWithMessage("验证失败", c)
			return
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
