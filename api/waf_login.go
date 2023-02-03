package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
)

type WafLoginApi struct {
}

func (w *WafLoginApi) LoginApi(c *gin.Context) {
	var req request.WafLoginReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafAccountService.GetInfoByLoginApi(req)
		if bean.Id != "" {
			//记录状态
			accessToken := utils.Md5String(uuid.NewV4().String())
			tokenInfo := wafTokenInfoService.AddApi(bean.LoginAccount, accessToken, c.ClientIP())
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
