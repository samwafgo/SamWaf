package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"github.com/gin-gonic/gin"
)

type WafLoginApi struct {
}

func (w *WafLoginApi) LoginApi(c *gin.Context) {
	var req request.WafLoginReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafAccountService.GetInfoByLoginApi(req)
		if bean.Id != "" {

			response.OkWithDetailed(response2.LoginRep{
				AccessToken: "asdfadfadfadf",
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
	var req request.WafLoginReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafAccountService.GetInfoByLoginApi(req)
		if bean.Id != "" {
			response.OkWithDetailed("json", "注销成功", c)
			return
		} else {
			response.FailWithMessage("注销异常", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
