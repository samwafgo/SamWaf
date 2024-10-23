package api

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
)

type WafLoginApi struct {
}

func (w *WafLoginApi) LoginApi(c *gin.Context) {
	/*bodyBytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		c.Abort()
		return
	}

	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes)) // Reset the request body to original
	fmt.Println("Raw body:", string(bodyBytes))*/
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

			//校验密码是否正确
			if bean.LoginPassword != utils.Md5String(req.LoginPassword+global.GWAF_DEFAULT_ACCOUNT_SALT) {
				response.FailWithMessage("登录密码错误", c)
				return
			}
			//如果存在旧的状态删除
			oldTokenInfo := wafTokenInfoService.GetInfoByLoginAccount(req.LoginAccount)
			if oldTokenInfo.Id != "" {
				wafTokenInfoService.DelApiByAccount(oldTokenInfo.LoginAccount)
			}
			//记录状态
			accessToken := utils.Md5String(uuid.NewV4().String())
			tokenInfo := wafTokenInfoService.AddApi(bean.LoginAccount, accessToken, c.ClientIP())

			//通知信息
			noticeStr := fmt.Sprintf("登录IP:%s 归属地区：%s", c.ClientIP(), utils.GetCountry(c.ClientIP()))
			global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
				BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "登录信息"},
				OperaCnt:        noticeStr,
			})

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
