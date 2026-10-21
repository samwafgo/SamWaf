package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"net"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

type WafRuleBanApi struct {
}

var ruleBanHostCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// GetConfigApi 获取规则封禁配置
// @Summary      获取规则封禁配置
// @Description  获取规则封禁执行动作配置
// @Tags         网站防护-规则封禁
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ruleban/config [get]
func (w *WafRuleBanApi) GetConfigApi(c *gin.Context) {
	var req request.WafRuleBanConfigReq
	err := c.ShouldBind(&req)
	if err == nil {
		response.OkWithDetailed(wafRuleBanService.GetConfigApi(), "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// SetConfigApi 设置规则封禁配置
// @Summary      设置规则封禁配置
// @Description  更新规则封禁全局配置
// @Tags         网站防护-规则封禁
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafRuleBanSetConfigReq  true  "配置参数"
// @Success      200   {object}  response.Response  "设置成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ruleban/config [post]
func (w *WafRuleBanApi) SetConfigApi(c *gin.Context) {
	var req request.WafRuleBanSetConfigReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		if req.Mode != 0 && req.Mode != 1 {
			response.FailWithMessage("封禁执行动作取值不合法", c)
			return
		}
		if err := wafRuleBanService.SetConfigApi(req); err != nil {
			response.FailWithMessage("设置失败", c)
			return
		}

		response.OkWithMessage("设置成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetBanIpListApi 获取规则封禁列表
// @Summary      获取规则封禁列表
// @Description  获取当前因自定义规则 RF.Ban 命中而被临时封禁的IP列表
// @Tags         网站防护-规则封禁
// @Produce      json
// @Success      200  {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ruleban/baniplist [get]
func (w *WafRuleBanApi) GetBanIpListApi(c *gin.Context) {
	beans, err := wafRuleBanService.GetBanIpListApi()
	if err != nil {
		response.FailWithMessage("获取失败", c)
		return
	}

	total := len(beans)
	response.OkWithDetailed(response.PageResult{
		List:      beans,
		Total:     int64(total),
		PageIndex: 1,
		PageSize:  999999,
	}, "获取成功", c)
}

// RemoveBanIpApi 移除规则封禁IP
func (w *WafRuleBanApi) RemoveBanIpApi(c *gin.Context) {
	var req request.WafRuleBanRemoveBanIpReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		req.Ip = strings.TrimSpace(req.Ip)
		if net.ParseIP(req.Ip) == nil {
			response.FailWithMessage("IP格式不合法", c)
			return
		}
		req.HostCode = strings.TrimSpace(req.HostCode)
		if req.HostCode != "" && !ruleBanHostCodePattern.MatchString(req.HostCode) {
			response.FailWithMessage("站点编码格式不合法", c)
			return
		}
		wafRuleBanService.RemoveBanIpApi(req)
		response.OkWithMessage(req.Ip+" 移除成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
