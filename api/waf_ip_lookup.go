package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"strings"

	"github.com/gin-gonic/gin"
)

type WafIPLookupApi struct {
}

// LookupApi IP归属查询
// @Summary      IP归属查询
// @Description  查一个IP当前落在哪些名单里：IP黑/白名单、IP组、威胁情报IP、IP失败封禁、CC封禁、系统防火墙封禁、CDN回源段
// @Tags         网站防护-IP归属查询
// @Produce      json
// @Param        ip       query     string  true   "待查询的IP"
// @Param        sources  query     string  false  "只查指定来源(逗号分隔)，留空查全部"
// @Success      200  {object}  response.Response  "查询成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/ip/lookup [get]
func (w *WafIPLookupApi) LookupApi(c *gin.Context) {
	var req request.WafIPLookupReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	// sources 为空=查全部；前端为了显示进度会分批传入几个来源
	var sources []string
	if strings.TrimSpace(req.Sources) != "" {
		sources = strings.Split(req.Sources, ",")
	}
	result, err := wafIPLookupService.Lookup(req.Ip, sources)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(result, "查询成功", c)
}
