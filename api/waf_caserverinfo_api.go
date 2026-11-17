package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// isValidCaServerAddress CA服务器地址必须是可解析的 https URL（含合法的内网 CA）。
// 带用户信息的写法（user:pass@host）会被列出页向所有角色回显，一律拒绝；
// 端口号必须是合法的 1-65535 数字，避免到使用时才报错。
func isValidCaServerAddress(addr string) bool {
	u, err := url.ParseRequestURI(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return false
	}
	if u.User != nil {
		return false
	}
	if portStr := u.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	return true
}

type WafCaServerInfoApi struct {
}

func (w *WafCaServerInfoApi) AddApi(c *gin.Context) {
	var req request.WafCaServerInfoAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {

		if !isValidCaServerAddress(req.CaServerAddress) {
			response.FailWithMessage("CA服务器地址必须是合法的https地址", c)
			return
		}
		cnt := wafCaServerInfoService.CheckIsExistApi(req)
		if cnt == 0 {
			err = wafCaServerInfoService.AddApi(req)
			if err == nil {
				response.OkWithMessage("添加成功", c)
			} else {
				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前记录已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafCaServerInfoApi) GetDetailApi(c *gin.Context) {
	var req request.WafCaServerInfoDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafCaServerInfoService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafCaServerInfoApi) GetListApi(c *gin.Context) {
	var req request.WafCaServerInfoSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		CaServerInfo, total, _ := wafCaServerInfoService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      CaServerInfo,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafCaServerInfoApi) DelApi(c *gin.Context) {
	var req request.WafCaServerInfoDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafCaServerInfoService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			response.OkWithMessage("删除成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafCaServerInfoApi) ModifyApi(c *gin.Context) {
	var req request.WafCaServerInfoEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		if !isValidCaServerAddress(req.CaServerAddress) {
			response.FailWithMessage("CA服务器地址必须是合法的https地址", c)
			return
		}
		err = wafCaServerInfoService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误"+err.Error(), c)
		} else {
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
