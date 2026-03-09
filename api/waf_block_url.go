package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafBlockUrlApi struct {
}

// AddApi 新增URL黑名单
// @Summary      新增URL黑名单
// @Description  为指定网站新增一条URL黑名单记录（匹配该URL的请求将被拦截）
// @Tags         网站防护-URL黑名单
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafBlockUrlAddReq  true  "URL黑名单配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/blockurl/add [post]
func (w *WafBlockUrlApi) AddApi(c *gin.Context) {
	var req request.WafBlockUrlAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafUrlBlockService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafUrlBlockService.AddApi(req)
			if err == nil {
				w.NotifyWaf(req.HostCode)
				response.OkWithMessage("添加成功", c)
			} else {

				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前网站的Url已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetDetailApi 获取URL黑名单详情
// @Summary      获取URL黑名单详情
// @Description  根据ID获取URL黑名单记录详情
// @Tags         网站防护-URL黑名单
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/blockurl/detail [get]
func (w *WafBlockUrlApi) GetDetailApi(c *gin.Context) {
	var req request.WafBlockUrlDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafUrlBlockService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取URL黑名单列表
// @Summary      获取URL黑名单列表
// @Description  分页查询URL黑名单列表
// @Tags         网站防护-URL黑名单
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafBlockUrlSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/blockurl/list [post]
func (w *WafBlockUrlApi) GetListApi(c *gin.Context) {
	var req request.WafBlockUrlSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafUrlBlockService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      beans,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelBlockUrlApi 删除URL黑名单
// @Summary      删除URL黑名单
// @Description  根据ID删除URL黑名单记录
// @Tags         网站防护-URL黑名单
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "记录ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/blockurl/del [get]
func (w *WafBlockUrlApi) DelBlockUrlApi(c *gin.Context) {
	var req request.WafBlockUrlDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafUrlBlockService.GetDetailByIdApi(req.Id)
		err = wafUrlBlockService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			w.NotifyWaf(bean.HostCode)
			response.OkWithMessage("删除成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ModifyBlockUrlApi 编辑URL黑名单
// @Summary      编辑URL黑名单
// @Description  修改URL黑名单记录
// @Tags         网站防护-URL黑名单
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafBlockUrlEditReq  true  "URL黑名单配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/blockurl/edit [post]
func (w *WafBlockUrlApi) ModifyBlockUrlApi(c *gin.Context) {
	var req request.WafBlockUrlEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafUrlBlockService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			w.NotifyWaf(req.HostCode)
			response.OkWithMessage("编辑成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

/*
*
通知到waf引擎实时生效
*/
func (w *WafBlockUrlApi) NotifyWaf(host_code string) {
	var urlWhites []model.URLBlockList
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Find(&urlWhites)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeBlockURL,
		Content:  urlWhites,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}

// BatchDelBlockUrlApi 批量删除URL黑名单
func (w *WafBlockUrlApi) BatchDelBlockUrlApi(c *gin.Context) {
	var req request.WafBlockUrlBatchDelReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafUrlBlockService.GetHostCodesByIds(req.Ids)
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		// 执行批量删除
		err = wafUrlBlockService.BatchDelApi(req)
		if err != nil {
			response.FailWithMessage("批量删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range hostCodes {
				w.NotifyWaf(hostCode)
			}
			response.OkWithMessage(fmt.Sprintf("成功删除 %d 条记录", len(req.Ids)), c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelAllBlockUrlApi 删除指定网站的所有URL黑名单
func (w *WafBlockUrlApi) DelAllBlockUrlApi(c *gin.Context) {
	var req request.WafBlockUrlDelAllReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafUrlBlockService.GetHostCodes()
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		err = wafUrlBlockService.DelAllApi(req)
		if err != nil {
			response.FailWithMessage("全部删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range hostCodes {
				w.NotifyWaf(hostCode)
			}
			if len(req.HostCode) > 0 {
				response.OkWithMessage("成功删除该网站的所有URL黑名单", c)
			} else {
				response.OkWithMessage("成功删除所有URL黑名单", c)
			}
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
