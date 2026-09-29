package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"SamWaf/waftask"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafSystemConfigApi struct {
}

func (w *WafSystemConfigApi) AddApi(c *gin.Context) {
	var req request.WafSystemConfigAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafSystemConfigService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafSystemConfigService.AddApi(req)
			if err == nil {
				response.OkWithMessage("添加成功", c)
			} else {

				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前数据已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSystemConfigApi) GetDetailApi(c *gin.Context) {
	var req request.WafSystemConfigDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafSystemConfigService.GetDetailApi(req)
		waf_service.MaskSensitiveConfig(&bean)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取系统配置列表
// @Summary      获取系统配置列表
// @Description  分页查询系统配置项列表
// @Tags         系统配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafSystemConfigSearchReq  true  "查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /systemconfig/list [post]
func (w *WafSystemConfigApi) GetListApi(c *gin.Context) {
	var req request.WafSystemConfigSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafSystemConfigService.GetListApi(req)
		for i := range beans {
			waf_service.MaskSensitiveConfig(&beans[i])
		}
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
func (w *WafSystemConfigApi) DelApi(c *gin.Context) {
	var req request.WafSystemConfigDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafSystemConfigService.DelApi(req)
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

// ModifyApi 更新系统配置
// @Summary      更新系统配置
// @Description  修改系统配置项的值
// @Tags         系统配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafSystemConfigEditReq  true  "配置参数"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /systemconfig/edit [post]
func (w *WafSystemConfigApi) ModifyApi(c *gin.Context) {
	var req request.WafSystemConfigEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 密钥类配置：留空=保持原值(防止只改备注把密钥冲掉)，清空需提交哨兵值。
		req.Value = resolveSensitiveConfigValue(req.Item, req.Value,
			func() string { return wafSystemConfigService.GetDetailByIdApi(req.Id).Value })
		if msg, ok := checkSystemConfigValue(req.Item, req.Value); !ok {
			response.FailWithMessage(msg, c)
			return
		}
		err = wafSystemConfigService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			waftask.TaskLoadSetting(true)
			response.OkWithMessage("编辑成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ModifyByItemApi 通过item更新系统配置
// @Summary      通过item更新系统配置
// @Description  通过配置项的 item 键名修改对应的 value 值
// @Tags         系统配置
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafSystemConfigEditByItemReq  true  "配置参数"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /systemconfig/editByItem [post]
func (w *WafSystemConfigApi) ModifyByItemApi(c *gin.Context) {
	var req request.WafSystemConfigEditByItemReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	if req.Item == "" {
		response.FailWithMessage("item 不能为空", c)
		return
	}

	// 密钥类配置：留空=保持原值，清空需提交哨兵值。
	req.Value = resolveSensitiveConfigValue(req.Item, req.Value,
		func() string { return wafSystemConfigService.GetDetailByItem(req.Item).Value })

	if msg, ok := checkSystemConfigValue(req.Item, req.Value); !ok {
		response.FailWithMessage(msg, c)
		return
	}

	err = wafSystemConfigService.ModifyByItemApi(req)
	if err != nil {
		response.FailWithMessage("编辑发生错误: "+err.Error(), c)
	} else {
		waftask.TaskLoadSetting(true)
		response.OkWithMessage("编辑成功", c)
	}
}

func (w *WafSystemConfigApi) GetDetailByItemApi(c *gin.Context) {
	var req request.WafSystemConfigDetailByItemReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafSystemConfigService.GetDetailByItemApi(req)
		waf_service.MaskSensitiveConfig(&bean)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// resolveSensitiveConfigValue 处理密钥类配置项的写入语义：
//   - 非密钥项：原样返回，行为不变；
//   - 密钥项 + 提交清空哨兵：返回空串（显式清空）；
//   - 密钥项 + 留空：返回库中原值（保持不变，防止只改备注等操作把密钥冲掉）；
//   - 密钥项 + 填了新值：返回新值。
//
// loadCurrent 惰性读取库中现值，仅在“密钥项且留空”时才调用。
func resolveSensitiveConfigValue(item, submitted string, loadCurrent func() string) string {
	if !waf_service.IsSensitiveConfigItem(item) {
		return submitted
	}
	if submitted == waf_service.ConfigClearSentinel {
		return ""
	}
	if submitted == "" {
		return loadCurrent()
	}
	return submitted
}

// checkSystemConfigValue 针对特定配置项做写入前校验。
// 配置值最终会进 SQL 的参数绑定，不存在拼接注入，但这些值来自管理端输入，
// 该挡的（引号、注释符、控制字符、超长、超多）在写库前就挡掉，别等查询时静默丢弃。
func checkSystemConfigValue(item string, value string) (string, bool) {
	switch item {
	case "attack_tag_exclude":
		if bad, ok := waf_service.ValidateAttackTagExclude(value); !ok {
			return fmt.Sprintf("排除标签不合法: %q（不能含引号/分号/反斜杠/注释符/控制字符，单项不超过 255 字符，最多 30 项）", bad), false
		}
	case "exclude_ip_log":
		// 与站点级清单同一套校验（checkExcludeIPLog 在 waf_host.go），存坏行当场拒绝
		if err := checkExcludeIPLog(value); err != nil {
			return err.Error(), false
		}
	}
	return "", true
}
