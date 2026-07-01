package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafTamperRuleApi struct {
}

// AddApi 新增网页防篡改规则
func (w *WafTamperRuleApi) AddApi(c *gin.Context) {
	var req request.WafTamperRuleAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		cnt := wafTamperRuleService.CheckIsExistApi(req)
		if cnt == 0 {
			err = wafTamperRuleService.AddApi(req)
			if err == nil {
				w.NotifyWaf(req.HostCode)
				response.OkWithMessage("添加成功", c)
			} else {
				response.FailWithMessage("添加失败:"+err.Error(), c)
			}
			return
		} else {
			response.FailWithMessage("同站点下该URL的防篡改规则已存在", c)
			return
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetDetailApi 获取网页防篡改规则详情（不含基线正文）
func (w *WafTamperRuleApi) GetDetailApi(c *gin.Context) {
	var req request.WafTamperRuleDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafTamperRuleService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取网页防篡改规则列表（不含基线正文，保持轻量）
func (w *WafTamperRuleApi) GetListApi(c *gin.Context) {
	var req request.WafTamperRuleSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		list, total, _ := wafTamperRuleService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      list,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelApi 删除网页防篡改规则
func (w *WafTamperRuleApi) DelApi(c *gin.Context) {
	var req request.WafTamperRuleDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafTamperRuleService.GetDetailByIdApi(req.Id)
		if bean.Id == "" {
			response.FailWithMessage("未找到信息", c)
			return
		}
		err = wafTamperRuleService.DelApi(req)
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

// ModifyApi 编辑网页防篡改规则
func (w *WafTamperRuleApi) ModifyApi(c *gin.Context) {
	var req request.WafTamperRuleEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafTamperRuleService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误:"+err.Error(), c)
		} else {
			w.NotifyWaf(req.HostCode)
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// RelearnApi 重新学习基线
func (w *WafTamperRuleApi) RelearnApi(c *gin.Context) {
	var req request.WafTamperRuleRelearnReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafTamperRuleService.GetDetailByIdApi(req.Id)
		if bean.Id == "" {
			response.FailWithMessage("未找到信息", c)
			return
		}
		err = wafTamperRuleService.RelearnApi(req)
		if err != nil {
			response.FailWithMessage("操作失败:"+err.Error(), c)
		} else {
			w.NotifyWaf(bean.HostCode)
			response.OkWithMessage("已触发重新学习，正在后端重新抓取基线（无后端的站点将在下次访问时重学）", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// RelearnBatchApi 批量/整站重新学习基线
func (w *WafTamperRuleApi) RelearnBatchApi(c *gin.Context) {
	var req request.WafTamperRuleRelearnBatchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafTamperRuleService.RelearnBatchApi(req)
		if err != nil {
			response.FailWithMessage("操作失败:"+err.Error(), c)
		} else {
			w.NotifyWaf(req.HostCode)
			response.OkWithMessage("已触发重新学习，正在后端重新抓取基线（无后端的站点将在下次访问时重学）", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ExtractUrlsApi 抓取当前站点后端的一个页面，返回同站静态资源候选供批量添加
func (w *WafTamperRuleApi) ExtractUrlsApi(c *gin.Context) {
	var req request.WafTamperRuleExtractReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		list, e := wafTamperRuleService.ExtractUrlsApi(req)
		if e != nil {
			response.FailWithMessage(e.Error(), c)
		} else {
			response.OkWithDetailed(gin.H{"list": list, "total": len(list)}, "提取成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// AddBatchApi 批量新增受保护 URL 规则
func (w *WafTamperRuleApi) AddBatchApi(c *gin.Context) {
	var req request.WafTamperRuleAddBatchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		added, skipped, e := wafTamperRuleService.AddBatchApi(req)
		if e != nil {
			response.FailWithMessage("批量添加失败:"+e.Error(), c)
		} else {
			w.NotifyWaf(req.HostCode)
			response.OkWithDetailed(gin.H{"added": added, "skipped": skipped},
				fmt.Sprintf("批量添加完成：新增 %d 条，跳过 %d 条", added, skipped), c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelBatchApi 批量删除受保护 URL 规则
func (w *WafTamperRuleApi) DelBatchApi(c *gin.Context) {
	var req request.WafTamperRuleDelBatchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		cnt, e := wafTamperRuleService.DelBatchApi(req)
		if e != nil {
			response.FailWithMessage("批量删除失败:"+e.Error(), c)
		} else {
			w.NotifyWaf(req.HostCode)
			response.OkWithMessage(fmt.Sprintf("已删除 %d 条", cnt), c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetBaselineApi 查看基线正文（按需拉取；文本回内容，二进制只回元数据）
func (w *WafTamperRuleApi) GetBaselineApi(c *gin.Context) {
	var req request.WafTamperRuleBaselineReq
	err := c.ShouldBind(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	bean := wafTamperRuleService.GetBaselineApi(req.Id)
	if bean.Id == "" {
		response.FailWithMessage("未找到信息", c)
		return
	}
	isText := isTextContentType(bean.ContentType)
	result := gin.H{
		"content_type":    bean.ContentType,
		"content_size":    bean.ContentSize,
		"baseline_hash":   bean.BaselineHash,
		"baseline_status": bean.BaselineStatus,
		"last_learn_time": bean.LastLearnTime,
		"is_text":         isText,
		"content":         "", // 文本正文
		"content_base64":  "", // 非文本(图片等)以 base64 返回，供前端 data URL 渲染/下载
	}
	if len(bean.BaselineContent) > 0 {
		if isText {
			result["content"] = string(bean.BaselineContent)
		} else {
			result["content_base64"] = base64.StdEncoding.EncodeToString(bean.BaselineContent)
		}
	}
	response.OkWithDetailed(result, "获取成功", c)
}

// isTextContentType 判断 Content-Type 是否可按文本展示
func isTextContentType(ct string) bool {
	ct = strings.ToLower(ct)
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	for _, kw := range []string{"javascript", "json", "xml", "html", "css", "ecmascript", "x-www-form-urlencoded"} {
		if strings.Contains(ct, kw) {
			return true
		}
	}
	return false
}

// NotifyWaf 通知到 waf 引擎实时生效
func (w *WafTamperRuleApi) NotifyWaf(host_code string) {
	var list []model.TamperRule
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Find(&list)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeTamperRule,
		Content:  list,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}
