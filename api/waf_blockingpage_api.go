package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/http/httpguts"
	"gorm.io/gorm"
)

type WafBlockingPageApi struct {
}

// normalizeContentPriority 归一化内容优先级：只接受白名单取值，其余（含空值、老数据）一律按默认的"优先自定义模版"处理
func normalizeContentPriority(v string) string {
	if v == model.BlockingPageContentPriorityBackend {
		return model.BlockingPageContentPriorityBackend
	}
	return model.BlockingPageContentPrioritySamwaf
}

func validateUnmatchedHostPage(hostCode, responseCode, attackType, content, headers string) error {
	if hostCode != global.GWAF_GLOBAL_HOST_CODE || responseCode != "403" || attackType != "" {
		return errors.New("未匹配网站响应仅支持全局网站、403响应码及通用类型")
	}
	if len(content) > 256*1024 || len(headers) > 16*1024 {
		return errors.New("页面内容或响应头超出长度限制")
	}
	if strings.TrimSpace(content) != "" {
		tmpl, err := template.New("unmatchedHost").Delims("[[", "]]").Parse(content)
		if err != nil {
			return errors.New("页面模板格式错误")
		}
		if err := tmpl.Execute(io.Discard, map[string]string{"SAMWAF_HOST": "example.com"}); err != nil {
			return errors.New("页面模板变量或上下文错误")
		}
	}
	if headers == "" {
		return nil
	}
	var list []map[string]string
	if err := json.Unmarshal([]byte(headers), &list); err != nil || len(list) > 32 {
		return errors.New("响应头格式错误或数量超出限制")
	}
	for _, header := range list {
		name, value := header["name"], header["value"]
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return errors.New("响应头名称或值格式错误")
		}
		switch strings.ToLower(name) {
		case "content-length", "content-encoding", "transfer-encoding", "connection", "trailer", "upgrade", "te":
			return errors.New("不支持设置传输控制响应头")
		}
	}
	return nil
}

func (w *WafBlockingPageApi) AddApi(c *gin.Context) {
	var req request.WafBlockingPageAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		if req.BlockingType != "not_match_website" && req.ResponseCode == "not_match_website" {
			response.FailWithMessage("响应代码格式错误", c)
			return
		}
		if req.BlockingType == "not_match_website" {
			if err := validateUnmatchedHostPage(req.HostCode, req.ResponseCode, req.AttackType, req.ResponseContent, req.ResponseHeader); err != nil {
				response.FailWithMessage(err.Error(), c)
				return
			}
		}
		req.ContentPriority = normalizeContentPriority(req.ContentPriority)
		cnt := wafBlockingPageService.CheckIsExistApi(req)
		if cnt == 0 {
			err = wafBlockingPageService.AddApi(req)
			if err == nil {
				w.NotifyWaf(req.HostCode)
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

func (w *WafBlockingPageApi) GetDetailApi(c *gin.Context) {
	var req request.WafBlockingPageDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafBlockingPageService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafBlockingPageApi) GetListApi(c *gin.Context) {
	var req request.WafBlockingPageSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		if req.PageIndex < 1 || req.PageSize < 1 || req.PageSize > 1000 {
			response.FailWithMessage("分页参数超出范围", c)
			return
		}
		BlockingPage, total, err := wafBlockingPageService.GetListApi(req)
		if err != nil {
			response.FailWithMessage("获取失败", c)
			return
		}
		response.OkWithDetailed(response.PageResult{
			List:      BlockingPage,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafBlockingPageApi) DelApi(c *gin.Context) {
	var req request.WafBlockingPageDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafBlockingPageService.GetDetailByIdApi(req.Id)
		if bean.Id == "" {
			response.FailWithMessage("未找到信息", c)
			return
		}
		err = wafBlockingPageService.DelApi(req)
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

func (w *WafBlockingPageApi) ModifyApi(c *gin.Context) {
	var req request.WafBlockingPageEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		if req.BlockingType != "not_match_website" && req.ResponseCode == "not_match_website" {
			response.FailWithMessage("响应代码格式错误", c)
			return
		}
		if req.BlockingType == "not_match_website" {
			if err := validateUnmatchedHostPage(req.HostCode, req.ResponseCode, req.AttackType, req.ResponseContent, req.ResponseHeader); err != nil {
				response.FailWithMessage(err.Error(), c)
				return
			}
		}
		req.ContentPriority = normalizeContentPriority(req.ContentPriority)
		bean := wafBlockingPageService.GetDetailByIdApi(req.Id)
		err = wafBlockingPageService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误"+err.Error(), c)
		} else {
			notifyWafHostChanged(w.NotifyWaf, bean.HostCode, req.HostCode)
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetUnmatchedBuiltinApi 返回未匹配网站的内置响应页面，供管理端弹窗预览，保持与运行时同一来源。
func (w *WafBlockingPageApi) GetUnmatchedBuiltinApi(c *gin.Context) {
	response.OkWithDetailed(global.GLOBAL_DEFAULT_NOT_MATCH_WEBSITE, "获取成功", c)
}

func (w *WafBlockingPageApi) NotifyWaf(hostCode string) {
	var blockingPageList []model.BlockingPage
	global.GWAF_LOCAL_DB.Where("host_code=? ", hostCode).Order("update_time ASC, id ASC").Find(&blockingPageList)
	blockingPageMap := map[string]model.BlockingPage{}
	if len(blockingPageList) > 0 {
		for i := 0; i < len(blockingPageList); i++ {
			if blockingPageList[i].BlockingType == "not_match_website" {
				// 域名不匹配使用固定的key
				blockingPageMap["not_match_website"] = blockingPageList[i]
			} else if blockingPageList[i].BlockingType == "other_block" && blockingPageList[i].ResponseCode != "not_match_website" {
				// other_block 类型根据 response_code 区分不同的错误页面
				// 例如: 403(WAF拦截), 404, 500, 502 等
				if blockingPageList[i].ResponseCode != "" {
					blockingPageMap[blockingPageList[i].ResponseCode] = blockingPageList[i]
				}
			}
		}
	}

	var chanInfo = spec.ChanCommonHost{
		HostCode: hostCode,
		Type:     enums.ChanTypeBlockingPage,
		Content:  blockingPageMap,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}
