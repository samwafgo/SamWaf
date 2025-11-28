package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"errors"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafBlockingPageApi struct {
}

func (w *WafBlockingPageApi) AddApi(c *gin.Context) {
	var req request.WafBlockingPageAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
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
		BlockingPage, total, _ := wafBlockingPageService.GetListApi(req)
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
		bean := wafBlockingPageService.GetDetailByIdApi(req.Id)
		err = wafBlockingPageService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误"+err.Error(), c)
		} else {
			w.NotifyWaf(req.HostCode)
			if bean.HostCode != req.HostCode && bean.HostCode != "" {
				//老的主机编码
				w.NotifyWaf(bean.HostCode)
			}
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafBlockingPageApi) NotifyWaf(hostCode string) {
	var blockingPageList []model.BlockingPage
	global.GWAF_LOCAL_DB.Where("host_code=? ", hostCode).Find(&blockingPageList)
	blockingPageMap := map[string]model.BlockingPage{}
	if len(blockingPageList) > 0 {
		for i := 0; i < len(blockingPageList); i++ {
			if blockingPageList[i].BlockingType == "not_match_website" {
				// 域名不匹配使用固定的key
				blockingPageMap["not_match_website"] = blockingPageList[i]
			} else if blockingPageList[i].BlockingType == "other_block" {
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
