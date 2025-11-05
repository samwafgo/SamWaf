package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/model/spec"
	"SamWaf/utils"
	"errors"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafAntiCCApi struct {
}

func (w *WafAntiCCApi) AddApi(c *gin.Context) {
	ruleHelper := &utils.RuleHelper{}
	var req request.WafAntiCCAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 检查是否启用了前置规则
		if req.IsEnableRule {
			// 检查规则内容是否为空
			if req.RuleContent == "" {
				response.FailWithMessage("前置规则内容不能为空", c)
				return
			}
			// 检查规则内容是否合法
			err = ruleHelper.CheckRuleAvailable(req.RuleContent)
			if err != nil {
				response.FailWithMessage("前置规则校验失败", c)
				return
			}
		}

		err = wafAntiCCService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafAntiCCService.AddApi(req)
			if err == nil {
				w.NotifyWaf(req.HostCode)
				response.OkWithMessage("添加成功", c)
			} else {

				response.FailWithMessage("添加失败 "+err.Error(), c)
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
func (w *WafAntiCCApi) GetDetailApi(c *gin.Context) {
	var req request.WafAntiCCDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafAntiCCService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafAntiCCApi) GetListApi(c *gin.Context) {
	var req request.WafAntiCCSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafAntiCCService.GetListApi(req)
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

func (w *WafAntiCCApi) GetBanIpListApi(c *gin.Context) {
	banIpList := global.GCACHE_WAFCACHE.ListAvailableKeysWithPrefix(enums.CACHE_CCVISITBAN_PRE)
	beans := make([]response2.CcIpRep, 0, len(banIpList))

	// 遍历 banIpList，将每个 IP 信息添加到 beans 中
	for banIp, duration := range banIpList {
		// 去掉 IP 的前缀
		banIp := strings.TrimPrefix(banIp, enums.CACHE_CCVISITBAN_PRE)

		// 将剩余时间格式化为 "hours:minutes:seconds" 格式
		remainTime := fmt.Sprintf("%02d时%02d分", int(duration.Hours()), int(duration.Minutes())%60)

		region := utils.GetCountry(banIp)
		// 将信息添加到 beans 中
		beans = append(beans, response2.CcIpRep{
			IP:         banIp,
			RemainTime: remainTime,
			Region:     fmt.Sprintf("%v", region),
		})
	}

	// 计算总条目数
	total := len(beans)
	// 返回带分页信息的响应（假设 req.PageIndex 和 req.PageSize 已在请求中解析）
	response.OkWithDetailed(response.PageResult{
		List:      beans,
		Total:     int64(total),
		PageIndex: 1,
		PageSize:  999999,
	}, "获取成功", c)
}

// RemoveCCBanIPApi 移除被封禁的IP
func (w *WafAntiCCApi) RemoveCCBanIPApi(c *gin.Context) {
	var req request.WafAntiCCRemoveBanIpReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		ccCacheKey := enums.CACHE_CCVISITBAN_PRE + req.Ip
		if global.GCACHE_WAFCACHE.IsKeyExist(ccCacheKey) {
			global.GCACHE_WAFCACHE.Remove(ccCacheKey)
			global.GWAF_CHAN_CLEAR_CC_IP <- req.Ip
			response.OkWithMessage(req.Ip+" 移除成功", c)
		} else {
			response.FailWithMessage("键值未找到或以过期", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafAntiCCApi) DelAntiCCApi(c *gin.Context) {
	var req request.WafAntiCCDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafAntiCCService.GetDetailByIdApi(req.Id)
		err = wafAntiCCService.DelApi(req)
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

func (w *WafAntiCCApi) ModifyAntiCCApi(c *gin.Context) {
	ruleHelper := &utils.RuleHelper{}
	var req request.WafAntiCCEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 检查是否启用了前置规则
		if req.IsEnableRule {
			// 检查规则内容是否为空
			if req.RuleContent == "" {
				response.FailWithMessage("前置规则内容不能为空", c)
				return
			}
			// 检查规则内容是否合法
			err = ruleHelper.CheckRuleAvailable(req.RuleContent)
			if err != nil {
				response.FailWithMessage("前置规则校验失败", c)
				return
			}
		}

		err = wafAntiCCService.ModifyApi(req)
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
func (w *WafAntiCCApi) NotifyWaf(host_code string) {
	var antiCC model.AntiCC
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Limit(1).Find(&antiCC)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeAnticc,
		Content:  antiCC,
	}
	global.GWAF_CHAN_MSG <- chanInfo

}
