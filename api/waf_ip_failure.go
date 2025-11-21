package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"SamWaf/wafipban"
	"SamWaf/waftask"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

type WafIPFailureApi struct {
}

// GetConfigApi 获取IP失败封禁配置
func (w *WafIPFailureApi) GetConfigApi(c *gin.Context) {
	var req request.WafIPFailureConfigReq
	err := c.ShouldBind(&req)
	if err == nil {
		configResp := response2.IPFailureConfigResp{
			Enabled:     global.GCONFIG_IP_FAILURE_BAN_ENABLED,
			StatusCodes: global.GCONFIG_IP_FAILURE_STATUS_CODES,
			LockTime:    global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME,
		}
		response.OkWithDetailed(configResp, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// SetConfigApi 设置IP失败封禁配置
func (w *WafIPFailureApi) SetConfigApi(c *gin.Context) {
	var req request.WafIPFailureSetConfigReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 更新配置
		// 1. 更新启用状态
		config := wafSystemConfigService.GetDetailByItemApi(request.WafSystemConfigDetailByItemReq{Item: "ip_failure_ban_enabled"})
		wafSystemConfigService.ModifyApi(request.WafSystemConfigEditReq{
			Id:        config.Id,
			Item:      config.Item,
			ItemClass: config.ItemClass,
			Value:     fmt.Sprintf("%d", req.Enabled),
			Remarks:   config.Remarks,
			ItemType:  config.ItemType,
			Options:   config.Options,
		})

		// 2. 更新状态码
		config = wafSystemConfigService.GetDetailByItemApi(request.WafSystemConfigDetailByItemReq{Item: "ip_failure_status_codes"})
		wafSystemConfigService.ModifyApi(request.WafSystemConfigEditReq{
			Id:        config.Id,
			Item:      config.Item,
			ItemClass: config.ItemClass,
			Value:     req.StatusCodes,
			Remarks:   config.Remarks,
			ItemType:  config.ItemType,
			Options:   config.Options,
		})

		// 3. 更新锁定时间
		config = wafSystemConfigService.GetDetailByItemApi(request.WafSystemConfigDetailByItemReq{Item: "ip_failure_ban_lock_time"})
		wafSystemConfigService.ModifyApi(request.WafSystemConfigEditReq{
			Id:        config.Id,
			Item:      config.Item,
			ItemClass: config.ItemClass,
			Value:     fmt.Sprintf("%d", req.LockTime),
			Remarks:   config.Remarks,
			ItemType:  config.ItemType,
			Options:   config.Options,
		})

		// 重新加载配置
		waftask.TaskLoadSetting(true)

		response.OkWithMessage("设置成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetBanIpListApi 获取被封禁的IP列表
func (w *WafIPFailureApi) GetBanIpListApi(c *gin.Context) {
	// 获取所有IP失败记录
	banIpList := global.GCACHE_WAFCACHE.ListAvailableKeysWithPrefix(enums.CACHE_IP_FAILURE_PRE)
	beans := make([]response2.IPFailureIpResp, 0, len(banIpList))

	manager := wafipban.GetIPFailureManager()

	// 遍历 banIpList，将每个 IP 信息添加到 beans 中
	for banKey, duration := range banIpList {
		// 去掉 IP 的前缀
		ip := strings.TrimPrefix(banKey, enums.CACHE_IP_FAILURE_PRE)

		// 获取IP失败详细信息
		record := manager.GetFailureInfo(ip)
		if record == nil {
			continue
		}

		// 只显示满足条件的IP（即有阈值记录的IP，表示是被规则封禁的）
		if record.TriggerMinutes == 0 || record.TriggerCount == 0 {
			continue
		}

		// 将剩余时间格式化：小于1分钟显示秒，否则显示时和分
		var remainTime string
		totalMinutes := int(duration.Minutes())
		if totalMinutes < 1 {
			// 小于1分钟，显示秒
			seconds := int(duration.Seconds())
			remainTime = fmt.Sprintf("%d秒", seconds)
		} else {
			// 大于等于1分钟，显示时和分
			hours := int(duration.Hours())
			minutes := totalMinutes % 60
			if hours > 0 {
				remainTime = fmt.Sprintf("%d时%02d分", hours, minutes)
			} else {
				remainTime = fmt.Sprintf("%d分", minutes)
			}
		}

		region := utils.GetCountry(ip)

		// 将信息添加到 beans 中
		beans = append(beans, response2.IPFailureIpResp{
			IP:             ip,
			FailCount:      record.Count,
			FirstTime:      record.FirstTime.Format("2006-01-02 15:04:05"),
			LastTime:       record.LastTime.Format("2006-01-02 15:04:05"),
			RemainTime:     remainTime,
			Region:         fmt.Sprintf("%v", region),
			TriggerMinutes: record.TriggerMinutes,
			TriggerCount:   record.TriggerCount,
		})
	}

	// 计算总条目数
	total := len(beans)

	// 返回带分页信息的响应
	response.OkWithDetailed(response.PageResult{
		List:      beans,
		Total:     int64(total),
		PageIndex: 1,
		PageSize:  999999,
	}, "获取成功", c)
}

// RemoveIPFailureBanIPApi 移除被封禁的IP
func (w *WafIPFailureApi) RemoveIPFailureBanIPApi(c *gin.Context) {
	var req request.WafIPFailureRemoveBanIpReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 直接清除失败记录窗口累积
		manager := wafipban.GetIPFailureManager()
		manager.ClearIPFailure(req.Ip)
		global.GCACHE_WAFCACHE.Remove(enums.CACHE_CCVISITBAN_PRE + req.Ip)
		response.OkWithMessage(req.Ip+" 移除成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
