package api

import (
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"encoding/json"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
)

/*
*
通知订阅精细化配置 API（issue #822）

这些接口回答用户的三个问题：

	"能不能少发点"   → config / batchconfig（频控）
	"能不能换个格式" → preview / templatevars（模板）
	"为什么没收到"   → dryrun / test（调试）
*/

// ========== 入参校验 ==========

// buildThrottleJSON 校验并序列化频控配置
//
// 所有边界都在这里卡死：窗口/冷却/上限的取值范围、梯度长度、去重维度白名单。
// 校验放 api 层是分层要求，也避免脏配置进到频控引擎里变成除零或死循环。
func buildThrottleJSON(mode string, req request.WafNotifyThrottleReq) (string, string, error) {
	if mode == "" {
		mode = model.ThrottleModeInherit
	}
	if !model.IsValidThrottleMode(mode) {
		return "", "", errors.New("频控模式不合法")
	}

	if req.AggregateWindowSec != 0 && (req.AggregateWindowSec < model.ThrottleWindowMin || req.AggregateWindowSec > model.ThrottleWindowMax) {
		return "", "", errors.New("聚合窗口必须在 1~3600 秒之间")
	}
	if req.AggregateMaxDetail != 0 && (req.AggregateMaxDetail < model.ThrottleMaxDetailMin || req.AggregateMaxDetail > model.ThrottleMaxDetailMax) {
		return "", "", errors.New("合并展示条数必须在 1~50 之间")
	}
	if req.CooldownResetSec != 0 && (req.CooldownResetSec < 1 || req.CooldownResetSec > model.ThrottleResetSecMax) {
		return "", "", errors.New("冷却重置时间必须在 1~86400 秒之间")
	}
	if req.MaxPerHour < 0 || req.MaxPerHour > model.ThrottleMaxPerHourMax {
		return "", "", errors.New("每小时上限必须在 0~10000 之间")
	}
	if len(req.CooldownStepsSec) > model.ThrottleCooldownSteps {
		return "", "", errors.New("冷却梯度最多 5 级")
	}
	for _, s := range req.CooldownStepsSec {
		if s < model.ThrottleCooldownMin || s > model.ThrottleCooldownMax {
			return "", "", errors.New("冷却梯度每一级必须在 1~86400 秒之间")
		}
	}
	for _, k := range req.DedupKeys {
		if !model.IsValidDedupKey(k) {
			return "", "", errors.New("去重维度不合法: " + k)
		}
	}
	if !model.IsValidQuietHours(req.QuietHours) {
		return "", "", errors.New("免打扰时段格式应为 HH:MM-HH:MM")
	}
	if !model.IsValidSeverity(req.QuietHoursBypassSeverity) {
		return "", "", errors.New("免打扰穿透级别不合法")
	}

	cfg := model.NotifyThrottleConfig{
		AggregateWindowSec:       req.AggregateWindowSec,
		AggregateMaxDetail:       req.AggregateMaxDetail,
		CooldownStepsSec:         req.CooldownStepsSec,
		CooldownResetSec:         req.CooldownResetSec,
		MaxPerHour:               req.MaxPerHour,
		DedupKeys:                req.DedupKeys,
		QuietHours:               req.QuietHours,
		QuietHoursBypassSeverity: req.QuietHoursBypassSeverity,
	}.Sanitize()

	buf, err := json.Marshal(cfg)
	if err != nil {
		return "", "", errors.New("频控配置序列化失败")
	}
	return mode, string(buf), nil
}

// buildFilterJSON 校验并序列化过滤条件
func buildFilterJSON(req request.WafNotifyFilterReq) (string, error) {
	if !model.IsValidSeverity(req.MinSeverity) {
		return "", errors.New("最低严重级别不合法")
	}
	if len(req.Domains) > 100 || len(req.ExcludeIps) > 100 || len(req.Keywords) > 100 {
		return "", errors.New("过滤条件每项最多 100 条")
	}
	for _, v := range append(append([]string{}, req.Domains...), append(req.ExcludeIps, req.Keywords...)...) {
		if len(v) > 256 {
			return "", errors.New("过滤条件单项长度不能超过 256")
		}
	}

	cfg := model.NotifyFilterConfig{
		Domains:     trimList(req.Domains),
		ExcludeIps:  trimList(req.ExcludeIps),
		Keywords:    trimList(req.Keywords),
		MinSeverity: req.MinSeverity,
	}
	if cfg.IsEmpty() {
		return "", nil // 全空就存空串，前端读到就知道"没配过滤"
	}
	buf, err := json.Marshal(cfg)
	if err != nil {
		return "", errors.New("过滤条件序列化失败")
	}
	return string(buf), nil
}

func trimList(list []string) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// checkTemplateLen 模板长度校验
func checkTemplateLen(title, content string) error {
	if len(title) > model.NotifyTitleTemplateMax {
		return errors.New("标题模板长度不能超过 500")
	}
	if len(content) > model.NotifyBodyTemplateMax {
		return errors.New("正文模板长度不能超过 8192")
	}
	return nil
}

// ========== 接口 ==========

// SaveConfigApi 保存单个订阅的频控/模板/过滤配置
// @Summary      保存通知订阅精细化配置
// @Description  为单个「消息类型 × 渠道」订阅配置频率控制、消息模板与过滤条件
// @Tags         通知-订阅
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafNotifySubscriptionConfigReq  true  "订阅配置"
// @Success      200   {object}  response.Response  "保存成功"
// @Security     ApiKeyAuth
// @Router       /notify/subscription/config [post]
func (w *WafNotifySubscriptionApi) SaveConfigApi(c *gin.Context) {
	var req request.WafNotifySubscriptionConfigReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	if _, err := wafNotifySubscriptionService.GetById(req.Id); err != nil {
		response.FailWithMessage("订阅不存在", c)
		return
	}
	mode, throttleJSON, err := buildThrottleJSON(req.ThrottleMode, req.Throttle)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	filterJSON, err := buildFilterJSON(req.Filter)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	if err = checkTemplateLen(req.TitleTemplate, req.ContentTemplate); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	// 模板先试渲染一次，语法错误当场告诉用户，别等到真出事时才降级
	if err = validateTemplates(req.TitleTemplate, req.ContentTemplate); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}

	if err = wafNotifySubscriptionService.SaveConfigApi(req.Id, mode, throttleJSON, filterJSON,
		req.TitleTemplate, req.ContentTemplate); err != nil {
		response.FailWithMessage("保存失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("保存成功", c)
}

// BatchConfigApi 批量套用配置
// @Summary      批量套用通知订阅配置
// @Description  把一份频控/模板/过滤配置套用到某类渠道的全部消息类型，或某个消息类型的全部渠道
// @Tags         通知-订阅
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafNotifySubscriptionBatchConfigReq  true  "批量配置"
// @Success      200   {object}  response.Response  "套用成功"
// @Security     ApiKeyAuth
// @Router       /notify/subscription/batchconfig [post]
func (w *WafNotifySubscriptionApi) BatchConfigApi(c *gin.Context) {
	var req request.WafNotifySubscriptionBatchConfigReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if req.ChannelType == "" && req.MessageType == "" {
		response.FailWithMessage("请指定渠道类型或消息类型", c)
		return
	}
	if req.MessageType != "" && !waf_service.IsKnownMessageType(req.MessageType) {
		response.FailWithMessage("消息类型不合法", c)
		return
	}
	if !req.ApplyThrottle && !req.ApplyTemplate && !req.ApplyFilter {
		response.FailWithMessage("请至少选择一项要套用的配置", c)
		return
	}

	editMap := map[string]interface{}{}
	if req.ApplyThrottle {
		mode, throttleJSON, err := buildThrottleJSON(req.ThrottleMode, req.Throttle)
		if err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
		editMap["ThrottleMode"] = mode
		editMap["ThrottleJSON"] = throttleJSON
	}
	if req.ApplyTemplate {
		if err := checkTemplateLen(req.TitleTemplate, req.ContentTemplate); err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
		if err := validateTemplates(req.TitleTemplate, req.ContentTemplate); err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
		editMap["TitleTemplate"] = req.TitleTemplate
		editMap["ContentTemplate"] = req.ContentTemplate
	}
	if req.ApplyFilter {
		filterJSON, err := buildFilterJSON(req.Filter)
		if err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
		editMap["FilterJSON"] = filterJSON
	}

	var targets []model.NotifySubscription
	if req.MessageType != "" {
		targets = wafNotifySubscriptionService.GetSubscriptionsByMessageTypeAll(req.MessageType)
	} else {
		targets = wafNotifySubscriptionService.GetSubscriptionsByChannelType(req.ChannelType)
	}
	// 两个条件都给了就取交集：既限定渠道类型又限定消息类型
	if req.MessageType != "" && req.ChannelType != "" {
		allowed := map[string]bool{}
		for _, s := range wafNotifySubscriptionService.GetSubscriptionsByChannelType(req.ChannelType) {
			allowed[s.Id] = true
		}
		filtered := make([]model.NotifySubscription, 0, len(targets))
		for _, s := range targets {
			if allowed[s.Id] {
				filtered = append(filtered, s)
			}
		}
		targets = filtered
	}

	success := 0
	for _, sub := range targets {
		if err := wafNotifySubscriptionService.SaveConfigPartialApi(sub.Id, copyMap(editMap)); err == nil {
			success++
		}
	}
	response.OkWithDetailed(gin.H{"total": len(targets), "success": success}, "套用成功", c)
}

func copyMap(src map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(src)+1)
	for k, v := range src {
		out[k] = v
	}
	return out
}

// PreviewApi 模板预览（不发送、不写日志）
// @Summary      预览通知模板渲染结果
// @Description  用样例数据渲染标题与正文，不发送任何通知
// @Tags         通知-订阅
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafNotifySubscriptionPreviewReq  true  "预览参数"
// @Success      200   {object}  response.Response  "预览成功"
// @Security     ApiKeyAuth
// @Router       /notify/subscription/preview [post]
func (w *WafNotifySubscriptionApi) PreviewApi(c *gin.Context) {
	var req request.WafNotifySubscriptionPreviewReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if !waf_service.IsKnownMessageType(req.MessageType) {
		response.FailWithMessage("消息类型不合法", c)
		return
	}
	if err := checkTemplateLen(req.TitleTemplate, req.ContentTemplate); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}

	ev := waf_service.SampleNotifyEvent(req.MessageType)
	sub := model.NotifySubscription{
		MessageType:     req.MessageType,
		TitleTemplate:   req.TitleTemplate,
		ContentTemplate: req.ContentTemplate,
	}
	title, content, used := waf_service.RenderNotifyMessage(sub, req.ChannelType, ev)

	response.OkWithDetailed(gin.H{
		"title":         title,
		"content":       content,
		"template_used": used,
		"is_fallback":   used == model.TemplateUsedFallback,
	}, "预览成功", c)
}

// TestApi 订阅级测试发送
// @Summary      测试发送通知订阅
// @Description  用样例数据与当前模板真实发送一条通知，绕过频率控制与过滤条件
// @Tags         通知-订阅
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafNotifySubscriptionTestReq  true  "测试参数"
// @Success      200   {object}  response.Response  "发送成功"
// @Security     ApiKeyAuth
// @Router       /notify/subscription/test [post]
func (w *WafNotifySubscriptionApi) TestApi(c *gin.Context) {
	var req request.WafNotifySubscriptionTestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := checkTemplateLen(req.TitleTemplate, req.ContentTemplate); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}

	sub, err := wafNotifySubscriptionService.GetById(req.Id)
	if err != nil {
		response.FailWithMessage("订阅不存在", c)
		return
	}
	channel := wafNotifyChannelService.GetDetailApi(request.WafNotifyChannelDetailReq{Id: sub.ChannelId})
	if channel.Id == "" {
		response.FailWithMessage("渠道不存在", c)
		return
	}

	if err = waf_service.WafNotifySenderServiceApp.SendTestToSubscription(sub, channel,
		req.TitleTemplate, req.ContentTemplate); err != nil {
		response.FailWithMessage("发送失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("发送成功，请检查是否收到通知", c)
}

// DryRunApi 干跑：只演算不发送
// @Summary      通知订阅干跑演算
// @Description  演算当前状态下一条事件会不会发出去、被什么挡住，不产生任何外发流量
// @Tags         通知-订阅
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafNotifySubscriptionDryRunReq  true  "干跑参数"
// @Success      200   {object}  response.Response  "演算成功"
// @Security     ApiKeyAuth
// @Router       /notify/subscription/dryrun [post]
func (w *WafNotifySubscriptionApi) DryRunApi(c *gin.Context) {
	var req request.WafNotifySubscriptionDryRunReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	sub, err := wafNotifySubscriptionService.GetById(req.Id)
	if err != nil {
		response.FailWithMessage("订阅不存在", c)
		return
	}

	res := waf_service.WafNotifyThrottleServiceApp.DryRun(sub)
	eff := res.Effective
	response.OkWithDetailed(gin.H{
		"would_send":    res.WouldSend,
		"action":        res.Action,
		"reason":        res.Reason,
		"reason_text":   res.ReasonText,
		"cooldown_left": res.CooldownLeft,
		"hour_used":     res.HourUsed,
		"suppressed":    res.Suppressed,
		"effective": gin.H{
			"mode":                 eff.Mode,
			"aggregate_window_sec": eff.AggregateWindowSec,
			"aggregate_max_detail": eff.AggregateMaxDetail,
			"cooldown_steps_sec":   eff.CooldownStepsSec,
			"cooldown_reset_sec":   eff.CooldownResetSec,
			"max_per_hour":         eff.MaxPerHour,
			"dedup_keys":           eff.DedupKeys,
			"quiet_hours":          eff.QuietHours,
		},
	}, "演算成功", c)
}

// TemplateVarsApi 取某消息类型可用的模板变量
// @Summary      获取通知模板可用变量
// @Description  返回指定消息类型可用的模板变量清单与内置默认模板示例
// @Tags         通知-订阅
// @Accept       json
// @Produce      json
// @Param        message_type  query     string  true  "消息类型"
// @Success      200   {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /notify/subscription/templatevars [get]
func (w *WafNotifySubscriptionApi) TemplateVarsApi(c *gin.Context) {
	var req request.WafNotifySubscriptionTemplateVarsReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if !waf_service.IsKnownMessageType(req.MessageType) {
		response.FailWithMessage("消息类型不合法", c)
		return
	}
	sample := waf_service.SampleNotifyEvent(req.MessageType)
	response.OkWithDetailed(gin.H{
		"vars":              waf_service.GetNotifyTemplateVars(req.MessageType),
		"default_title":     sample.DefaultTitle,
		"default_content":   sample.DefaultContent,
		"message_type_name": waf_service.GetMessageTypeName(req.MessageType),
	}, "获取成功", c)
}

// GetGlobalThrottleApi 获取全局默认频控配置
// @Summary      获取通知全局默认频率配置
// @Description  获取通知的全局默认频控参数，订阅未单独配置时继承这份
// @Tags         通知-订阅
// @Produce      json
// @Success      200   {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /notify/globalthrottle [get]
func (w *WafNotifySubscriptionApi) GetGlobalThrottleApi(c *gin.Context) {
	cfg := waf_service.WafNotifyThrottleServiceApp.GetGlobal()
	response.OkWithDetailed(gin.H{
		"mode":       cfg.Mode,
		"debug_mode": cfg.DebugMode,
		"throttle": gin.H{
			"aggregate_window_sec":        cfg.Config.AggregateWindowSec,
			"aggregate_max_detail":        cfg.Config.AggregateMaxDetail,
			"cooldown_steps_sec":          cfg.Config.CooldownStepsSec,
			"cooldown_reset_sec":          cfg.Config.CooldownResetSec,
			"max_per_hour":                cfg.Config.MaxPerHour,
			"dedup_keys":                  cfg.Config.DedupKeys,
			"quiet_hours":                 cfg.Config.QuietHours,
			"quiet_hours_bypass_severity": cfg.Config.QuietHoursBypassSeverity,
		},
		"builtin": gin.H{
			"aggregate_window_sec": 10,
			"cooldown_steps_sec":   []int{60, 300, 900},
			"cooldown_reset_sec":   1800,
		},
	}, "获取成功", c)
}

// UpdateGlobalThrottleApi 更新全局默认频控配置
// @Summary      更新通知全局默认频率配置
// @Description  更新全局默认频控参数，立即生效
// @Tags         通知-订阅
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafNotifyGlobalThrottleUpdateReq  true  "全局频控配置"
// @Success      200   {object}  response.Response  "更新成功"
// @Security     ApiKeyAuth
// @Router       /notify/globalthrottle/update [post]
func (w *WafNotifySubscriptionApi) UpdateGlobalThrottleApi(c *gin.Context) {
	var req request.WafNotifyGlobalThrottleUpdateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if req.Mode == "" || req.Mode == model.ThrottleModeInherit {
		response.FailWithMessage("全局默认模式不能为继承", c)
		return
	}
	mode, throttleJSON, err := buildThrottleJSON(req.Mode, req.Throttle)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}

	var cfg model.NotifyThrottleConfig
	_ = json.Unmarshal([]byte(throttleJSON), &cfg)
	if err = waf_service.WafNotifyThrottleServiceApp.SaveGlobal(waf_service.NotifyGlobalThrottle{
		Mode:      mode,
		Config:    cfg,
		DebugMode: req.DebugMode,
	}); err != nil {
		response.FailWithMessage("保存失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("保存成功", c)
}

// validateTemplates 用样例数据试渲染，语法错误立刻反馈
func validateTemplates(titleTpl, contentTpl string) error {
	if strings.TrimSpace(titleTpl) == "" && strings.TrimSpace(contentTpl) == "" {
		return nil
	}
	sub := model.NotifySubscription{TitleTemplate: titleTpl, ContentTemplate: contentTpl}
	_, _, used := waf_service.RenderNotifyMessage(sub, "", waf_service.SampleNotifyEvent(model.MSG_TYPE_RULE_TRIGGER))
	if used == model.TemplateUsedFallback {
		return errors.New("模板渲染失败，请检查语法（变量写法形如 {{.Domain}}）")
	}
	return nil
}
