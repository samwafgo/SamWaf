package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/wafhostguard"
	"errors"
	"net"
	"strings"

	"github.com/gin-gonic/gin"
)

type WafHostGuardApi struct {
}

// normalizeHostGuardPage 兜底分页参数，避免 PageSize=0 时算出 Limit(0) 查不到数据
func normalizeHostGuardPage(pageIndex, pageSize *int) {
	if *pageIndex <= 0 {
		*pageIndex = 1
	}
	if *pageSize <= 0 {
		*pageSize = 20
	}
	if *pageSize > 500 {
		*pageSize = 500
	}
}

// checkBanTargetIP 校验封禁目标。只接受单 IP 与 CIDR：
// 这些值最终会进 ipset/netsh/pfctl，通配符、区间这类 WAF 应用层写法在系统层表达不了，
// 必须在 API 层挡住而不是传给底层命令。
func checkBanTargetIP(raw string) error {
	ip := strings.TrimSpace(raw)
	if ip == "" {
		return errors.New("IP不能为空")
	}
	if strings.Contains(ip, "/") {
		if _, _, err := net.ParseCIDR(ip); err != nil {
			return errors.New("CIDR格式不正确：" + ip)
		}
		return nil
	}
	if net.ParseIP(ip) == nil {
		return errors.New("IP格式不正确（系统层封禁只支持单个IP或CIDR网段）：" + ip)
	}
	return nil
}

// GetStatusApi 运行状态
// @Summary      主机防爆破运行状态
// @Description  返回采集是否运行、事件源、工作模式、环境能力与降级原因
// @Tags         主机防爆破
// @Produce      json
// @Success      200  {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/status [get]
func (w *WafHostGuardApi) GetStatusApi(c *gin.Context) {
	response.OkWithDetailed(wafhostguard.GetStatus(), "获取成功", c)
}

// GetStatisticsApi 概览统计
// @Summary      主机防爆破概览统计
// @Tags         主机防爆破
// @Produce      json
// @Success      200  {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/statistics [get]
func (w *WafHostGuardApi) GetStatisticsApi(c *gin.Context) {
	response.OkWithDetailed(wafHostGuardService.GetStatistics(), "获取成功", c)
}

// GetEventListApi 登录失败事件列表
// @Summary      主机登录失败事件列表
// @Tags         主机防爆破
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGuardEventSearchReq  true  "查询条件"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/event/list [post]
func (w *WafHostGuardApi) GetEventListApi(c *gin.Context) {
	var req request.WafHostGuardEventSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	normalizeHostGuardPage(&req.PageIndex, &req.PageSize)

	list, total, err := wafHostGuardService.GetEventList(req)
	if err != nil {
		response.FailWithMessage("查询失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(response.PageResult{
		List:      list,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "查询成功", c)
}

// GetBanListApi 封禁列表
// @Summary      主机防爆破封禁列表
// @Tags         主机防爆破
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGuardBanSearchReq  true  "查询条件"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/ban/list [post]
func (w *WafHostGuardApi) GetBanListApi(c *gin.Context) {
	var req request.WafHostGuardBanSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	normalizeHostGuardPage(&req.PageIndex, &req.PageSize)

	list, total, err := wafHostGuardService.GetBanList(req)
	if err != nil {
		response.FailWithMessage("查询失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(response.PageResult{
		List:      list,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "查询成功", c)
}

// ReleaseBanApi 提前解封
// @Summary      提前解封
// @Tags         主机防爆破
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGuardBanIdReq  true  "封禁记录ID"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/ban/release [post]
func (w *WafHostGuardApi) ReleaseBanApi(c *gin.Context) {
	var req request.WafHostGuardBanIdReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if strings.TrimSpace(req.Id) == "" {
		response.FailWithMessage("参数错误：ID不能为空", c)
		return
	}
	if err := wafHostGuardService.ReleaseBan(req.Id); err != nil {
		response.FailWithMessage("解封失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("已解封", c)
}

// PromoteBanApi 提升为永久封禁
// @Summary      提升为永久封禁
// @Tags         主机防爆破
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGuardBanIdReq  true  "封禁记录ID"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/ban/permanent [post]
func (w *WafHostGuardApi) PromoteBanApi(c *gin.Context) {
	var req request.WafHostGuardBanIdReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if strings.TrimSpace(req.Id) == "" {
		response.FailWithMessage("参数错误：ID不能为空", c)
		return
	}
	if err := wafHostGuardService.PromoteToPermanent(req.Id); err != nil {
		response.FailWithMessage("操作失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("已提升为永久封禁", c)
}

// ManualBanApi 手工封禁
// @Summary      手工封禁一个IP
// @Tags         主机防爆破
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGuardManualBanReq  true  "封禁参数"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/ban/manual [post]
func (w *WafHostGuardApi) ManualBanApi(c *gin.Context) {
	var req request.WafHostGuardManualBanReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if err := checkBanTargetIP(req.IP); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	if req.BanMinutes < 0 {
		response.FailWithMessage("封禁时长不能为负数（0 表示永久封禁）", c)
		return
	}
	if err := wafHostGuardService.ManualBan(req); err != nil {
		response.FailWithMessage("封禁失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("已封禁", c)
}

// GetOffenderListApi 攻击者档案列表
// @Summary      攻击者档案列表
// @Tags         主机防爆破
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGuardOffenderSearchReq  true  "查询条件"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/offender/list [post]
func (w *WafHostGuardApi) GetOffenderListApi(c *gin.Context) {
	var req request.WafHostGuardOffenderSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	normalizeHostGuardPage(&req.PageIndex, &req.PageSize)

	list, total, err := wafHostGuardService.GetOffenderList(req)
	if err != nil {
		response.FailWithMessage("查询失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(response.PageResult{
		List:      list,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "查询成功", c)
}

// ResetOffenderApi 重置攻击者阶梯
// @Summary      重置攻击者阶梯
// @Description  重置后该IP下次被封从第1级重新开始
// @Tags         主机防爆破
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGuardOffenderIdReq  true  "档案ID"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/offender/reset [post]
func (w *WafHostGuardApi) ResetOffenderApi(c *gin.Context) {
	var req request.WafHostGuardOffenderIdReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if strings.TrimSpace(req.Id) == "" {
		response.FailWithMessage("参数错误：ID不能为空", c)
		return
	}
	if err := wafHostGuardService.ResetOffender(req.Id); err != nil {
		response.FailWithMessage("重置失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("已重置该IP的封禁阶梯", c)
}

// DelOffenderApi 删除攻击者档案
// @Summary      删除攻击者档案
// @Tags         主机防爆破
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGuardOffenderIdReq  true  "档案ID"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/offender/del [post]
func (w *WafHostGuardApi) DelOffenderApi(c *gin.Context) {
	var req request.WafHostGuardOffenderIdReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if strings.TrimSpace(req.Id) == "" {
		response.FailWithMessage("参数错误：ID不能为空", c)
		return
	}
	if err := wafHostGuardService.DeleteOffender(req.Id); err != nil {
		response.FailWithMessage("删除失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("已删除", c)
}

// GetLadderApi 取封禁阶梯
// @Summary      获取封禁阶梯配置
// @Tags         主机防爆破
// @Produce      json
// @Success      200  {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/ladder/list [get]
func (w *WafHostGuardApi) GetLadderApi(c *gin.Context) {
	list, err := wafHostGuardService.GetLadders()
	if err != nil {
		response.FailWithMessage("查询失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(list, "查询成功", c)
}

// SaveLadderApi 保存封禁阶梯
// @Summary      保存封禁阶梯配置
// @Description  整表替换，前端一次提交全部级别
// @Tags         主机防爆破
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGuardLadderEditReq  true  "阶梯列表"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/ladder/save [post]
func (w *WafHostGuardApi) SaveLadderApi(c *gin.Context) {
	var req request.WafHostGuardLadderEditReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if err := wafHostGuardService.SaveLadders(req); err != nil {
		response.FailWithMessage("保存失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("保存成功", c)
}

// TestWhitelistApi 白名单自测
// @Summary      白名单自测
// @Description  输入一个IP，返回它会不会被豁免以及命中了哪一层白名单
// @Tags         主机防爆破
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGuardWhitelistTestReq  true  "待测IP"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/whitelist/test [post]
func (w *WafHostGuardApi) TestWhitelistApi(c *gin.Context) {
	var req request.WafHostGuardWhitelistTestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if strings.TrimSpace(req.IP) == "" {
		response.FailWithMessage("请输入要检测的IP", c)
		return
	}
	white, reason := wafHostGuardService.TestWhitelist(req.IP)
	response.OkWithDetailed(gin.H{
		"ip":          req.IP,
		"whitelisted": white,
		"reason":      reason,
	}, "检测完成", c)
}

// AddWhitelistApi 加入白名单
// @Summary      把IP加入白名单
// @Description  追加到白名单配置，并立即解除该IP当前的封禁
// @Tags         主机防爆破
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGuardWhitelistAddReq  true  "IP"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostguard/whitelist/add [post]
func (w *WafHostGuardApi) AddWhitelistApi(c *gin.Context) {
	var req request.WafHostGuardWhitelistAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if err := checkBanTargetIP(req.IP); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	if err := wafHostGuardService.AddToWhitelist(req.IP); err != nil {
		response.FailWithMessage("加入白名单失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("已加入白名单，该IP当前的封禁也已解除", c)
}
