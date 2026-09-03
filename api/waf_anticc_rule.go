package api

import (
	"SamWaf/model"
	"strings"

	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/model/spec"
	"SamWaf/wafenginecore/ccstats"

	"github.com/gin-gonic/gin"
)

type WafAntiCCRuleApi struct {
}

// notifyCCRuleChanged 通知引擎重新加载某个网站的CC规则。
// 规则被移到别的网站时，新旧两个网站都要通知：只通知新站会让旧站一直用着已经不属于它的规则。
func notifyCCRuleChanged(hostCodes ...string) {
	seen := map[string]bool{}
	for _, code := range hostCodes {
		if code == "" || seen[code] {
			continue
		}
		seen[code] = true
		global.GWAF_CHAN_MSG <- spec.ChanCommonHost{
			HostCode: code,
			Type:     enums.ChanTypeAntiCCRule,
		}
	}
}

// maxCCRuleHostCodes 「全部网站 + 指定分组」查看方式一次能带的站点数上限
const maxCCRuleHostCodes = 500

func (w *WafAntiCCRuleApi) GetListApi(c *gin.Context) {
	var req request.WafAntiCCRuleSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	// host_codes 由客户端传入，剔空并封顶，避免拼出超长 IN 条件
	if len(req.HostCodes) > 0 {
		codes := make([]string, 0, len(req.HostCodes))
		for _, code := range req.HostCodes {
			code = strings.TrimSpace(code)
			if code == "" {
				continue
			}
			codes = append(codes, code)
			if len(codes) >= maxCCRuleHostCodes {
				break
			}
		}
		req.HostCodes = codes
	}
	list, total, err := wafAntiCCRuleService.GetListApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	response.OkWithDetailed(response.PageResult{
		List:      withCaptchaExclude(list),
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "获取成功", c)
}

func (w *WafAntiCCRuleApi) GetDetailApi(c *gin.Context) {
	var req request.WafAntiCCRuleDetailReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	response.OkWithDetailed(wafAntiCCRuleService.GetDetailApi(req.Id), "获取成功", c)
}

func (w *WafAntiCCRuleApi) AddApi(c *gin.Context) {
	var req request.WafAntiCCRuleAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	rule, err := wafAntiCCRuleService.AddApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	notifyCCRuleChanged(rule.HostCode)
	response.OkWithMessage("添加成功", c)
}

func (w *WafAntiCCRuleApi) ModifyApi(c *gin.Context) {
	var req request.WafAntiCCRuleEditReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	oldHostCode, err := wafAntiCCRuleService.ModifyApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	notifyCCRuleChanged(req.HostCode, oldHostCode)
	response.OkWithMessage("编辑成功", c)
}

func (w *WafAntiCCRuleApi) DelApi(c *gin.Context) {
	var req request.WafAntiCCRuleDelReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	hostCode, err := wafAntiCCRuleService.DelApi(req.Id)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	// 规则没了，它的命中统计也一起清掉：留着会在看板里显示一条已经不存在的规则的旧数据。
	// 只在删除时清，改动（改名/调阈值）不清——那些数字仍然是这条规则攒下来的。
	ccstats.Default.Drop(req.Id)
	notifyCCRuleChanged(hostCode)
	response.OkWithMessage("删除成功", c)
}

func (w *WafAntiCCRuleApi) ToggleApi(c *gin.Context) {
	var req request.WafAntiCCRuleToggleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	hostCode, err := wafAntiCCRuleService.ToggleApi(req)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	notifyCCRuleChanged(hostCode)
	response.OkWithMessage("操作成功", c)
}

func (w *WafAntiCCRuleApi) SortApi(c *gin.Context) {
	var req request.WafAntiCCRuleSortReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafAntiCCRuleService.SortApi(req); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	notifyCCRuleChanged(req.HostCode)
	response.OkWithMessage("排序成功", c)
}

// ccRuleWithMeta 在规则本体之外带上该站点「永不挑战的路径」。
//
// 界面要能看出「这条规则的动作是人机验证，但它管的路径正好在豁免清单里」这种冲突。
// 由后端一次算好随列表返回，而不是让前端为每个站点各发一次详情请求。
type ccRuleWithMeta struct {
	model.AntiCCRule
	CaptchaExcludeURLs string `json:"captcha_exclude_urls"`
}

func withCaptchaExclude(list []model.AntiCCRule) []ccRuleWithMeta {
	out := make([]ccRuleWithMeta, 0, len(list))
	if len(list) == 0 {
		return out
	}
	excludeByHost := map[string]string{}
	globalHostCodes := make([]string, 0, 2)
	unionSeen := map[string]bool{}
	union := make([]string, 0, 8)
	for _, h := range wafHostService.GetAllHostApi() {
		// 全局网站可能不止一条记录，全都要挂上并集
		if h.GLOBAL_HOST == 1 {
			globalHostCodes = append(globalHostCodes, h.Code)
			continue
		}
		if h.CaptchaJSON == "" {
			continue
		}
		ex := string(model.ParseCaptchaConfig(h.CaptchaJSON).ExcludeURLs)
		if ex == "" {
			continue
		}
		excludeByHost[h.Code] = ex
		// 全局规则命中哪个站点，就按那个站点的清单判定，所以取并集：
		// 只要有站点配了，这条全局规则就存在「某些站点不会被挑战」的情况
		for _, p := range strings.Split(ex, "\n") {
			p = strings.TrimSpace(p)
			if p == "" || unionSeen[p] {
				continue
			}
			unionSeen[p] = true
			union = append(union, p)
		}
	}
	if len(union) > 0 {
		joined := strings.Join(union, "\n")
		for _, code := range globalHostCodes {
			excludeByHost[code] = joined
		}
	}
	// 命中数一次性取回整张表再按规则查，避免每条规则各自去抢一次锁
	hits := ccstats.Default.Counts()
	for _, rule := range list {
		rule.HitCount = hits[rule.Id]
		out = append(out, ccRuleWithMeta{
			AntiCCRule:         rule,
			CaptchaExcludeURLs: excludeByHost[rule.HostCode],
		})
	}
	return out
}

// GetCaptchaOverviewApi 各站点的人机验证要点，供全局 CC 规则展示用。
//
// 全局规则没有「所属站点」可跳，人机验证的配置又落在各个站点上，
// 前端要按站点逐条列出来，才知道哪几个站点会把这条规则要求的挑战跳过。
func (w *WafAntiCCRuleApi) GetCaptchaOverviewApi(c *gin.Context) {
	rep := response2.CCCaptchaOverviewRep{Sites: []response2.CCCaptchaSiteRep{}}
	for _, h := range wafHostService.GetAllHostApi() {
		if h.GLOBAL_HOST == 1 {
			continue
		}
		rep.HostTotal++
		if h.CaptchaJSON == "" {
			continue
		}
		cfg := model.ParseCaptchaConfig(h.CaptchaJSON)
		if strings.TrimSpace(string(cfg.ExcludeURLs)) == "" {
			continue
		}
		rep.Sites = append(rep.Sites, response2.CCCaptchaSiteRep{
			HostCode: h.Code,
			// 带端口：同一域名常有多条记录，只给域名会看起来像三条重复
			HostName:    HostDisplayName(h),
			EngineType:  cfg.EngineType,
			ExcludeURLs: string(cfg.ExcludeURLs),
		})
	}
	response.OkWithDetailed(rep, "获取成功", c)
}

// RecommendThresholdApi 按历史流量推荐阈值。
//
// 结果只是「填进输入框」的建议，保存与否由用户决定；算不出来时如实说明原因，
// 不给一个看起来很准的错数——用户拿它去配封禁，错了是真实访客被挡在外面。
func (w *WafAntiCCRuleApi) RecommendThresholdApi(c *gin.Context) {
	var req request.WafCCThresholdRecommendReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	req.HostCode = strings.TrimSpace(req.HostCode)
	if req.HostCode == "" {
		response.FailWithMessage("请先选择网站", c)
		return
	}
	if req.WindowSec < 0 || req.WindowSec > 86400 {
		response.FailWithMessage("统计周期需在 1-86400 秒之间", c)
		return
	}
	if req.Days < 0 || req.Days > 30 {
		response.FailWithMessage("样本天数需在 1-30 天之间", c)
		return
	}
	if len(req.Conditions) > 64*1024 || len(req.ExcludeExts) > 4096 {
		response.FailWithMessage("参数过长", c)
		return
	}
	response.OkWithDetailed(wafCCThresholdService.RecommendApi(req), "获取成功", c)
}

// GetHitsApi 一条规则的命中看板：触发总数、按动作分布、TOP N 客户端。
//
// 数据来自进程内统计，重启归零——这是运维观察窗口，不是审计账本，
// 需要留痕的信息在攻击日志里。界面上必须写明统计起点，否则「触发 3 次」
// 既可能是刚重启也可能是三个月才 3 次。
func (w *WafAntiCCRuleApi) GetHitsApi(c *gin.Context) {
	var req request.WafCCHitsReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	// 规则必须真实存在且属于当前租户，否则等于把进程内统计做成了一个可枚举的探针
	rule := wafAntiCCRuleService.GetDetailApi(req.RuleId)
	if rule.Id == "" {
		response.FailWithMessage("规则不存在", c)
		return
	}
	top := req.Top
	if top <= 0 || top > ccstats.TopDefault {
		top = ccstats.TopDefault
	}
	board := ccstats.Default.Board(req.RuleId, top)
	response.OkWithDetailed(gin.H{
		"board":      board,
		"rule_name":  rule.RuleName,
		"rule_code":  rule.RuleCode,
		"stat_dim":   rule.StatDim,
		"since":      ccstats.Default.StartedAt(),
		"host_code":  rule.HostCode,
		"action":     rule.Action,
		"window_sec": rule.WindowSec,
		"threshold":  rule.Threshold,
	}, "获取成功", c)
}

// SetEmergencyApi 开关紧急模式（对标 Under Attack Mode）。
func (w *WafAntiCCRuleApi) SetEmergencyApi(c *gin.Context) {
	var req request.WafCCEmergencyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if req.Enable != 0 && req.Enable != 1 {
		response.FailWithMessage("参数不正确", c)
		return
	}
	host, err := wafCCEmergencyService.SetEmergency(req.HostCode, req.Enable, req.DurationMin)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	// 走与「防御状态」同一条通知：紧急模式读的是引擎里的站点快照，不通知的话开关点了不生效
	global.GWAF_CHAN_HOST <- wafHostService.GetDetailByCodeApi(req.HostCode)
	response.OkWithDetailed(gin.H{
		"enable": host.EmergencyMode,
		"until":  host.EmergencyUntil,
	}, "操作成功", c)
}

// GetEmergencyStatusApi 查紧急模式状态。不传站点时返回所有开着的站点——
// 「开着忘了关」是这个功能最现实的风险，界面要能一眼看到。
func (w *WafAntiCCRuleApi) GetEmergencyStatusApi(c *gin.Context) {
	var req request.WafCCEmergencyStatusReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	response.OkWithDetailed(wafCCEmergencyService.EmergencyStatus(req.HostCode), "获取成功", c)
}
