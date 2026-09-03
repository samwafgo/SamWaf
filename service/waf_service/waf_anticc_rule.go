package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

type WafAntiCCRuleService struct{}

var WafAntiCCRuleServiceApp = new(WafAntiCCRuleService)

// maxRulesPerHost 单个网站的规则数量上限。
// 规则在每个请求上按序求值，条数没有上限就等于给热路径加了一段可无限增长的线性开销。
const maxRulesPerHost = 20

// normalizeAndValidate 把请求体规范化成可落库的规则，并逐项过白名单。
// 前端传来的值一律不可信：枚举必须过白名单，值与操作符的搭配必须由后端独立校验。
func normalizeAndValidate(req *request.WafAntiCCRuleAddReq) (*model.AntiCCRule, error) {
	rule := &model.AntiCCRule{
		HostCode:      strings.TrimSpace(req.HostCode),
		RuleName:      strings.TrimSpace(req.RuleName),
		Priority:      req.Priority,
		IsEnable:      req.IsEnable,
		MatchMode:     req.MatchMode,
		MatchExpr:     req.MatchExpr,
		CountPhase:    req.CountPhase,
		CountScope:    req.CountScope,
		ExcludeExts:   req.ExcludeExts,
		StatDim:       req.StatDim,
		StatDimField:  strings.TrimSpace(req.StatDimField),
		Algo:          req.Algo,
		WindowSec:     req.WindowSec,
		Threshold:     req.Threshold,
		Burst:         req.Burst,
		Action:        req.Action,
		ActionSeconds: req.ActionSeconds,
		BanScope:      req.BanScope,
		StopGlobal:    req.StopGlobal,
		Remarks:       req.Remarks,
	}

	if rule.RuleName == "" {
		return nil, errors.New("规则名不能为空")
	}
	// 新建规则的默认值：滑动窗口、排除静态、人机验证、只封本站点。
	// 这些默认值只作用于新建规则，迁移过来的存量配置保持原行为。
	if rule.MatchMode == "" {
		rule.MatchMode = model.CCMatchModeAll
	}
	if rule.CountPhase == "" {
		rule.CountPhase = model.CCCountPhaseRequest
	}
	if rule.CountScope == "" {
		rule.CountScope = model.CCCountScopeDynamic
	}
	if rule.StatDim == "" {
		rule.StatDim = model.CCStatDimIP
	}
	if rule.Algo == "" {
		rule.Algo = model.CCAlgoWindow
	}
	if rule.Action == "" {
		rule.Action = model.CCActionCaptcha
	}
	if rule.BanScope == "" {
		rule.BanScope = model.CCBanScopeHost
	}
	if rule.ActionSeconds <= 0 {
		rule.ActionSeconds = 300
	}
	// 没传这个字段时按新建默认值处理（豁免已验证爬虫）；传了就以传的为准。
	// 迁移过来的存量规则不走这里，保持它们原来的 0。
	if req.BotExempt == nil {
		rule.BotExempt = 1
	} else if *req.BotExempt == 1 {
		rule.BotExempt = 1
	} else {
		rule.BotExempt = 0
	}

	if !model.IsValidCCMatchMode(rule.MatchMode) {
		return nil, errors.New("匹配方式不合法")
	}
	if !model.IsValidCCCountPhase(rule.CountPhase) {
		return nil, errors.New("计数阶段不合法")
	}
	if !model.IsValidCCCountScope(rule.CountScope) {
		return nil, errors.New("统计口径不合法")
	}
	if !model.IsValidCCStatDim(rule.StatDim) {
		return nil, errors.New("统计维度不合法")
	}
	if !model.IsValidCCAlgo(rule.Algo) {
		return nil, errors.New("限流算法不合法")
	}
	if !model.IsValidCCAction(rule.Action) {
		return nil, errors.New("动作不合法")
	}
	if rule.BanScope != model.CCBanScopeHost && rule.BanScope != model.CCBanScopeGlobal {
		return nil, errors.New("封禁作用域不合法")
	}
	if rule.WindowSec <= 0 || rule.WindowSec > 86400 {
		return nil, errors.New("时间窗口需在 1~86400 秒之间")
	}
	if rule.Threshold <= 0 {
		return nil, errors.New("请求次数必须大于 0")
	}
	if rule.Burst < 0 {
		return nil, errors.New("突发容忍不能为负数")
	}

	// 统计维度需要字段名时必须给出，且字段名要过同一套 token 校验
	if model.CCStatDimNeedsField(rule.StatDim) {
		if err := model.ValidateCCFieldKey(rule.StatDimField); err != nil {
			return nil, err
		}
	} else {
		rule.StatDimField = ""
	}

	switch rule.MatchMode {
	case model.CCMatchModeSimple:
		conds, err := model.ValidateCCConditions(req.Conditions)
		if err != nil {
			return nil, err
		}
		b, err := json.Marshal(conds)
		if err != nil {
			return nil, err
		}
		rule.MatchJson = string(b)
		rule.MatchExpr = ""
		// 引用了响应期字段就必须按响应期计数，否则规则永远不会命中
		if model.CCConditionsNeedResponsePhase(conds) {
			rule.CountPhase = model.CCCountPhaseResponse
		}
	case model.CCMatchModeExpr:
		if strings.TrimSpace(rule.MatchExpr) == "" {
			return nil, errors.New("脚本条件不能为空")
		}
		rule.MatchJson = ""
	default:
		rule.MatchJson = ""
		rule.MatchExpr = ""
	}
	return rule, nil
}

func (receiver *WafAntiCCRuleService) AddApi(req request.WafAntiCCRuleAddReq) (*model.AntiCCRule, error) {
	rule, err := normalizeAndValidate(&req)
	if err != nil {
		return nil, err
	}

	var count int64
	global.GWAF_LOCAL_DB.Model(&model.AntiCCRule{}).Where("host_code = ?", rule.HostCode).Count(&count)
	if count >= maxRulesPerHost {
		return nil, errors.New("单个网站的CC规则不能超过 20 条")
	}

	now := customtype.JsonTime(time.Now())
	rule.BaseOrm = baseorm.BaseOrm{
		Id:          uuid.GenUUID(),
		USER_CODE:   global.GWAF_USER_CODE,
		Tenant_ID:   global.GWAF_TENANT_ID,
		CREATE_TIME: now,
		UPDATE_TIME: now,
	}
	rule.RuleCode = AllocCCRuleCode(global.GWAF_LOCAL_DB)
	if err := global.GWAF_LOCAL_DB.Create(rule).Error; err != nil {
		return nil, err
	}
	return rule, nil
}

// AllocCCRuleCode 取一个当前未被占用的规则短码。
// 短码要念给管理员听、也要能一眼在列表里对上，所以必须唯一；
// 重试若干次仍撞车就退回主键，宁可码长一点也不能出现两条规则同码。
func AllocCCRuleCode(db *gorm.DB) string {
	for i := 0; i < 8; i++ {
		code := model.GenCCRuleCode()
		var n int64
		if err := db.Model(&model.AntiCCRule{}).Where("rule_code = ?", code).Count(&n).Error; err != nil {
			return code
		}
		if n == 0 {
			return code
		}
	}
	return "CC-" + uuid.GenUUID()[:6]
}

// ModifyApi 修改规则。返回旧的 host_code：网站被改到别的站点时，
// 新旧两个站点的引擎缓存都要刷新，只通知新站会让旧站一直用着已删除的规则。
func (receiver *WafAntiCCRuleService) ModifyApi(req request.WafAntiCCRuleEditReq) (oldHostCode string, err error) {
	var old model.AntiCCRule
	if err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&old).Error; err != nil {
		return "", err
	}
	rule, err := normalizeAndValidate(&req.WafAntiCCRuleAddReq)
	if err != nil {
		return "", err
	}
	updates := map[string]interface{}{
		"host_code":      rule.HostCode,
		"rule_name":      rule.RuleName,
		"priority":       rule.Priority,
		"is_enable":      rule.IsEnable,
		"match_mode":     rule.MatchMode,
		"match_json":     rule.MatchJson,
		"match_expr":     rule.MatchExpr,
		"count_phase":    rule.CountPhase,
		"count_scope":    rule.CountScope,
		"exclude_exts":   rule.ExcludeExts,
		"stat_dim":       rule.StatDim,
		"stat_dim_field": rule.StatDimField,
		"algo":           rule.Algo,
		"window_sec":     rule.WindowSec,
		"threshold":      rule.Threshold,
		"burst":          rule.Burst,
		"action":         rule.Action,
		"action_seconds": rule.ActionSeconds,
		"ban_scope":      rule.BanScope,
		"stop_global":    rule.StopGlobal,
		"bot_exempt":     rule.BotExempt,
		"remarks":        rule.Remarks,
		"UPDATE_TIME":    customtype.JsonTime(time.Now()),
	}
	if err := global.GWAF_LOCAL_DB.Model(&model.AntiCCRule{}).
		Where("id = ?", req.Id).Updates(updates).Error; err != nil {
		return "", err
	}
	return old.HostCode, nil
}

func (receiver *WafAntiCCRuleService) DelApi(id string) (hostCode string, err error) {
	var rule model.AntiCCRule
	if err := global.GWAF_LOCAL_DB.Where("id = ?", id).First(&rule).Error; err != nil {
		return "", err
	}
	if err := global.GWAF_LOCAL_DB.Where("id = ?", id).Delete(&model.AntiCCRule{}).Error; err != nil {
		return "", err
	}
	return rule.HostCode, nil
}

func (receiver *WafAntiCCRuleService) ToggleApi(req request.WafAntiCCRuleToggleReq) (hostCode string, err error) {
	var rule model.AntiCCRule
	if err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&rule).Error; err != nil {
		return "", err
	}
	enable := 0
	if req.IsEnable == 1 {
		enable = 1
	}
	err = global.GWAF_LOCAL_DB.Model(&model.AntiCCRule{}).Where("id = ?", req.Id).
		Updates(map[string]interface{}{"is_enable": enable, "UPDATE_TIME": customtype.JsonTime(time.Now())}).Error
	return rule.HostCode, err
}

// SortApi 按给定顺序重排优先级。步长留 10，方便之后往中间插规则不用整体重排。
func (receiver *WafAntiCCRuleService) SortApi(req request.WafAntiCCRuleSortReq) error {
	if len(req.Ids) == 0 {
		return errors.New("排序列表不能为空")
	}
	return global.GWAF_LOCAL_DB.Transaction(func(tx *gorm.DB) error {
		// 只在这批规则「原本占用的优先级槽位」之间重排。
		// 列表是分页的，提交上来的可能只是该站点规则的一部分；
		// 按位置从 10 开始重编会把没提交的那些规则挤到后面去，顺序凭空变了。
		var rules []model.AntiCCRule
		if err := tx.Where("host_code = ? and id in ?", req.HostCode, req.Ids).Find(&rules).Error; err != nil {
			return err
		}
		if len(rules) != len(req.Ids) {
			return errors.New("排序列表与该网站的规则不匹配")
		}
		slots := make([]int, 0, len(rules))
		for _, r := range rules {
			slots = append(slots, r.Priority)
		}
		sort.Ints(slots)
		// 存量数据里同一站点的优先级可能重复（默认值都是 100），
		// 槽位不严格递增的话交换就成了空操作，看起来像「点了没反应」
		for i := 1; i < len(slots); i++ {
			if slots[i] <= slots[i-1] {
				slots[i] = slots[i-1] + 1
			}
		}
		for i, id := range req.Ids {
			if err := tx.Model(&model.AntiCCRule{}).
				Where("id = ? and host_code = ?", id, req.HostCode).
				Update("priority", slots[i]).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (receiver *WafAntiCCRuleService) GetDetailApi(id string) model.AntiCCRule {
	var rule model.AntiCCRule
	global.GWAF_LOCAL_DB.Where("id = ?", id).Find(&rule)
	return rule
}

func (receiver *WafAntiCCRuleService) GetListApi(req request.WafAntiCCRuleSearchReq) ([]model.AntiCCRule, int64, error) {
	var list []model.AntiCCRule
	var total int64

	q := global.GWAF_LOCAL_DB.Model(&model.AntiCCRule{})
	// 顺序：限定单站点时按优先级排；跨站点查看时先按站点聚拢，
	// 否则不同站点的规则会按优先级交叉排在一起，看不出各站点自己的执行顺序
	order := "priority asc"
	if strings.TrimSpace(req.HostCode) != "" {
		q = q.Where("host_code = ?", req.HostCode)
	} else {
		if len(req.HostCodes) > 0 {
			q = q.Where("host_code IN ?", req.HostCodes)
		}
		order = "host_code asc, priority asc"
	}
	q.Count(&total)

	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}
	pageIndex := req.PageIndex
	if pageIndex <= 0 {
		pageIndex = 1
	}
	err := q.Order(order).Limit(pageSize).Offset(pageSize * (pageIndex - 1)).Find(&list).Error
	return list, total, err
}

// GetAllByHost 取某网站的全部规则（不分页），供引擎加载与默认模板判断使用。
func (receiver *WafAntiCCRuleService) GetAllByHost(hostCode string) []model.AntiCCRule {
	var list []model.AntiCCRule
	global.GWAF_LOCAL_DB.Where("host_code = ?", hostCode).Order("priority asc").Find(&list)
	return list
}

// CreateDefaultRules 为新建的网站生成一套开箱可用的 CC 规则。
//
// 阈值取自公开可查的行业参考值并按「排除静态资源后」折算：静态资源不计数之后，
// 同样的数字对应的实际压力比整站计数时大得多，直接照搬整站阈值会形同虚设。
// 兜底那条用封禁，前两条用人机验证——误伤成本远低于封 IP。
// 网站已有规则时直接跳过，避免迁移过来的存量配置被覆盖。
func (receiver *WafAntiCCRuleService) CreateDefaultRules(hostCode string) error {
	if strings.TrimSpace(hostCode) == "" {
		return nil
	}
	var count int64
	global.GWAF_LOCAL_DB.Model(&model.AntiCCRule{}).Where("host_code = ?", hostCode).Count(&count)
	if count > 0 {
		return nil
	}

	templates := []model.AntiCCRule{
		{
			RuleName:      "动态接口频次",
			Priority:      50,
			MatchMode:     model.CCMatchModeAll,
			CountScope:    model.CCCountScopeDynamic,
			StatDim:       model.CCStatDimIP,
			WindowSec:     60,
			Threshold:     600,
			Action:        model.CCActionCaptcha,
			ActionSeconds: 300,
			BotExempt:     1,
			Remarks:       "排除静态资源后按IP限频，超限转人机验证",
		},
		{
			RuleName:      "全站兜底",
			Priority:      90,
			MatchMode:     model.CCMatchModeAll,
			CountScope:    model.CCCountScopeAll,
			StatDim:       model.CCStatDimIP,
			WindowSec:     60,
			Threshold:     3000,
			Action:        model.CCActionBan,
			ActionSeconds: 600,
			BanScope:      model.CCBanScopeHost,
			BotExempt:     1,
			Remarks:       "含静态资源的整站兜底阈值，仅封禁本站点",
		},
	}

	now := customtype.JsonTime(time.Now())
	for i := range templates {
		t := templates[i]
		t.HostCode = hostCode
		t.IsEnable = 1
		t.CountPhase = model.CCCountPhaseRequest
		t.Algo = model.CCAlgoWindow
		if t.BanScope == "" {
			t.BanScope = model.CCBanScopeHost
		}
		t.RuleCode = AllocCCRuleCode(global.GWAF_LOCAL_DB)
		t.BaseOrm = baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: now,
			UPDATE_TIME: now,
		}
		if err := global.GWAF_LOCAL_DB.Create(&t).Error; err != nil {
			return err
		}
	}
	return nil
}
