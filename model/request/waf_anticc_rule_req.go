package request

import (
	"SamWaf/model"
	"SamWaf/model/common/request"
)

// WafAntiCCRuleAddReq 新增CC规则
type WafAntiCCRuleAddReq struct {
	HostCode      string                 `json:"host_code" binding:"required"`
	RuleName      string                 `json:"rule_name" binding:"required"`
	Priority      int                    `json:"priority"`
	IsEnable      int                    `json:"is_enable"`
	MatchMode     string                 `json:"match_mode"`
	Conditions    []model.MatchCondition `json:"conditions"`
	MatchExpr     string                 `json:"match_expr"`
	CountPhase    string                 `json:"count_phase"`
	CountScope    string                 `json:"count_scope"`
	ExcludeExts   string                 `json:"exclude_exts"`
	StatDim       string                 `json:"stat_dim"`
	StatDimField  string                 `json:"stat_dim_field"`
	Algo          string                 `json:"algo"`
	WindowSec     int                    `json:"window_sec" binding:"required"`
	Threshold     int                    `json:"threshold" binding:"required"`
	Burst         int                    `json:"burst"`
	Action        string                 `json:"action"`
	ActionSeconds int                    `json:"action_seconds"`
	BanScope      string                 `json:"ban_scope"`
	StopGlobal    int                    `json:"stop_global"`
	// BotExempt 用指针：0 与「没传」必须分得开，否则新建时的默认开启会把用户显式关闭的意图吃掉
	BotExempt *int   `json:"bot_exempt"`
	Remarks   string `json:"remarks"`
}

// WafAntiCCRuleEditReq 编辑CC规则
type WafAntiCCRuleEditReq struct {
	Id string `json:"id" binding:"required"`
	WafAntiCCRuleAddReq
}

type WafAntiCCRuleSearchReq struct {
	HostCode string `json:"host_code"`
	// HostCodes 供「全部网站 + 指定分组」的查看方式使用：不限定单个站点，
	// 但把范围收敛到该分组下的站点。HostCode 非空时以 HostCode 为准。
	HostCodes []string `json:"host_codes"`
	request.PageInfo
}

type WafAntiCCRuleDelReq struct {
	Id string `json:"id" form:"id"`
}

type WafAntiCCRuleDetailReq struct {
	Id string `json:"id" form:"id"`
}

// WafAntiCCRuleSortReq 批量调整优先级
type WafAntiCCRuleSortReq struct {
	HostCode string   `json:"host_code" binding:"required"`
	Ids      []string `json:"ids" binding:"required"` //按目标顺序排列的规则ID
}

// WafAntiCCRuleToggleReq 启用/停用
type WafAntiCCRuleToggleReq struct {
	Id       string `json:"id" binding:"required"`
	IsEnable int    `json:"is_enable"`
}

// WafCCThresholdRecommendReq 按历史流量推荐阈值。
// 字段与规则表单一一对应：圈样本用的口径必须和这条规则运行时的口径一致，
// 否则算出来的分布与实际计数对不上。
type WafCCThresholdRecommendReq struct {
	HostCode     string `json:"host_code" binding:"required"`
	WindowSec    int    `json:"window_sec"`
	CountScope   string `json:"count_scope"`
	StatDim      string `json:"stat_dim"`
	StatDimField string `json:"stat_dim_field"`
	ExcludeExts  string `json:"exclude_exts"`
	MatchMode    string `json:"match_mode"`
	Conditions   string `json:"conditions"` // 与规则表单同一份条件 JSON
	Days         int    `json:"days"`
}

// WafCCHitsReq 查看一条规则的命中看板
type WafCCHitsReq struct {
	RuleId string `json:"rule_id" form:"rule_id" binding:"required"`
	Top    int    `json:"top" form:"top"`
}

// WafCCEmergencyReq 紧急模式开关。
//
// DurationMin 是自动关闭前的分钟数，0=手动关闭前一直开着。
// 默认给到期时间：这个开关会让全部访客多走一道人机验证，忘了关的代价由真实用户承担。
type WafCCEmergencyReq struct {
	HostCode    string `json:"host_code" binding:"required"`
	Enable      int    `json:"enable"`
	DurationMin int    `json:"duration_min"`
}

// WafCCEmergencyStatusReq 查询紧急模式状态。HostCode 为空时返回全部站点。
type WafCCEmergencyStatusReq struct {
	HostCode string `json:"host_code" form:"host_code"`
}
