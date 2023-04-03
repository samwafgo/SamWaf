package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"errors"
)

type WafRuleService struct{}

var WafRuleServiceApp = new(WafRuleService)

func (receiver *WafRuleService) AddApi(wafRuleAddReq request.WafRuleAddReq, ruleCode string, chsName string, hostCode string, ruleContent string) error {
	var wafRule = &model.Rules{
		TenantId:        global.GWAF_TENANT_ID,
		HostCode:        hostCode, //网站CODE
		RuleCode:        ruleCode,
		RuleName:        chsName,
		RuleContent:     ruleContent,
		RuleContentJSON: wafRuleAddReq.RuleJson, //TODO 后续考虑是否应该再从结构转一次
		RuleVersionName: "初版",
		RuleVersion:     1,
		UserCode:        global.GWAF_USER_CODE,
		IsPublicRule:    0,
		IsManualRule:    wafRuleAddReq.IsManualRule,
		RuleStatus:      1,
	}
	global.GWAF_LOCAL_DB.Create(wafRule)
	return nil
}

func (receiver *WafRuleService) CheckIsExistApi(ruleName string, ruleCode string) error {
	return global.GWAF_LOCAL_DB.First(&model.Rules{}, "rule_name = ? and rule_code = ?", ruleName, ruleCode).Error
}

func (receiver *WafRuleService) ModifyApi(wafRuleEditReq request.WafRuleEditReq, chsName string, hostCode string, ruleContent string) error {
	var rule model.Rules

	global.GWAF_LOCAL_DB.Where("rule_name = ? and host_code= ?",
		chsName, hostCode).Find(&rule)

	if rule.Id != 0 && rule.RuleCode != wafRuleEditReq.CODE {

		return errors.New("当前规则名称已经存在")
	}

	global.GWAF_LOCAL_DB.Where("rule_code=?", wafRuleEditReq.CODE).Find(&rule)

	ruleMap := map[string]interface{}{
		"HostCode":        hostCode,
		"RuleName":        chsName,
		"RuleContent":     ruleContent,
		"RuleContentJSON": wafRuleEditReq.RuleJson,
		"RuleVersionName": "初版",
		"RuleVersion":     rule.RuleVersion + 1,
		"User_code":       global.GWAF_USER_CODE,
		"IsPublicRule":    0,
		"IsManualRule":    wafRuleEditReq.IsManualRule,
		"RuleStatus":      "1",
		//"UPDATE_TIME": time.Now(),
	}
	err := global.GWAF_LOCAL_DB.Model(model.Rules{}).Where("rule_code=?", wafRuleEditReq.CODE).Updates(ruleMap).Error

	return err
}
func (receiver *WafRuleService) GetDetailApi(wafRuleDetailReq request.WafRuleDetailReq) model.Rules {
	var rules model.Rules
	global.GWAF_LOCAL_DB.Where("RULE_CODE=?", wafRuleDetailReq.CODE).Find(&rules)
	return rules
}
func (receiver *WafRuleService) GetDetailByCodeApi(ruleCode string) model.Rules {
	var webRule model.Rules
	global.GWAF_LOCAL_DB.Where("rule_code=?", ruleCode).Find(&webRule)
	return webRule
}
func (receiver *WafRuleService) GetListApi(wafRuleSearchReq request.WafRuleSearchReq) ([]model.Rules, int64, error) {
	var total int64 = 0
	var rules []model.Rules
	global.GWAF_LOCAL_DB.Where("rule_status= 1").Limit(wafRuleSearchReq.PageSize).Offset(wafRuleSearchReq.PageSize * (wafRuleSearchReq.PageIndex - 1)).Find(&rules)
	global.GWAF_LOCAL_DB.Model(&model.Rules{}).Count(&total)

	return rules, total, nil
}

func (receiver *WafRuleService) GetListByHostCodeApi(wafRuleSearchReq request.WafRuleSearchReq) ([]model.Rules, int64, error) {
	var total int64 = 0
	var rules []model.Rules
	global.GWAF_LOCAL_DB.Where("host_code = ? and rule_status= 1",
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE, wafRuleSearchReq.HostCode).Limit(wafRuleSearchReq.PageSize).Offset(wafRuleSearchReq.PageSize * (wafRuleSearchReq.PageIndex - 1)).Find(&rules)
	global.GWAF_LOCAL_DB.Where("host_code = ? and rule_status= 1",
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE, wafRuleSearchReq.HostCode).Model(&model.Rules{}).Count(&total)

	return rules, total, nil
}

func (receiver *WafRuleService) DelRuleApi(req request.WafRuleDelReq) error {
	var rule model.Rules
	err := global.GWAF_LOCAL_DB.Where("rule_code = ?", req.CODE).First(&rule).Error
	if err != nil {

		return errors.New("要删除的规则信息未找到")
	}
	ruleMap := map[string]interface{}{
		"RuleStatus":  "999",
		"RuleVersion": 999999,
	}
	err = global.GWAF_LOCAL_DB.Model(model.Rules{}).Where("rule_code = ?", req.CODE).Updates(ruleMap).Error
	if err != nil {

		return errors.New("删除失败")
	}
	return nil
}
