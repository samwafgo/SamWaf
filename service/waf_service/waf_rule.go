package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/utils/zlog"
	"errors"
	uuid "github.com/satori/go.uuid"
	"time"
)

type WafRuleService struct{}

var WafRuleServiceApp = new(WafRuleService)

func (receiver *WafRuleService) AddApi(wafRuleAddReq request.WafRuleAddReq, ruleCode string, chsName string, hostCode string, ruleContent string) error {

	var wafRule = &model.Rules{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode:        hostCode, //网站CODE
		RuleCode:        ruleCode,
		RuleName:        chsName,
		RuleContent:     ruleContent,
		RuleContentJSON: wafRuleAddReq.RuleJson, //TODO 后续考虑是否应该再从结构转一次
		RuleVersionName: "初版",
		RuleVersion:     1,
		IsPublicRule:    0,
		IsManualRule:    wafRuleAddReq.IsManualRule,
		RuleStatus:      1,
	}
	global.GWAF_LOCAL_DB.Create(wafRule)
	return nil
}

/*
*

	false表明 不存在
*/
func (receiver *WafRuleService) CheckIsExistApi(ruleName string, hostCode string) int64 {
	var count int64 = 0
	err := global.GWAF_LOCAL_DB.Model(&model.Rules{}).Where("rule_name = ? and host_code = ? and rule_status<> 999", ruleName, hostCode).Count(&count).Error
	if err != nil {
		zlog.Error("检查是否存在错误", err)
	}
	return count
}

func (receiver *WafRuleService) ModifyApi(wafRuleEditReq request.WafRuleEditReq, chsName string, hostCode string, ruleContent string) error {
	var rule model.Rules

	global.GWAF_LOCAL_DB.Where("rule_name = ? and host_code= ?",
		chsName, hostCode).Find(&rule)

	if rule.Id != "" && rule.RuleCode != wafRuleEditReq.CODE {

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
		"UPDATE_TIME":     customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.Rules{}).Where("rule_code=?", wafRuleEditReq.CODE).Updates(ruleMap).Error

	return err
}
func (receiver *WafRuleService) GetDetailApi(wafRuleDetailReq request.WafRuleDetailReq) model.Rules {
	var rules model.Rules
	global.GWAF_LOCAL_DB.Where("RULE_CODE=?  and rule_status<> 999", wafRuleDetailReq.CODE).Find(&rules)
	return rules
}
func (receiver *WafRuleService) GetDetailByCodeApi(ruleCode string) model.Rules {
	var webRule model.Rules
	global.GWAF_LOCAL_DB.Where("rule_code=?  and rule_status<> 999 ", ruleCode).Find(&webRule)
	return webRule
}
func (receiver *WafRuleService) GetListApi(wafRuleSearchReq request.WafRuleSearchReq) ([]model.Rules, int64, error) {
	var total int64 = 0
	var rules []model.Rules
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = "rule_status=? "
	if len(wafRuleSearchReq.HostCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " host_code=? "
	}
	if len(wafRuleSearchReq.RuleName) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " rule_name=? "
	}
	//where字段赋值
	whereValues = append(whereValues, 1)
	if len(wafRuleSearchReq.HostCode) > 0 {
		whereValues = append(whereValues, wafRuleSearchReq.HostCode)
	}
	if len(wafRuleSearchReq.RuleName) > 0 {
		whereValues = append(whereValues, wafRuleSearchReq.RuleName)
	}

	global.GWAF_LOCAL_DB.Model(&model.Rules{}).Where(whereField, whereValues...).Limit(wafRuleSearchReq.PageSize).Offset(wafRuleSearchReq.PageSize * (wafRuleSearchReq.PageIndex - 1)).Find(&rules)
	global.GWAF_LOCAL_DB.Model(&model.Rules{}).Where(whereField, whereValues...).Count(&total)

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
