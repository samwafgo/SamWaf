package model

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type RuleTool struct {
}

func IfCompare(condition bool, trueVal, falseVal interface{}) interface{} {
	if condition {
		return trueVal
	}
	return falseVal
}

type RuleInfo struct {
	IsManualRule     string             `json:"is_manual_rule"`
	RuleContent      string             `json:"rule_content"` //规则内容
	RuleBase         RuleBase           `json:"rule_base"`
	RuleCondition    RuleCondition      `json:"rule_condition"`
	RuleDoAssignment []RuleDoAssignment `json:"rule_do_assignment"`
	RuleDoMethod     []RuleDoMethod     `json:"rule_do_method"`
}
type RuleBase struct {
	Salience       int    `json:"salience"`
	RuleName       string `json:"rule_name"`
	RuleDomainCode string `json:"rule_domain_code"`
}
type RelationDetail struct {
	FactName  string `json:"fact_name"`
	Attr      string `json:"attr"`
	AttrType  string `json:"attr_type"`
	AttrJudge string `json:"attr_judge"`
	AttrVal   string `json:"attr_val"`
	AttrVal2  string `json:"attr_val2"` //TODO 暂时这么是为了给函数返回值进行判断的
}
type RuleCondition struct {
	RelationDetail []RelationDetail `json:"relation_detail"`
	RelationSymbol string           `json:"relation_symbol"`
}
type RuleDoAssignment struct {
	FactName string `json:"fact_name"`
	Attr     string `json:"attr"`
	AttrType string `json:"attr_type"`
	AttrVal  string `json:"attr_val"`
}
type Parms struct {
	AttrType string `json:"attr_type"`
	AttrVal  string `json:"attr_val"`
}
type RuleDoMethod struct {
	FactName   string  `json:"fact_name"`
	MethodName string  `json:"method_name"`
	Parms      []Parms `json:"parms"`
}

// json字符串转规则对象
func (receiver *RuleTool) LoadRule(jsonstr string) (RuleInfo, error) {
	var ruleInfo RuleInfo
	err := json.Unmarshal([]byte(jsonstr), &ruleInfo)
	if err != nil {
		fmt.Printf("unmarshal err=%v\n", err)
	}
	return ruleInfo, err
}

/*//将格式化的吐给前端
func (receiver *RuleTool) GenRuleToFront(rule RuleInfo) {

}*/
//生成实际可使用的规则字符串
func (receiver *RuleTool) GenRuleInfo(rule RuleInfo, remark string) string {

	var conditionTpl = ""
	for _, condition := range rule.RuleCondition.RelationDetail {

		if conditionTpl != "" {
			if strings.HasPrefix(condition.AttrJudge, "system.") {
				conditionTpl = conditionTpl + fmt.Sprintf(" %s %s.%s.%s(%s) == %s",
					rule.RuleCondition.RelationSymbol, condition.FactName, condition.Attr, strings.Replace(condition.AttrJudge, "system.", "", 1),
					IfCompare(condition.AttrType == "string", "\""+condition.AttrVal+"\"", condition.AttrVal), condition.AttrVal2)
			} else {
				conditionTpl = conditionTpl + fmt.Sprintf(" %s %s.%s %s %s",
					rule.RuleCondition.RelationSymbol, condition.FactName, condition.Attr, condition.AttrJudge,
					IfCompare(condition.AttrType == "string", "\""+condition.AttrVal+"\"", condition.AttrVal))
			}
		} else {
			if strings.HasPrefix(condition.AttrJudge, "system.") {
				conditionTpl = conditionTpl + fmt.Sprintf("%s.%s.%s(%s) == %s",
					condition.FactName, condition.Attr, strings.Replace(condition.AttrJudge, "system.", "", 1),
					IfCompare(condition.AttrType == "string", "\""+condition.AttrVal+"\"", condition.AttrVal), condition.AttrVal2)
			} else {
				conditionTpl = conditionTpl + fmt.Sprintf("%s.%s %s %s",
					condition.FactName, condition.Attr, condition.AttrJudge,
					IfCompare(condition.AttrType == "string", "\""+condition.AttrVal+"\"", condition.AttrVal))
			}

		}
	}
	var dev = map[string]string{
		"rule_name":      rule.RuleBase.RuleName,
		"rule_remark":    remark,
		"rule_salience":  strconv.Itoa(rule.RuleBase.Salience),
		"rule_condition": conditionTpl,
	}

	var ruleTpl = `
rule R${rule_name} "${rule_remark}" salience ${rule_salience} {
    when 
        ${rule_condition}
    then 
		Retract("R${rule_name}");
} `
	s := os.Expand(ruleTpl, func(k string) string { return dev[k] })
	return s
}
