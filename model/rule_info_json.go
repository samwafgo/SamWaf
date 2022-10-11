package model

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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
	RuleBase            RuleBase            `json:"rule_base"`
	RuleConditionDetail RuleConditionDetail `json:"rule_condition_detail"`
	RuleDoAssignment    []RuleDoAssignment  `json:"rule_do_assignment"`
	RuleDoMethod        []RuleDoMethod      `json:"rule_do_method"`
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
}
type RuleConditionDetail struct {
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
	for _, condition := range rule.RuleConditionDetail.RelationDetail {
		if conditionTpl != "" {
			conditionTpl = conditionTpl + fmt.Sprintf(" %s %s.%s %s %s",
				rule.RuleConditionDetail.RelationSymbol, condition.FactName, condition.Attr, condition.AttrJudge,
				IfCompare(condition.AttrType == "string", "\""+condition.AttrVal+"\"", condition.AttrVal))
		} else {
			conditionTpl = conditionTpl + fmt.Sprintf("%s.%s %s %s",
				condition.FactName, condition.Attr, condition.AttrJudge, IfCompare(condition.AttrType == "string", "\""+condition.AttrVal+"\"", condition.AttrVal))
		}
	}
	var do_assignmentTpl = ""
	for _, do_assignment := range rule.RuleDoAssignment {
		do_assignmentTpl = do_assignmentTpl +
			fmt.Sprintf("%s.%s = %s;\n",
				do_assignment.FactName, do_assignment.Attr,
				IfCompare(do_assignment.AttrType == "string", "\""+do_assignment.AttrVal+"\"", do_assignment.AttrVal))

	}
	var do_methodTpl = ""
	for _, do_method := range rule.RuleDoMethod {
		do_methodTpl = do_methodTpl +
			fmt.Sprintf("%s.%s ",
				do_method.FactName, do_method.MethodName)
		var parm_str = ""
		for _, do_method_parms := range do_method.Parms {
			if parm_str != "" {
				parm_str = parm_str +
					fmt.Sprintf(",%s",
						IfCompare(do_method_parms.AttrType == "string",
							"\""+do_method_parms.AttrVal+"\"", do_method_parms.AttrVal))
			} else {

				parm_str = parm_str +
					fmt.Sprintf("%s",
						IfCompare(do_method_parms.AttrType == "string",
							"\""+do_method_parms.AttrVal+"\"", do_method_parms.AttrVal))
			}
		}
		if parm_str != "" {
			do_methodTpl = do_methodTpl + "(" + parm_str + ")" + ";\n"
		} else {
			do_methodTpl = do_methodTpl + "()" + ";\n"
		}

	}
	var dev = map[string]string{
		"rule_name":      rule.RuleBase.RuleName,
		"rule_remark":    remark,
		"rule_salience":  strconv.Itoa(rule.RuleBase.Salience),
		"rule_condition": conditionTpl,
		"rule_action":    do_assignmentTpl + do_methodTpl,
	}

	var rule_tpl = `
rule R${rule_name} "${rule_remark}" salience ${rule_salience} {
    when 
        ${rule_condition}
    then
        ${rule_action}
		Retract("${rule_name}");
} `
	s := os.Expand(rule_tpl, func(k string) string { return dev[k] })
	return s
}
