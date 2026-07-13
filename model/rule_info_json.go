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
	RuleContent      string             `json:"rule_content"`      //规则内容
	RuleAction       string             `json:"rule_action"`       //命中之后的动作 deny(拦截,默认) allow(放行) log(仅记录)
	RuleActionSkips  []string           `json:"rule_action_skips"` //放行时要跳过的检测模块 如 ["CC","AI"]，["ALL"]表示全部
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
// genRuleActionStmt 根据界面选择的动作生成 then 块里的动作语句
// 没有选择动作(老数据)时按拦截处理，与老规则行为一致
func genRuleActionStmt(rule RuleInfo) string {
	switch rule.RuleAction {
	case "log":
		return "RF.Log();"
	case "allow":
		//跳过的模块名只能来自白名单枚举，非法值直接丢弃，绝不把用户传来的字符串原样拼进规则
		skips := make([]string, 0, len(rule.RuleActionSkips))
		skipAll := false
		for _, m := range rule.RuleActionSkips {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m == "ALL" {
				skipAll = true
				break
			}
			if ruleSkipModuleWhiteList[m] {
				skips = append(skips, m)
			}
		}
		if skipAll {
			return "RF.AllowAll();"
		}
		if len(skips) == 0 {
			return "RF.Allow();"
		}
		quoted := make([]string, 0, len(skips))
		for _, m := range skips {
			quoted = append(quoted, "\""+m+"\"")
		}
		return fmt.Sprintf("RF.Allow(%s);", strings.Join(quoted, ", "))
	default:
		return "RF.Deny();"
	}
}

// ruleSkipModuleWhiteList 与 utils.RuleSkipModules 保持一致
// （model 包不能引 utils，会形成循环依赖，所以这里单独列一份，加规则模块时两边都要改）
var ruleSkipModuleWhiteList = map[string]bool{
	"BOT": true, "SQLI": true, "XSS": true, "SCAN": true, "RCE": true,
	"DIR": true, "CC": true, "AI": true, "SENSITIVE": true, "OWASP": true,
	"ANTILEECH": true, "CSRF": true, "UPLOAD": true, "CAPTCHA": true,
}

// 生成实际可使用的规则字符串
// 所有拼进 GRL 的内容都经过转义或白名单校验，防止用户/攻击者通过条件值注入额外的规则语句
func (receiver *RuleTool) GenRuleInfo(rule RuleInfo, remark string) (string, error) {

	if err := ValidateRuleName(rule.RuleBase.RuleName); err != nil {
		return "", err
	}
	if err := ValidateRuleRelationSymbol(rule.RuleCondition.RelationSymbol); err != nil {
		return "", err
	}
	//优先级钳制，防止拼出非法的 salience
	salience := rule.RuleBase.Salience
	if salience < 0 {
		salience = 0
	}
	if salience > 10000 {
		salience = 10000
	}

	var conditionTpl = ""
	for _, condition := range rule.RuleCondition.RelationDetail {
		if err := ValidateRuleFactName(condition.FactName); err != nil {
			return "", err
		}
		if err := ValidateRuleAttr(condition.Attr); err != nil {
			return "", err
		}
		if err := ValidateRuleJudge(condition.AttrJudge); err != nil {
			return "", err
		}
		if err := ValidateRuleAttrType(condition.AttrType); err != nil {
			return "", err
		}
		if err := ValidateRuleAttrVal(condition.AttrType, condition.AttrVal); err != nil {
			return "", err
		}

		//字符串值转义后再包引号；非字符串值上面已校验为纯数字/布尔，可以裸拼
		attrVal := condition.AttrVal
		if condition.AttrType == "string" {
			attrVal = "\"" + EscapeGrlString(condition.AttrVal) + "\""
		} else {
			attrVal = strings.TrimSpace(condition.AttrVal)
		}

		var expr string
		if strings.HasPrefix(condition.AttrJudge, "system.") {
			if err := ValidateRuleBoolVal(condition.AttrVal2); err != nil {
				return "", err
			}
			expr = fmt.Sprintf("%s.%s.%s(%s) == %s",
				condition.FactName, condition.Attr,
				strings.Replace(condition.AttrJudge, "system.", "", 1),
				attrVal, condition.AttrVal2)
		} else {
			expr = fmt.Sprintf("%s.%s %s %s",
				condition.FactName, condition.Attr, condition.AttrJudge, attrVal)
		}

		if conditionTpl != "" {
			conditionTpl = conditionTpl + " " + rule.RuleCondition.RelationSymbol + " " + expr
		} else {
			conditionTpl = expr
		}
	}

	var dev = map[string]string{
		"rule_name":        rule.RuleBase.RuleName,
		"rule_remark":      EscapeGrlString(remark),
		"rule_salience":    strconv.Itoa(salience),
		"rule_condition":   conditionTpl,
		"rule_action_stmt": genRuleActionStmt(rule),
	}

	var ruleTpl = `
rule R${rule_name} "${rule_remark}" salience ${rule_salience} {
    when
        ${rule_condition}
    then
		${rule_action_stmt}
} `
	s := os.Expand(ruleTpl, func(k string) string { return dev[k] })
	return s, nil
}
