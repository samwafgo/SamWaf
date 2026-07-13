package model

import (
	"fmt"
	"regexp"
	"strings"
)

// 规则文本是"模板 + 用户可控内容"拼出来的，而且内容不一定来自管理员本人：
// 从攻击日志一键新建规则时，拼进去的是攻击者构造的 URL / UA / Header 原文。
// 引入规则动作(RF.Deny/RF.Allow)之后，一次注入就足以把一条拦截规则改写成放行规则，
// 所以这里对所有拼进 GRL 的内容做严格处理：
//   - 值（字符串字面量）：转义
//   - 结构位（字段名、运算符、关系符、类型、优先级）：白名单，不合法直接拒绝

// EscapeGrlString 把字符串安全地转义成 GRL 双引号字面量的内容
// 参照 grule 的词法定义 grulev3.g4:
//
//	DQUOTA_STRING : '"' ( '\\'. | '""' | ~('"'|'\\') )* '"'
//
// 反斜杠和双引号需要转义；换行/回车等控制字符直接剔除（换行可以截断规则块，是逃逸的主要手段）
func EscapeGrlString(s string) string {
	var sb strings.Builder
	sb.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\':
			sb.WriteString(`\\`)
		case '"':
			sb.WriteString(`\"`)
		case '\r', '\n', '\t':
			// 结构性空白，直接丢弃
		default:
			// 其余控制字符一律丢弃
			if r < 0x20 || r == 0x7f {
				continue
			}
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// 允许在规则条件里使用的事实字段（与前端下拉保持一致，服务端独立校验，不信任前端传上来的值）
var ruleAttrSimpleWhiteList = map[string]bool{
	"HOST":        true,
	"URL":         true,
	"REFERER":     true,
	"USER_AGENT":  true,
	"METHOD":      true,
	"COOKIES":     true,
	"BODY":        true,
	"PORT":        true,
	"SRC_IP":      true,
	"COUNTRY":     true,
	"PROVINCE":    true,
	"CITY":        true,
	"IsSafeBot()": true,
}

// 方法型字段：GetHeaderValue("xxx") / GetIPFailureCount(5)
var (
	ruleAttrHeaderRegex    = regexp.MustCompile(`^GetHeaderValue\("[A-Za-z0-9_\-]{1,64}"\)$`)
	ruleAttrFailCountRegex = regexp.MustCompile(`^GetIPFailureCount\(\d{1,5}\)$`)
	ruleNumberRegex        = regexp.MustCompile(`^-?\d+(\.\d+)?$`)
	ruleNameRegex          = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)
)

// 允许的判断运算符
var ruleJudgeWhiteList = map[string]bool{
	"==": true, "!=": true, ">": true, "<": true, ">=": true, "<=": true,
	"system.Contains": true, "system.HasPrefix": true, "system.HasSuffix": true,
}

// 允许的条件关系符
var ruleRelationSymbolWhiteList = map[string]bool{
	"&&": true, "||": true,
}

// 允许的值类型
var ruleAttrTypeWhiteList = map[string]bool{
	"string": true, "int": true, "float": true, "bool": true,
}

// ValidateRuleFactName 校验事实对象名，界面编排的规则只允许用 MF（当前请求）
func ValidateRuleFactName(factName string) error {
	if factName == "MF" {
		return nil
	}
	return fmt.Errorf("不支持的事实对象: %s", factName)
}

// ValidateRuleAttr 校验事实字段名
func ValidateRuleAttr(attr string) error {
	if ruleAttrSimpleWhiteList[attr] {
		return nil
	}
	if ruleAttrHeaderRegex.MatchString(attr) || ruleAttrFailCountRegex.MatchString(attr) {
		return nil
	}
	return fmt.Errorf("不支持的规则字段: %s", attr)
}

// ValidateRuleJudge 校验判断运算符
func ValidateRuleJudge(judge string) error {
	if ruleJudgeWhiteList[judge] {
		return nil
	}
	return fmt.Errorf("不支持的规则运算符: %s", judge)
}

// ValidateRuleRelationSymbol 校验条件关系符（只有一个条件时可以为空）
func ValidateRuleRelationSymbol(symbol string) error {
	if symbol == "" || ruleRelationSymbolWhiteList[symbol] {
		return nil
	}
	return fmt.Errorf("不支持的条件关系符: %s", symbol)
}

// ValidateRuleAttrType 校验值类型
func ValidateRuleAttrType(attrType string) error {
	if ruleAttrTypeWhiteList[attrType] {
		return nil
	}
	return fmt.Errorf("不支持的值类型: %s", attrType)
}

// ValidateRuleAttrVal 校验条件值
// 字符串类型会被引号包裹+转义，怎么写都逃不出去；
// 但非字符串类型是裸拼进表达式的，必须限定为纯数字/布尔，否则
// attr_type=int + attr_val=`1 then RF.AllowAll()` 就能直接逃逸出字符串上下文。
func ValidateRuleAttrVal(attrType, attrVal string) error {
	if attrType == "string" {
		return nil
	}
	v := strings.TrimSpace(attrVal)
	switch attrType {
	case "int", "float":
		if !ruleNumberRegex.MatchString(v) {
			return fmt.Errorf("值类型为 %s 时，值必须是数字: %s", attrType, attrVal)
		}
	case "bool":
		if v != "true" && v != "false" {
			return fmt.Errorf("值类型为 bool 时，值只能是 true 或 false: %s", attrVal)
		}
	}
	return nil
}

// ValidateRuleBoolVal 校验函数结果判断值（只能是 true / false）
func ValidateRuleBoolVal(val string) error {
	if val == "true" || val == "false" {
		return nil
	}
	return fmt.Errorf("函数结果判断值只能是 true 或 false: %s", val)
}

// ValidateRuleName 校验规则名（会被拼进 rule R${rule_name}）
func ValidateRuleName(name string) error {
	if ruleNameRegex.MatchString(name) {
		return nil
	}
	return fmt.Errorf("规则标识不合法，只能是字母和数字: %s", name)
}
