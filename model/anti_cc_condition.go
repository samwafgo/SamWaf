package model

import (
	"encoding/json"
	"errors"
	"strings"
)

// MatchCondition 是一条结构化匹配条件。条件之间按 AND 组合。
//
// Key 只在 Field 需要指定字段名时使用（请求头 / Cookie / 查询参数 / JSON 请求体字段）——
// 光有「目标 + 判断 + 值」表达不了「取哪个头」。
type MatchCondition struct {
	Field string    `json:"field"`         //匹配目标，见 CCField* 常量
	Key   string    `json:"key,omitempty"` //Field 需要字段名时的名字，校验见 ValidateCCFieldKey
	Op    string    `json:"op"`            //操作符，见 CCOp* 常量
	Value CCCondVal `json:"value,omitempty"`
}

// CCCondVal 兼容前端把值传成字符串或数组两种形态，内部统一成字符串切片。
// 单值操作符取第 0 个，between 取前两个，in/not_in 取全部，存在性操作符忽略。
type CCCondVal []string

func (v *CCCondVal) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*v = nil
		return nil
	}
	if trimmed[0] == '[' {
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*v = arr
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	*v = []string{single}
	return nil
}

func (v CCCondVal) MarshalJSON() ([]byte, error) {
	if v == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]string(v))
}

// —— 匹配目标 ——
//
// A 组：请求期即可取得，CC 检测点在转发前，直接从 *http.Request 上读。
// B 组：只有等后端响应回来才知道，必须把规则的 CountPhase 设为 response。
const (
	// A 组：请求期
	CCFieldURI        = "uri"         //URL 路径
	CCFieldQueryStr   = "query_str"   //原始查询串
	CCFieldMethod     = "method"      //请求方法
	CCFieldHost       = "host"        //域名
	CCFieldExt        = "ext"         //URL 路径的文件扩展名
	CCFieldScheme     = "scheme"      //协议
	CCFieldUserAgent  = "user_agent"  //User-Agent
	CCFieldReferer    = "referer"     //Referer
	CCFieldHeader     = "header"      //任意请求头，需 Key
	CCFieldCookie     = "cookie"      //任意 Cookie，需 Key
	CCFieldQueryParam = "query"       //任意查询参数，需 Key
	CCFieldBodyField  = "body"        //JSON 请求体字段，需 Key
	CCFieldClientIP   = "client_ip"   //客户端 IP
	CCFieldCountry    = "country"     //国家/地区
	CCFieldProvince   = "province"    //省
	CCFieldCity       = "city"        //市
	CCFieldIsBot      = "is_bot"      //是否已识别为机器人
	CCFieldBodyLength = "body_length" //请求体大小

	// B 组：响应期
	CCFieldRespContentType = "resp_content_type" //响应 Content-Type
	CCFieldStatusCode      = "status_code"       //响应状态码
	CCFieldRespLength      = "resp_length"       //响应大小
	CCFieldUpstreamCost    = "upstream_cost"     //后端处理耗时(毫秒)
)

// —— 操作符 ——
const (
	CCOpEq          = "eq"
	CCOpNe          = "ne"
	CCOpContains    = "contains"
	CCOpNotContains = "not_contains"
	CCOpPrefix      = "prefix"
	CCOpSuffix      = "suffix"
	CCOpRegex       = "regex"
	CCOpIn          = "in"
	CCOpNotIn       = "not_in"
	CCOpGt          = "gt"
	CCOpLt          = "lt"
	CCOpBetween     = "between"
	CCOpExists      = "exists"
	CCOpNotExists   = "not_exists"
)

// ccFieldSpec 描述一个匹配目标的性质。
type ccFieldSpec struct {
	NeedKey    bool // 是否必须指定字段名
	Numeric    bool // 是否为数值型（决定能否用 gt/lt/between）
	RespPhase  bool // 是否只有响应期才能取到
	Multivalue bool // 是否可能有多个值（同名头/同名参数）
}

var ccFieldSpecs = map[string]ccFieldSpec{
	CCFieldURI:        {},
	CCFieldQueryStr:   {},
	CCFieldMethod:     {},
	CCFieldHost:       {},
	CCFieldExt:        {},
	CCFieldScheme:     {},
	CCFieldUserAgent:  {},
	CCFieldReferer:    {},
	CCFieldHeader:     {NeedKey: true, Multivalue: true},
	CCFieldCookie:     {NeedKey: true},
	CCFieldQueryParam: {NeedKey: true, Multivalue: true},
	CCFieldBodyField:  {NeedKey: true, Multivalue: true},
	CCFieldClientIP:   {},
	CCFieldCountry:    {},
	CCFieldProvince:   {},
	CCFieldCity:       {},
	CCFieldIsBot:      {Numeric: true},
	CCFieldBodyLength: {Numeric: true},

	CCFieldRespContentType: {RespPhase: true},
	CCFieldStatusCode:      {Numeric: true, RespPhase: true},
	CCFieldRespLength:      {Numeric: true, RespPhase: true},
	CCFieldUpstreamCost:    {Numeric: true, RespPhase: true},
}

// ccOpArity 操作符需要几个值：0=不需要 1=一个 2=两个 -1=任意多个。
// 这张表同时是界面「值控件形态」的契约：0 不显示输入框，-1 用多选，2 用两个框。
var ccOpArity = map[string]int{
	CCOpEq: 1, CCOpNe: 1, CCOpContains: 1, CCOpNotContains: 1,
	CCOpPrefix: 1, CCOpSuffix: 1, CCOpRegex: 1, CCOpGt: 1, CCOpLt: 1,
	CCOpIn: -1, CCOpNotIn: -1,
	CCOpBetween:   2,
	CCOpExists:    0,
	CCOpNotExists: 0,
}

// ccNumericOps 只能用于数值型目标的操作符。
var ccNumericOps = map[string]bool{CCOpGt: true, CCOpLt: true, CCOpBetween: true}

func IsValidCCField(field string) bool {
	_, ok := ccFieldSpecs[field]
	return ok
}

func IsValidCCOp(op string) bool {
	_, ok := ccOpArity[op]
	return ok
}

// CCFieldNeedsKey 该匹配目标是否必须指定字段名。
func CCFieldNeedsKey(field string) bool { return ccFieldSpecs[field].NeedKey }

// CCFieldIsResponsePhase 该匹配目标是否只有响应期才能取到。
func CCFieldIsResponsePhase(field string) bool { return ccFieldSpecs[field].RespPhase }

// CCOpValueArity 该操作符需要的值个数（-1 表示任意多个）。
func CCOpValueArity(op string) int { return ccOpArity[op] }

// ccFieldKeyMaxLen 与「真实IP来源」的头名限制保持一致。
const ccFieldKeyMaxLen = 64

// ValidateCCFieldKey 校验字段名。
//
// 只允许 HTTP token 里的安全字符并限长：字段名会被拼进计数器键、运行日志与管理端界面，
// 放行换行或冒号会让这些下游拼接出畸形内容。规则与 api 层「真实IP来源」的头名校验一致。
func ValidateCCFieldKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("字段名不能为空")
	}
	if len(key) > ccFieldKeyMaxLen {
		return errors.New("字段名长度不能超过 64")
	}
	for _, ch := range key {
		if !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') &&
			!(ch >= '0' && ch <= '9') && ch != '-' && ch != '_' {
			return errors.New("字段名只能包含字母、数字、- 和 _")
		}
	}
	return nil
}

// ccRegexMaxLen 正则长度上限。
// Go 的 regexp 是 RE2，不存在灾难性回溯，限长是为了控制编译开销与界面可读性。
const ccRegexMaxLen = 512

// Validate 校验单条条件的自洽性。返回的错误直接面向用户。
func (c *MatchCondition) Validate() error {
	c.Field = strings.TrimSpace(c.Field)
	c.Op = strings.TrimSpace(c.Op)
	c.Key = strings.TrimSpace(c.Key)

	spec, ok := ccFieldSpecs[c.Field]
	if !ok {
		return errors.New("匹配目标不合法: " + c.Field)
	}
	if !IsValidCCOp(c.Op) {
		return errors.New("判断方式不合法: " + c.Op)
	}

	if spec.NeedKey {
		if err := ValidateCCFieldKey(c.Key); err != nil {
			return err
		}
	} else {
		// 不需要字段名的目标不接受多余入参，避免界面残留值被存进库
		c.Key = ""
	}

	if ccNumericOps[c.Op] && !spec.Numeric {
		return errors.New("该匹配目标不支持大小比较")
	}

	// 值的个数必须与操作符匹配。这层不能只靠前端：前端只是控件形态，后端才是防线。
	switch arity := ccOpArity[c.Op]; {
	case arity == 0:
		c.Value = nil // 存在性判断忽略界面残留值
	case arity == -1:
		if len(c.Value) == 0 {
			return errors.New("多选判断至少需要一个值")
		}
	default:
		if len(c.Value) < arity {
			return errors.New("该判断方式需要 " + itoa(arity) + " 个值")
		}
		c.Value = c.Value[:arity]
	}

	if c.Op == CCOpRegex && len(c.Value) > 0 && len(c.Value[0]) > ccRegexMaxLen {
		return errors.New("正则表达式长度不能超过 512")
	}
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// ValidateCCConditions 校验整组条件，并回填规范化后的 JSON。
func ValidateCCConditions(conds []MatchCondition) ([]MatchCondition, error) {
	if len(conds) == 0 {
		return nil, errors.New("请至少配置一个匹配条件")
	}
	if len(conds) > 20 {
		return nil, errors.New("单条规则的匹配条件不能超过 20 个")
	}
	for i := range conds {
		if err := conds[i].Validate(); err != nil {
			return nil, err
		}
	}
	return conds, nil
}

// CCConditionsNeedResponsePhase 判断这组条件里是否引用了响应期字段。
func CCConditionsNeedResponsePhase(conds []MatchCondition) bool {
	for _, c := range conds {
		if CCFieldIsResponsePhase(c.Field) {
			return true
		}
	}
	return false
}
