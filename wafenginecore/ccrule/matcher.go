// Package ccrule 负责把 CC 规则编译成可在请求热路径上直接求值的形态。
//
// 编译发生在规则保存/加载时，请求期只做取值与比较：
// 热路径上不允许编译正则、不允许解析 JSON、不允许反射。
package ccrule

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// maxFieldValueLen 参与匹配前对取值的截断长度。
// 请求头/Cookie/请求体字段的长度由客户端决定，不设上限的话
// contains、正则这类操作会在超长串上产生与请求量成正比的开销。
const maxFieldValueLen = 8 * 1024

// CompiledRule 是一条可直接求值的规则。
type CompiledRule struct {
	Rule *model.AntiCCRule

	conds       []compiledCond
	excludeExts map[string]bool
	// hasResponseField 条件里引用了响应期字段，必须等响应回来才能判定
	hasResponseField bool
}

type compiledCond struct {
	field   string
	key     string
	op      string
	values  []string
	lowered []string       // 忽略大小写比较用的小写副本
	re      *regexp.Regexp // op=regex 时预编译的正则
	num     []int64        // 数值型比较用的预解析值
}

// Compile 把规则编译成可求值形态。规则内容不合法时返回错误，保存与加载阶段都应拒绝。
func Compile(rule *model.AntiCCRule) (*CompiledRule, error) {
	cr := &CompiledRule{Rule: rule}

	if rule.CountScope == model.CCCountScopeDynamic {
		cr.excludeExts = make(map[string]bool)
		for _, ext := range rule.ExcludeExtList() {
			cr.excludeExts[ext] = true
		}
	}

	conds, err := rule.Conditions()
	if err != nil {
		return nil, err
	}
	for i := range conds {
		c := conds[i]
		if err := c.Validate(); err != nil {
			return nil, err
		}
		cc := compiledCond{field: c.Field, key: c.Key, op: c.Op, values: []string(c.Value)}
		cc.lowered = make([]string, len(cc.values))
		for j, v := range cc.values {
			cc.lowered[j] = strings.ToLower(v)
		}
		if c.Op == model.CCOpRegex && len(cc.values) > 0 {
			re, err := regexp.Compile(cc.values[0])
			if err != nil {
				return nil, err
			}
			cc.re = re
		}
		if c.Op == model.CCOpGt || c.Op == model.CCOpLt || c.Op == model.CCOpBetween {
			cc.num = make([]int64, 0, len(cc.values))
			for _, v := range cc.values {
				n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
				if err != nil {
					return nil, err
				}
				cc.num = append(cc.num, n)
			}
		}
		if model.CCFieldIsResponsePhase(c.Field) {
			cr.hasResponseField = true
		}
		cr.conds = append(cr.conds, cc)
	}
	return cr, nil
}

// NeedsResponsePhase 该规则是否必须等响应回来才能判定。
func (cr *CompiledRule) NeedsResponsePhase() bool {
	return cr.hasResponseField || cr.Rule.CountPhase == model.CCCountPhaseResponse
}

// Matches 判断请求是否落在本规则的匹配范围内。条件之间是 AND。
func (cr *CompiledRule) Matches(r *http.Request, log *innerbean.WebLog) bool {
	switch cr.Rule.MatchMode {
	case model.CCMatchModeAll:
		return true
	case model.CCMatchModeSimple:
		for i := range cr.conds {
			if !cr.conds[i].eval(r, log) {
				return false
			}
		}
		return true
	default:
		// expr 模式由调用方用规则引擎判定，这里不参与
		return true
	}
}

// InCountScope 判断这个请求按本规则的统计口径算不算一次。
func (cr *CompiledRule) InCountScope(r *http.Request) bool {
	switch cr.Rule.CountScope {
	case model.CCCountScopeDynamic:
		// 静态资源不计数。一次页面加载会带出几十个子请求，
		// 把它们算进来会让同一个阈值的含义完全变形。
		return !cr.excludeExts[strings.ToLower(path.Ext(r.URL.Path))]
	case model.CCCountScopeDocument:
		// 只统计「用户真的翻了一页」。现代浏览器必带 Sec-Fetch-Dest，回退看 Accept。
		if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" {
			return dest == "document"
		}
		return strings.Contains(r.Header.Get("Accept"), "text/html")
	case model.CCCountScopeOriginOnly:
		// 需要缓存命中标记，当前统一按回源处理；缓存层补上标记后在此细化
		return true
	default:
		return true
	}
}

// eval 求值一个条件。多值字段按「任一命中即命中」处理。
func (c *compiledCond) eval(r *http.Request, log *innerbean.WebLog) bool {
	values := c.fieldValues(r, log)

	switch c.op {
	case model.CCOpExists:
		return len(values) > 0
	case model.CCOpNotExists:
		return len(values) == 0
	}

	// not_* 系列语义是「所有取值都不满足」，与其余操作符的「任一满足」相反
	negated := c.op == model.CCOpNe || c.op == model.CCOpNotContains || c.op == model.CCOpNotIn
	if len(values) == 0 {
		// 字段不存在时，否定类条件视为成立，肯定类条件视为不成立
		return negated
	}
	for _, v := range values {
		if len(v) > maxFieldValueLen {
			v = v[:maxFieldValueLen]
		}
		hit := c.matchOne(v)
		if negated && hit {
			// 否定类条件只要有一个取值落在集合里就不成立
			return false
		}
		if !negated && hit {
			return true
		}
	}
	return negated
}

// matchOne 判断单个取值是否满足条件（不含 not_* 的取反，取反在 eval 里统一处理）。
func (c *compiledCond) matchOne(v string) bool {
	lv := strings.ToLower(v)
	switch c.op {
	case model.CCOpEq, model.CCOpNe:
		return len(c.lowered) > 0 && lv == c.lowered[0]
	case model.CCOpContains, model.CCOpNotContains:
		return len(c.lowered) > 0 && strings.Contains(lv, c.lowered[0])
	case model.CCOpPrefix:
		return len(c.lowered) > 0 && strings.HasPrefix(lv, c.lowered[0])
	case model.CCOpSuffix:
		return len(c.lowered) > 0 && strings.HasSuffix(lv, c.lowered[0])
	case model.CCOpRegex:
		return c.re != nil && c.re.MatchString(v)
	case model.CCOpIn, model.CCOpNotIn:
		for _, want := range c.lowered {
			if lv == want {
				return true
			}
		}
		return false
	case model.CCOpGt, model.CCOpLt, model.CCOpBetween:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return false
		}
		switch c.op {
		case model.CCOpGt:
			return len(c.num) > 0 && n > c.num[0]
		case model.CCOpLt:
			return len(c.num) > 0 && n < c.num[0]
		default:
			return len(c.num) > 1 && n >= c.num[0] && n <= c.num[1]
		}
	}
	return false
}

// fieldValues 取出条件所引用字段的当前值，可能是多个。
//
// 请求头一律直接读 r.Header：WebLog.HEADER 是拼接后的字符串，
// 按名取值要把整串切成切片，放在每请求每条件的热路径上会持续产生分配。
func (c *compiledCond) fieldValues(r *http.Request, log *innerbean.WebLog) []string {
	switch c.field {
	case model.CCFieldURI:
		return []string{r.URL.Path}
	case model.CCFieldQueryStr:
		return []string{r.URL.RawQuery}
	case model.CCFieldMethod:
		return []string{r.Method}
	case model.CCFieldHost:
		return []string{r.Host}
	case model.CCFieldExt:
		return []string{strings.ToLower(path.Ext(r.URL.Path))}
	case model.CCFieldScheme:
		if r.TLS != nil {
			return []string{"https"}
		}
		return []string{"http"}
	case model.CCFieldUserAgent:
		return nonEmpty(r.UserAgent())
	case model.CCFieldReferer:
		return nonEmpty(r.Referer())
	case model.CCFieldHeader:
		return r.Header.Values(c.key)
	case model.CCFieldCookie:
		if ck, err := r.Cookie(c.key); err == nil {
			return nonEmpty(ck.Value)
		}
		return nil
	case model.CCFieldQueryParam:
		if vs, ok := r.URL.Query()[c.key]; ok {
			return vs
		}
		return nil
	case model.CCFieldBodyField:
		return bodyFieldValues(log, c.key)
	case model.CCFieldClientIP:
		if log != nil {
			return nonEmpty(log.SRC_IP)
		}
		return nil
	case model.CCFieldCountry:
		return logField(log, func(l *innerbean.WebLog) string { return l.COUNTRY })
	case model.CCFieldProvince:
		return logField(log, func(l *innerbean.WebLog) string { return l.PROVINCE })
	case model.CCFieldCity:
		return logField(log, func(l *innerbean.WebLog) string { return l.CITY })
	case model.CCFieldIsBot:
		if log != nil {
			return []string{strconv.Itoa(log.IsBot)}
		}
		return nil
	case model.CCFieldBodyLength:
		if log != nil {
			return []string{strconv.FormatInt(log.CONTENT_LENGTH, 10)}
		}
		return nil

	// —— 响应期字段。只有 CountPhase=response 的规则会走到这里 ——
	case model.CCFieldRespContentType:
		if log != nil {
			return nonEmpty(headerFromRaw(log.ResHeader, "Content-Type"))
		}
		return nil
	case model.CCFieldStatusCode:
		if log != nil {
			return []string{strconv.Itoa(log.STATUS_CODE)}
		}
		return nil
	case model.CCFieldRespLength:
		if log != nil {
			return []string{strconv.FormatInt(log.RES_CONTENT_LENGTH, 10)}
		}
		return nil
	case model.CCFieldUpstreamCost:
		if log != nil {
			return []string{strconv.FormatInt(log.TimeSpent, 10)}
		}
		return nil
	}
	return nil
}

// bodyFieldValues 取 JSON 请求体里某个字段的全部取值。
// BodyFields 与 BodyValues 是平行数组，长度可能不一致（只填了值没填字段名），需按下标兜底。
func bodyFieldValues(log *innerbean.WebLog, key string) []string {
	if log == nil || len(log.BodyValues) == 0 {
		return nil
	}
	var out []string
	for i, v := range log.BodyValues {
		if i < len(log.BodyFields) && strings.EqualFold(log.BodyFields[i], key) {
			out = append(out, v)
		}
	}
	return out
}

// headerFromRaw 从拼接的响应头文本里取一个头的值。
// 响应头在请求期用不到，只有响应期计数会调用，不在主热路径上。
func headerFromRaw(raw, name string) string {
	if raw == "" {
		return ""
	}
	lowerName := strings.ToLower(name)
	for _, line := range strings.Split(raw, "\n") {
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(line[:idx])) == lowerName {
			return strings.TrimSpace(strings.TrimRight(line[idx+1:], "\r"))
		}
	}
	return ""
}

func nonEmpty(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

func logField(log *innerbean.WebLog, get func(*innerbean.WebLog) string) []string {
	if log == nil {
		return nil
	}
	return nonEmpty(get(log))
}
