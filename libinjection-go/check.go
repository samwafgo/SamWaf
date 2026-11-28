package libinjection

import (
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/corazawaf/libinjection-go"
)

const maxSQLiFPExclude = 200 // 指纹豁免项数量上限，防误配超长清单

var sqliFPExclude atomic.Pointer[map[string]struct{}]

// SetSQLiFingerprintExclude 解析逗号分隔的 libinjection SQLi 指纹清单并原子发布（读侧无锁）。
// 注意：libinjection 指纹字符严格区分大小写（如 't'=SQLType 与 'T'=TSQL 语义不同），仅裁剪首尾空白。
func SetSQLiFingerprintExclude(csv string) {
	m := make(map[string]struct{})
	for _, fp := range strings.Split(csv, ",") {
		fp = strings.TrimSpace(fp)
		if fp == "" {
			continue
		}
		m[fp] = struct{}{}
		if len(m) >= maxSQLiFPExclude {
			break
		}
	}
	sqliFPExclude.Store(&m)
}

// IsSQLiFingerprintExcluded 报告给定 SQLi 指纹是否在全局豁免集中。
func IsSQLiFingerprintExcluded(fp string) bool {
	if fp == "" {
		return false
	}
	m := sqliFPExclude.Load()
	if m == nil || len(*m) == 0 {
		return false
	}
	_, ok := (*m)[fp]
	return ok
}

func IsXSS(input string) bool {
	return libinjection.IsXSS(input)
}

// IsSQLiInspect 调用 libinjection 检测 SQLi 并返回 (是否生效命中, 原始指纹)。
// 当首轮指纹命中 sqli_fp_exclude 豁免集时，额外复验单引号/双引号上下文、注释符与分号子段，
// 防止利用 Pass 1(QuoteNone) 凑出豁免指纹短路掩盖单引号上下文或第 6 个 Token 之后的真实 SQL 注入。
func IsSQLiInspect(input string) (bool, string) {
	if input == "" {
		return false, ""
	}
	result, fp := libinjection.IsSQLi(input)
	if !result {
		return false, ""
	}
	if !IsSQLiFingerprintExcluded(fp) {
		return true, fp
	}
	if maskedHit, maskedFP := checkMaskedSQLiContexts(input); maskedHit {
		return true, maskedFP
	}
	return false, fp
}

func checkMaskedSQLiContexts(input string) (bool, string) {
	// 含明确 SQL 注释定界符（-- / /*）时禁止借弱指纹豁免放行（防 "' SELECT 1 -- ')=1" 把注释吞入字面量）
	if strings.Contains(input, "--") || strings.Contains(input, "/*") {
		return true, "comment_guard"
	}
	// 模拟单引号闭合上下文：若首轮因 QuoteNone 把引号对之间当普通字符串吞掉而命中豁免指纹，
	// 前置闭合串 "'a" 后引号角色翻转，暴露内部真实的 SQL 关键字指纹
	if idx := strings.IndexByte(input, '\''); idx >= 0 {
		if ok, fp2 := libinjection.IsSQLi("'a" + input); ok && !IsSQLiFingerprintExcluded(fp2) {
			return true, fp2
		}
		if ok, fp3 := libinjection.IsSQLi("1'" + input[idx+1:]); ok && !IsSQLiFingerprintExcluded(fp3) {
			return true, fp3
		}
	}
	// 模拟双引号闭合上下文
	if idx := strings.IndexByte(input, '"'); idx >= 0 {
		if ok, fp2 := libinjection.IsSQLi(`"a` + input); ok && !IsSQLiFingerprintExcluded(fp2) {
			return true, fp2
		}
		if ok, fp3 := libinjection.IsSQLi(`1"` + input[idx+1:]); ok && !IsSQLiFingerprintExcluded(fp3) {
			return true, fp3
		}
	}
	// 按分号拆段复检，防前 5 个 Token 凑出豁免指纹掩盖后续堆叠语句
	if strings.IndexByte(input, ';') >= 0 {
		for _, seg := range strings.Split(input, ";") {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			if ok, fpSeg := libinjection.IsSQLi(seg); ok && !IsSQLiFingerprintExcluded(fpSeg) {
				return true, fpSeg
			}
		}
	}
	return false, ""
}

func IsSQLiNotReturnPrint(input string) bool {
	result, _ := IsSQLiInspect(input)
	return result
}

// containsXSSChars 快速判断字符串是否包含 XSS 攻击的必要字符。
// 真实 XSS payload 必须含有 HTML/JS 特殊字符；不含这些字符可直接跳过 libinjection。
func containsXSSChars(s string) bool {
	for _, c := range s {
		switch c {
		case '<', '>', '"', '\'', '(', ')', '/', '`':
			return true
		}
	}
	return false
}

// IsXSSSingleValue 对单个已解码的参数值进行 XSS 检测，先做快速预过滤再调用 libinjection。
// 适用于已经拆分好的单个表单字段值。
func IsXSSSingleValue(v string) bool {
	return containsXSSChars(v) && libinjection.IsXSS(v)
}

// IsXSSInQueryValues 解析 query string，仅对参数值调用 IsXSS，避免参数名（如 style、href）
// 被 libinjection 误当 HTML 属性导致误报。
// 解析失败时回退到对整体字符串做预过滤 + IsXSS 检测。
func IsXSSInQueryValues(query string) bool {
	if query == "" {
		return false
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		// 解析失败说明格式异常，可能是恶意构造，回退到整体检测
		return containsXSSChars(query) && libinjection.IsXSS(query)
	}
	for _, vals := range values {
		for _, v := range vals {
			if IsXSSSingleValue(v) {
				return true
			}
		}
	}
	return false
}
