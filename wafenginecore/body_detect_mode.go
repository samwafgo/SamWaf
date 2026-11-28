package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/libinjection-go"
	"SamWaf/wafenginecore/wafhttpcore"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
)

// 请求体深度检测（D3/S1 新增的 formValue/JSON 逐值与裸文本 BODY 检测）受 GCONFIG_BODY_DETECT_MODE 门控：
//   observe(默认) 命中只在日志标记不拦截；block 命中即拦；off 不做请求体深检。
// 查询串(RawQuery/POST_FORM)及标准表单参数检测不受此开关影响，始终拦截。

// bodyDetectEnabled 请求体深检是否启用（off 时整体跳过 body 深检）
func bodyDetectEnabled() bool {
	return global.GCONFIG_BODY_DETECT_MODE != "off"
}

// bodyDetectBlocking 是否为拦截模式（block）；否则为 observe 观察
func bodyDetectBlocking() bool {
	return global.GCONFIG_BODY_DETECT_MODE == "block"
}

// markBodyObserve 观察模式命中：只在日志打观察标记(不置 IsBlock)，abnormal 日志模式下会因
// RULE 非空被落库，便于事后筛查(RULE 以“观察模式:”开头，status 非 403)确认无误后再切 block。
func markBodyObserve(weblogbean *innerbean.WebLog, title string) {
	weblogbean.RULE = "观察模式:疑似" + title
}

// SetSQLiFingerprintExclude 转发更新 libinjection-go 的全局 SQLi 指纹豁免集（读侧无锁）。
func SetSQLiFingerprintExclude(csv string) {
	libinjection.SetSQLiFingerprintExclude(csv)
}

// ── 按字段排除(E)：已知携带富文本/HTML/代码的字段名，其请求体值跳过深检 ──

const maxBodyDetectFieldExclude = 200 // 排除项数量上限，防误配超长清单

var bodyFieldExclude atomic.Pointer[map[string]struct{}] // RCU：构建完只读，读侧无锁

// SetBodyDetectFieldExclude 解析逗号分隔的字段名(小写去空、去重、封顶)为排除集并原子发布。
// 由配置加载(task_config)调用。
func SetBodyDetectFieldExclude(csv string) {
	m := make(map[string]struct{})
	for _, f := range strings.Split(csv, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		m[f] = struct{}{}
		if len(m) >= maxBodyDetectFieldExclude {
			break
		}
	}
	bodyFieldExclude.Store(&m)
}

// fieldAt 安全取 fields[i]，越界(如测试只填了 BodyValues 未填 BodyFields)返回 ""。
func fieldAt(fields []string, i int) string {
	if i >= 0 && i < len(fields) {
		return fields[i]
	}
	return ""
}

// isBodyFieldExcluded 字段名是否在排除集(不区分大小写)。空字段名与内部合成元数据键永不排除。
func isBodyFieldExcluded(field string) bool {
	if field == "" || field == wafhttpcore.MetaFormKey {
		return false
	}
	m := bodyFieldExclude.Load()
	if m == nil || len(*m) == 0 {
		return false
	}
	_, ok := (*m)[strings.ToLower(field)]
	return ok
}

// classifyWebLogBody 统一完成请求体的协议识别、表单提取与检测归一化：
//   - 多值 Content-Type 头：标记 HasAmbiguousBodyType=true，拒绝赋予任何二进制/multipart 免检资格；
//   - x-www-form-urlencoded：即使含局部非法百分号转义（如末尾 &x=%）也保留已解析字段并宽松解码补全；
//   - multipart/*：仅在无 boundary* 歧义、无尾随夹带且已见 part 结构合法时置 IsMultipart=true；
//   - 真实二进制体：Content-Type + 魔数 + 首尾/全量字节分布校验通过才置 IsBinaryBody=true。
func classifyWebLogBody(r *http.Request, weblogbean *innerbean.WebLog, rawBody []byte, truncatedAtBudget bool, formValues *url.Values) {
	if weblogbean == nil {
		return
	}
	weblogbean.BodyClassified = true
	if formValues != nil && *formValues == nil {
		*formValues = url.Values{}
	}

	var ctValues []string
	if r != nil {
		ctValues = r.Header.Values("Content-Type")
	}
	if len(ctValues) > 1 {
		weblogbean.HasAmbiguousBodyType = true
	}

	contentType := ""
	if len(ctValues) == 1 {
		contentType = ctValues[0]
	}
	baseMediaType := extractBaseMediaType(contentType)

	if baseMediaType == "application/x-www-form-urlencoded" {
		if weblogbean.BODY != "" {
			parsed, err := url.ParseQuery(weblogbean.BODY)
			if formValues != nil {
				for k, vals := range parsed {
					for _, v := range vals {
						(*formValues).Add(k, wafhttpcore.NormalizeForDetection(v))
					}
				}
			}
			if err == nil {
				weblogbean.IsUrlEncodedForm = true
			} else {
				// 存在畸形 % 转义（如 &pad=%）：Go r.FormValue 与 PHP/Python 仍会消费有效字段，
				// 除保留上方 parsed 结果外，再按宽松百分号解码逐段补齐并标记需第一阶段兜底。
				zlog.Debug("urlencoded parse partial error", zap.Error(err))
				weblogbean.HasAmbiguousBodyType = true
				if formValues != nil {
					ingestLooseUrlEncoded(weblogbean.BODY, *formValues)
				}
			}
		}
	} else if strings.HasPrefix(baseMediaType, "multipart/") {
		mpRes := wafhttpcore.ExtractMultipartFields(contentType, rawBody, truncatedAtBudget)
		weblogbean.IsMultipart = mpRes.Valid
		weblogbean.MultipartText = mpRes.MultipartText
		weblogbean.MultipartPlainFiles = mpRes.PlainFileBodies
		if !mpRes.Valid && len(rawBody) > 0 {
			// 声明为 multipart/* 但缺少合法 boundary、含 boundary* 歧义或结构畸形：强制保留第一阶段拦截
			weblogbean.HasAmbiguousBodyType = true
		}
		if formValues != nil {
			for k, vals := range mpRes.FormValues {
				for _, v := range vals {
					(*formValues).Add(k, v)
				}
			}
		}
		if len(mpRes.JSONValues) > 0 {
			weblogbean.BodyFields = append(weblogbean.BodyFields, mpRes.JSONFields...)
			weblogbean.BodyValues = append(weblogbean.BodyValues, mpRes.JSONValues...)
		}
	}

	if !weblogbean.IsMultipart && !weblogbean.HasAmbiguousBodyType {
		weblogbean.IsBinaryBody = wafhttpcore.IsConfirmedBinaryBody(contentType, rawBody)
	}

	if weblogbean.CookiesDecoded == "" && weblogbean.COOKIES != "" {
		weblogbean.CookiesDecoded = wafhttpcore.NormalizeForDetection(weblogbean.COOKIES)
	}

	if !weblogbean.IsMultipart && !weblogbean.IsBinaryBody {
		if weblogbean.BodyDecoded == "" && weblogbean.BODY != "" {
			weblogbean.BodyDecoded = wafhttpcore.NormalizeForDetection(weblogbean.BODY)
		}
		if len(weblogbean.BodyValues) == 0 && weblogbean.BODY != "" {
			weblogbean.BodyFields, weblogbean.BodyValues = wafhttpcore.ExtractJSONFieldValues(weblogbean.BODY)
		}
	}
}

func extractBaseMediaType(contentType string) string {
	if contentType == "" {
		return ""
	}
	if mt, ok := wafhttpcore.ParseSingleMediaType(contentType); ok {
		return mt
	}
	semi := strings.IndexByte(contentType, ';')
	if semi >= 0 {
		contentType = contentType[:semi]
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

func ingestLooseUrlEncoded(raw string, dst url.Values) {
	// application/x-www-form-urlencoded 仅以 '&' 分隔键值，不按 ';' 拆分（避免切碎字段值内的 JS/CSS 语句）
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		k, v, hasEq := strings.Cut(pair, "=")
		dk := wafhttpcore.NormalizeForDetection(wafhttpcore.PercentDecodeLoose(strings.ReplaceAll(k, "+", " ")))
		if !hasEq {
			dst.Add(dk, "")
			continue
		}
		dv := wafhttpcore.NormalizeForDetection(wafhttpcore.PercentDecodeLoose(strings.ReplaceAll(v, "+", " ")))
		dst.Add(dk, dv)
	}
}

// ensureWebLogBodyClassified 供直接调用各 Check* 的单元测试或旁路入口兜底，确保与 ServeHTTP 分流行为一致。
func ensureWebLogBodyClassified(r *http.Request, weblogbean *innerbean.WebLog, formValues *url.Values) {
	if weblogbean == nil || weblogbean.BodyClassified {
		return
	}
	raw := weblogbean.SrcByteBody
	if len(raw) == 0 && weblogbean.BODY != "" {
		raw = []byte(weblogbean.BODY)
	}
	classifyWebLogBody(r, weblogbean, raw, false, formValues)
}
