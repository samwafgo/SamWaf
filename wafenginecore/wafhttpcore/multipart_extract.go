package wafhttpcore

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/url"
	"strconv"
	"strings"
)

const (
	maxMultipartParts               = 1024      // 单个请求最多解析的 part 数量上限，超限一律视为异常不免检
	maxMultipartTextPartBytes       = 1 << 20   // 单个文本 part 读取上限（与 1MB 检测前缀预算对齐）
	maxMultipartTotalTextBytes      = 1 << 20   // 所有文本 part 累计提取上限
	maxMultipartPlainFilePeekBytes  = 64 * 1024 // 无歧义文件 part 探测是否为纯文本脚本的头部上限
	maxMultipartTotalPlainFileBytes = 256 * 1024
)

// MetaFormKey 是存放 multipart 元数据（未剥离路径的原始 filename 等）的内部合成键名，
// 包含不可配置的控制字符前缀，确保不会被 body_detect_field_exclude 排除。
const MetaFormKey = "\x00_multipart_meta"

// MultipartExtractResult 保存 multipart 请求体的有界拆包结果。
type MultipartExtractResult struct {
	// Valid 为 true 表示请求确属结构无歧义的 multipart/* 报文：
	// 单一合法 boundary、无 RFC2231 boundary* 覆盖、终止符后无夹带载荷、且所有已见 part 头部无解析歧义。
	Valid           bool
	FormValues      url.Values
	JSONFields      []string
	JSONValues      []string
	MultipartText   string
	PlainFileBodies []string // 无歧义文件 part 中经字节判别确属纯文本/脚本的片段（供 RCE 检测，不入 SQLi/XSS）
}

// HasAmbiguousMultipartHeader 检查 Content-Type 头组是否存在多值头、重复 boundary 或 RFC2231 boundary* 歧义。
// Go mime.ParseMediaType 会静默采信 boundary* 覆盖 boundary，而 PHP/Java/Python/Node 忽略 boundary*，必须阻断该差异。
func HasAmbiguousMultipartHeader(ctValues []string) bool {
	if len(ctValues) == 0 {
		return true
	}
	if len(ctValues) > 1 {
		return true
	}
	raw := ctValues[0]
	semi := strings.IndexByte(raw, ';')
	if semi < 0 {
		return true
	}
	// RFC 2046 bcharsnospace 不含反斜杠；Go mime.ParseMediaType 对引号内非 tspecial 前的 "\" 保留字面值，
	// 而 PHP/Java/Python 按 quoted-pair 反转义，会导致双边界前言走私，直接拒绝含反斜杠的参数区。
	if strings.IndexByte(raw[semi+1:], '\\') >= 0 {
		return true
	}
	rawParams := parseUnquotedMIMEParams(raw[semi+1:])
	boundaryCount := 0
	for _, p := range rawParams {
		if p.hasNameSpace {
			return true
		}
		ln := strings.ToLower(p.name)
		if ln == "boundary" {
			boundaryCount++
		} else if strings.HasPrefix(ln, "boundary") && strings.Contains(ln, "*") {
			// 拒绝 boundary* / boundary*0 / boundary*0* 等 RFC2231 扩展参数
			return true
		}
	}
	return boundaryCount != 1
}

// HasLeadingOrTrailingMultipartData 检查首个行首 --boundary 之前（Preamble）或首个行首 --boundary-- 之后（Epilogue）
// 是否夹带非空白数据，防止双边界走私。
func HasLeadingOrTrailingMultipartData(rawBody []byte, boundary string) bool {
	if len(rawBody) == 0 || boundary == "" {
		return false
	}
	openMarker := []byte("--" + boundary)
	firstOpen := -1
	searchOpen := 0
	for searchOpen < len(rawBody) {
		rel := bytes.Index(rawBody[searchOpen:], openMarker)
		if rel < 0 {
			break
		}
		pos := searchOpen + rel
		lineStart := pos == 0 || rawBody[pos-1] == '\n'
		afterPos := pos + len(openMarker)
		validRight := afterPos == len(rawBody) ||
			rawBody[afterPos] == '\r' ||
			rawBody[afterPos] == '\n' ||
			rawBody[afterPos] == ' ' ||
			rawBody[afterPos] == '\t' ||
			rawBody[afterPos] == '-'
		if lineStart && validRight {
			firstOpen = pos
			break
		}
		searchOpen = pos + 2
	}
	if firstOpen < 0 {
		return true
	}
	if len(bytes.Trim(rawBody[:firstOpen], "\r\n \t")) > 0 {
		return true
	}
	return HasTrailingMultipartData(rawBody, boundary)
}

// HasTrailingMultipartData 检查首个行首 --boundary-- 终止行之后是否仍夹带非空白数据（防双 boundary 前言/尾随走私）。
func HasTrailingMultipartData(rawBody []byte, boundary string) bool {
	if len(rawBody) == 0 || boundary == "" {
		return false
	}
	marker := []byte("--" + boundary + "--")
	searchFrom := 0
	for searchFrom < len(rawBody) {
		rel := bytes.Index(rawBody[searchFrom:], marker)
		if rel < 0 {
			return false
		}
		pos := searchFrom + rel
		lineStart := pos == 0 || rawBody[pos-1] == '\n'
		afterPos := pos + len(marker)
		// 终止标记后必须是空白/换行/EOF（排除 --boundary--xxx 更长边界前缀的巧合）
		lineEnd := afterPos == len(rawBody) ||
			rawBody[afterPos] == '\r' ||
			rawBody[afterPos] == '\n' ||
			rawBody[afterPos] == ' ' ||
			rawBody[afterPos] == '\t'
		if lineStart && lineEnd {
			tail := rawBody[afterPos:]
			return len(bytes.Trim(tail, "\r\n \t")) > 0
		}
		searchFrom = pos + 2
	}
	return false
}

// ExtractMultipartFields 从已读入内存的请求体前缀中拆出 multipart 文本字段与元数据，跳过无歧义的文件字段正文。
func ExtractMultipartFields(contentType string, rawBody []byte, truncatedAtBudget bool) MultipartExtractResult {
	res := MultipartExtractResult{
		FormValues: url.Values{},
	}
	if HasAmbiguousMultipartHeader([]string{contentType}) {
		return res
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		return res
	}
	boundary := params["boundary"]
	if boundary == "" {
		return res
	}
	if len(rawBody) == 0 {
		res.Valid = true
		return res
	}
	if HasLeadingOrTrailingMultipartData(rawBody, boundary) {
		return res
	}

	mr := multipart.NewReader(bytes.NewReader(rawBody), boundary)
	partsSeen := 0
	totalText := 0
	totalPlainFile := 0
	malformed := false
	var joinedText strings.Builder

	appendMeta := func(val string) {
		val = strings.TrimSpace(val)
		if val == "" {
			return
		}
		res.FormValues.Add(MetaFormKey, NormalizeForDetection(val))
		if joinedText.Len() < maxMultipartTotalTextBytes {
			if joinedText.Len() > 0 {
				joinedText.WriteByte('\n')
			}
			joinedText.WriteString(val)
		}
	}

	ingestTextCandidate := func(fieldKey, textVal string) {
		trimmed := strings.TrimSpace(textVal)
		if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
			jf, jv, complete := ExtractJSONFieldValuesComplete(trimmed)
			if len(jv) > 0 {
				res.JSONFields = append(res.JSONFields, jf...)
				res.JSONValues = append(res.JSONValues, jv...)
			}
			// 若伪装成 {/[ 开头却非合法完整 JSON（或超 2000 值上限被截断），剥去前导括号再入 FormValues，
			// 防止被 IsStructuredDataValue 当成合法嵌套 JSON 整段跳过。
			if !complete {
				res.FormValues.Add(fieldKey, NormalizeForDetection(strings.TrimLeft(trimmed, "{[ \t\r\n")))
				return
			}
		}
		res.FormValues.Add(fieldKey, NormalizeForDetection(textVal))
	}

	for {
		if partsSeen >= maxMultipartParts {
			// 已读 1MB 窗口内出现 >=1024 个 part 属异常填充，无论流是否在 1MB 处截断均不授予免检
			malformed = true
			break
		}
		part, partErr := mr.NextRawPart()
		if partErr != nil {
			if errors.Is(partErr, io.EOF) {
				break
			}
			if truncatedAtBudget && isMultipartTruncatedErr(partErr) {
				break
			}
			malformed = true
			break
		}
		partsSeen++

		info := inspectPartDisposition(part)
		if info.ambiguous {
			malformed = true
		}
		for _, fn := range info.rawFileNames {
			appendMeta(fn)
		}
		if info.fieldName != "" {
			appendMeta(info.fieldName)
		}

		if info.isUnambiguousFile && !info.ambiguous {
			// 对无歧义文件 part 探测头部：若无二进制字节证据（如伪装成 .jpg 的纯文本 PHP/Shell 脚本），
			// 记录到独立的 PlainFileBodies 供 RCE 模块检出，不送入 FormValues/SQLi/XSS 避免文本文件误报。
			if remainPlain := maxMultipartTotalPlainFileBytes - totalPlainFile; remainPlain > 0 {
				peekLimit := maxMultipartPlainFilePeekBytes
				if remainPlain < peekLimit {
					peekLimit = remainPlain
				}
				head, _ := io.ReadAll(io.LimitReader(part, int64(peekLimit)))
				if len(head) > 0 && !hasBinaryByteEvidence(head) {
					res.PlainFileBodies = append(res.PlainFileBodies, string(head))
					totalPlainFile += len(head)
					cte := strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Transfer-Encoding")))
					if cte == "base64" || cte == "quoted-printable" {
						if dec, ok := DecodeMultipartTransferEncoding(cte, head, peekLimit); ok && len(dec) > 0 && !hasBinaryByteEvidence(dec) {
							res.PlainFileBodies = append(res.PlainFileBodies, string(dec))
							totalPlainFile += len(dec)
						}
					}
				}
			}
			_ = part.Close()
			continue
		}

		fieldKey := info.fieldName
		if info.ambiguous {
			// 存在 name*/重复参数歧义时使用不可排除合成键，防止借 name* 命中 body_detect_field_exclude
			fieldKey = MetaFormKey
		}

		remain := maxMultipartTotalTextBytes - totalText
		if remain <= 0 {
			_ = part.Close()
			malformed = true
			break
		}
		valBytes, readErr := io.ReadAll(io.LimitReader(part, int64(remain)+1))
		_ = part.Close()
		if readErr != nil && !(truncatedAtBudget && isMultipartTruncatedErr(readErr)) {
			malformed = true
		}
		if len(valBytes) > remain {
			if !truncatedAtBudget {
				malformed = true
			}
			valBytes = valBytes[:remain]
		}
		totalText += len(valBytes)

		rawVal := string(valBytes)
		ingestTextCandidate(fieldKey, rawVal)

		// 兼容自动解码 Content-Transfer-Encoding（如 Go ParseMultipartForm 的 quoted-printable）的后端
		cte := strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Transfer-Encoding")))
		if cte != "" && cte != "7bit" && cte != "8bit" && cte != "binary" {
			decodedCTE, ok := decodeMultipartCTE(cte, valBytes)
			if ok && decodedCTE != rawVal {
				ingestTextCandidate(fieldKey, decodedCTE)
			} else if !ok {
				malformed = true
			}
		}

		if joinedText.Len() < maxMultipartTotalTextBytes {
			if joinedText.Len() > 0 {
				joinedText.WriteByte('\n')
			}
			if info.fieldName != "" {
				joinedText.WriteString(info.fieldName)
				joinedText.WriteByte('=')
			}
			joinedText.WriteString(rawVal)
		}
	}

	res.MultipartText = joinedText.String()
	res.Valid = !malformed && partsSeen > 0
	return res
}

type partDispositionInfo struct {
	fieldName         string
	rawFileNames      []string
	isUnambiguousFile bool
	ambiguous         bool
}

// inspectPartDisposition 严格校验单个 part 的 Content-Disposition：
// 仅当存在唯一 Content-Disposition 头、mime.ParseMediaType 合法解析为 form-data、
// 无重复 name/filename、无 name* 扩展、且标准非扩展参数 filename 非空时，才认定为无歧义文件 part。
func inspectPartDisposition(part *multipart.Part) partDispositionInfo {
	var out partDispositionInfo
	cdVals := part.Header.Values("Content-Disposition")
	if len(cdVals) != 1 {
		out.ambiguous = true
		out.fieldName = part.FormName()
		return out
	}
	rawCD := cdVals[0]
	dispType, dispParams, err := mime.ParseMediaType(rawCD)
	if err != nil || !strings.EqualFold(dispType, "form-data") {
		out.ambiguous = true
		out.fieldName = part.FormName()
		return out
	}

	semi := strings.IndexByte(rawCD, ';')
	var rawParams []mimeRawParam
	if semi >= 0 {
		rawParams = parseUnquotedMIMEParams(rawCD[semi+1:])
	}

	nameCount := 0
	plainFileCount := 0
	starFileCount := 0
	var plainFileVal string

	for _, p := range rawParams {
		if p.hasNameSpace {
			// 参数名末尾含空白（如 "filename =a.txt"）：Go 裁剪空白认作文件，PHP rfc1867 不裁剪而放入 $_POST
			out.ambiguous = true
		}
		ln := strings.ToLower(p.name)
		switch {
		case ln == "name":
			nameCount++
		case strings.HasPrefix(ln, "name") && strings.Contains(ln, "*"):
			out.ambiguous = true
		case ln == "filename":
			plainFileCount++
			plainFileVal = p.value
			if strings.TrimSpace(p.value) != "" {
				out.rawFileNames = append(out.rawFileNames, p.value)
			}
		case strings.HasPrefix(ln, "filename") && strings.Contains(ln, "*"):
			starFileCount++
			if stripped := stripMultipartRFC2231Charset(p.value); strings.TrimSpace(stripped) != "" {
				out.rawFileNames = append(out.rawFileNames, stripped)
				if dec := percentDecodeMultipartLoose(stripped); dec != stripped && strings.TrimSpace(dec) != "" {
					out.rawFileNames = append(out.rawFileNames, dec)
				}
			}
		}
	}

	if nameCount > 1 || plainFileCount > 1 {
		out.ambiguous = true
	}
	// 仅携带 filename* 而无标准非空 filename= 时，PHP 与 Go(非 UTF-8 字符集)会将其当作普通文本字段放入 POST，拒绝按文件跳过
	if starFileCount > 0 && (plainFileCount != 1 || strings.TrimSpace(plainFileVal) == "") {
		out.ambiguous = true
	}

	out.fieldName = dispParams["name"]
	if fn := dispParams["filename"]; strings.TrimSpace(fn) != "" {
		out.rawFileNames = appendUniqueString(out.rawFileNames, fn)
	}
	if !out.ambiguous && plainFileCount == 1 && strings.TrimSpace(plainFileVal) != "" {
		out.isUnambiguousFile = true
	}
	return out
}

type mimeRawParam struct {
	name         string
	value        string
	hasNameSpace bool // "=" 左侧参数名尾部或内部含空白字符
}

// parseUnquotedMIMEParams 按 RFC 2045 扫描引号外的 "; key=value" 对，正确忽略双引号内部的分号与等号。
func parseUnquotedMIMEParams(s string) []mimeRawParam {
	var out []mimeRawParam
	i := 0
	n := len(s)
	for i < n {
		for i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == ';') {
			i++
		}
		if i >= n {
			break
		}
		nameStart := i
		for i < n && s[i] != '=' && s[i] != ';' {
			i++
		}
		rawName := s[nameStart:i]
		name := strings.TrimSpace(rawName)
		hasSpace := name != rawName || strings.ContainsAny(name, " \t\r\n")
		if i >= n || s[i] == ';' {
			if name != "" {
				out = append(out, mimeRawParam{name: name, hasNameSpace: hasSpace})
			}
			continue
		}
		i++ // skip '='
		for i < n && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		var val strings.Builder
		if i < n && s[i] == '"' {
			i++ // skip opening '"'
			for i < n {
				if s[i] == '\\' && i+1 < n {
					i++
					val.WriteByte(s[i])
					i++
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				val.WriteByte(s[i])
				i++
			}
			for i < n && s[i] != ';' {
				i++
			}
		} else {
			valStart := i
			for i < n && s[i] != ';' {
				i++
			}
			val.WriteString(strings.TrimSpace(s[valStart:i]))
		}
		if name != "" {
			out = append(out, mimeRawParam{name: name, value: val.String(), hasNameSpace: hasSpace})
		}
	}
	return out
}

// DecodeMultipartTransferEncoding 对 quoted-printable / base64 的 part 内容解码供双轨检测（导出供 CheckUpload 共用）。
func DecodeMultipartTransferEncoding(cte string, raw []byte, limit int) ([]byte, bool) {
	cte = strings.ToLower(strings.TrimSpace(cte))
	switch cte {
	case "quoted-printable":
		qr := quotedprintable.NewReader(bytes.NewReader(raw))
		dec, err := io.ReadAll(io.LimitReader(qr, int64(limit)))
		if err != nil && len(dec) == 0 {
			return nil, false
		}
		return dec, true
	case "base64":
		cleaned := bytes.Map(func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, raw)
		if len(cleaned) > limit*2 {
			cleaned = cleaned[:limit*2]
		}
		dst := make([]byte, base64.StdEncoding.DecodedLen(len(cleaned)))
		n, err := base64.StdEncoding.Decode(dst, cleaned)
		if err != nil && n == 0 {
			return nil, false
		}
		if n > limit {
			n = limit
		}
		return dst[:n], true
	default:
		return nil, false
	}
}

func decodeMultipartCTE(cte string, raw []byte) (string, bool) {
	dec, ok := DecodeMultipartTransferEncoding(cte, raw, maxMultipartTextPartBytes)
	if !ok {
		return "", false
	}
	return string(dec), true
}

func appendUniqueString(slice []string, val string) []string {
	for _, item := range slice {
		if item == val {
			return slice
		}
	}
	return append(slice, val)
}

func isMultipartTruncatedErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	return strings.Contains(err.Error(), "EOF")
}

func stripMultipartRFC2231Charset(v string) string {
	if i := strings.Index(v, "'"); i >= 0 {
		if j := strings.Index(v[i+1:], "'"); j >= 0 {
			return v[i+1+j+1:]
		}
	}
	return v
}

// PercentDecodeLoose 宽松百分号解码（含 '+' 转空格能力由调用方按需叠加），非法 % 序列原样保留。
func PercentDecodeLoose(s string) string {
	return percentDecodeMultipartLoose(s)
}

func percentDecodeMultipartLoose(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if h, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(h))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
