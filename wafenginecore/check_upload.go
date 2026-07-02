package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	uploadScanHeadBytes = 64 * 1024 // 每个文件只扫前 64KB 找 webshell 特征
	uploadBufferSlack   = 64 * 1024 // 读 body 时相对单文件上限的余量(表单字段+boundary)
)

// PHP 脚本标记出现时才检查的危险函数（小写）
var uploadPHPDangerFuncs = []string{
	"eval(", "assert(", "system(", "passthru(", "shell_exec(", "popen(", "proc_open(",
	"base64_decode(", "gzinflate(", "str_rot13(", "create_function(", "call_user_func(",
	"$_post", "$_get", "$_request", "preg_replace(", "array_map(",
}

// ASP/JSP 脚本标记出现时才检查的危险调用（小写）
var uploadScriptDangerFuncs = []string{
	"runtime.getruntime", "processbuilder", ".exec(", "wscript.shell",
	"server.createobject", "eval request", "execute(", "eval(",
}

// 高可信正则：PHP 一句话木马（子串预过滤门控后才跑）
var reUploadPHPOneLiner = regexp.MustCompile(`(?i)(eval|assert)\s*\(\s*\$_(post|get|request|server|cookie)`)

// 图片扩展名（用于“声称图片却是脚本”判断；不含 svg，svg 本身是 xml 易误报）
var uploadImageExts = map[string]bool{
	"jpg": true, "jpeg": true, "png": true, "gif": true, "bmp": true, "webp": true, "ico": true, "tiff": true,
}

// extractUploadExts 提取文件名的所有扩展名段（去空字节、取 basename、小写、按 . 拆），用于双扩展名/空字节绕过检测
func extractUploadExts(filename string) []string {
	name := filename
	if i := strings.IndexByte(name, 0x00); i >= 0 { // 空字节截断 x.php\x00.jpg
		name = name[:i]
	}
	if idx := strings.LastIndexAny(name, "/\\"); idx >= 0 {
		name = name[idx+1:]
	}
	name = strings.ToLower(strings.TrimSpace(name))
	parts := strings.Split(name, ".")
	if len(parts) <= 1 {
		return nil
	}
	exts := make([]string, 0, len(parts)-1)
	for _, p := range parts[1:] {
		p = strings.TrimRight(strings.TrimSpace(p), ". ")
		if p != "" {
			exts = append(exts, p)
		}
	}
	return exts
}

// matchDangerousExt 文件名任一扩展名段命中黑名单即危险（防 shell.php.jpg 双扩展名）
func matchDangerousExt(filename, blacklist string) (bool, string) {
	bl := blacklist
	if strings.TrimSpace(bl) == "" {
		bl = model.DefaultUploadExtBlacklist
	}
	set := map[string]bool{}
	for _, e := range strings.Split(bl, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			set[e] = true
		}
	}
	for _, ext := range extractUploadExts(filename) {
		if set[ext] {
			return true, ext
		}
	}
	return false, ""
}

// overUploadSize 文件大小是否超过上限
func overUploadSize(size, maxKB int) bool {
	return maxKB > 0 && size > maxKB*1024
}

// matchUploadPathPrefix 路径是否命中任一前缀（换行分隔）
func matchUploadPathPrefix(path, lines string) bool {
	for _, line := range strings.Split(lines, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.HasPrefix(path, line) {
			return true
		}
	}
	return false
}

// hasUploadImageExt 文件名是否是图片扩展名（不含 svg）
func hasUploadImageExt(filename string) bool {
	exts := extractUploadExts(filename)
	if len(exts) == 0 {
		return false
	}
	return uploadImageExts[exts[len(exts)-1]]
}

// isUploadTypeMismatch 保守判断“声称图片/媒体但真实内容是脚本/HTML”
func isUploadTypeMismatch(filename, declaredCT string, head []byte) bool {
	claimImage := strings.HasPrefix(strings.ToLower(declaredCT), "image/") || hasUploadImageExt(filename)
	if !claimImage || len(head) == 0 {
		return false
	}
	real := strings.ToLower(http.DetectContentType(head))
	if strings.HasPrefix(real, "image/") {
		return false // 真的是图片，放行
	}
	// 声称图片但真实是 html/text/xml，或内容含脚本标记 → 不符
	if strings.HasPrefix(real, "text/") || strings.Contains(real, "html") || strings.Contains(real, "xml") {
		return true
	}
	lower := bytes.ToLower(head)
	if bytes.Contains(lower, []byte("<?php")) || bytes.Contains(lower, []byte("<?=")) ||
		bytes.Contains(lower, []byte("<%")) || bytes.Contains(lower, []byte("<script")) {
		return true
	}
	return false
}

// scanWebshell 只扫传入的头部字节：脚本标记 + 危险函数组合判定（低误报），命中返回特征名
func scanWebshell(head []byte) (bool, string) {
	if len(head) == 0 {
		return false, ""
	}
	lower := bytes.ToLower(head)
	// 1) 高可信：PHP 一句话木马
	if (bytes.Contains(lower, []byte("<?")) || bytes.Contains(lower, []byte("$_"))) && reUploadPHPOneLiner.Match(lower) {
		return true, "php-eval-superglobal"
	}
	// 2) PHP 脚本标记 + 危险函数
	if bytes.Contains(lower, []byte("<?php")) || bytes.Contains(lower, []byte("<?=")) {
		for _, f := range uploadPHPDangerFuncs {
			if bytes.Contains(lower, []byte(f)) {
				return true, "php:" + f
			}
		}
	}
	// 3) ASP/JSP 脚本标记 + 危险调用
	if bytes.Contains(lower, []byte("<%")) {
		for _, f := range uploadScriptDangerFuncs {
			if bytes.Contains(lower, []byte(f)) {
				return true, "script:" + f
			}
		}
	}
	return false, ""
}

// uploadBlock 构造拦截结果并标记风险等级
func uploadBlock(weblog *innerbean.WebLog, title, content string) detection.Result {
	weblog.RISK_LEVEL = 3
	return detection.Result{IsBlock: true, Title: title, Content: content}
}

// CheckUpload 文件上传内容检测：对 multipart 上传做 扩展名/大小/类型不符/Webshell 四维检测。
// 关键：禁用 r.ParseMultipartForm（会清空 body 致后端丢包）；读整份 body 到内存解析副本并复位 r.Body。
func (waf *WafEngine) CheckUpload(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values,
	hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{JumpGuardResult: false, IsBlock: false, Title: "", Content: ""}

	cfg := model.ParseUploadSecurityConfig(hostTarget.Host.UploadSecurityJSON)
	if cfg.IsEnable != 1 {
		return result
	}
	// 只对可能携带上传体的方法（其余零成本放行，不碰 body）
	m := strings.ToUpper(r.Method)
	if m != http.MethodPost && m != http.MethodPut && m != http.MethodPatch {
		return result
	}
	// 必须是 multipart/form-data 且能取到 boundary
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return result
	}
	boundary := params["boundary"]
	if boundary == "" || r.Body == nil {
		return result
	}
	// 路径门：IncludePaths 非空则只检测命中的；ExcludePaths 命中则跳过（优先）
	if strings.TrimSpace(cfg.IncludePaths) != "" && !matchUploadPathPrefix(r.URL.Path, cfg.IncludePaths) {
		return result
	}
	if matchUploadPathPrefix(r.URL.Path, cfg.ExcludePaths) {
		return result
	}

	// 读 body（限检测缓冲上限）并复位 r.Body，保证后端能收到完整上传
	limit := int64(cfg.MaxSizeKB)*1024 + uploadBufferSlack
	raw, _ := io.ReadAll(io.LimitReader(r.Body, limit+1))
	r.Body = io.NopCloser(bytes.NewReader(raw))

	// 请求体超过可检测上限：fail-closed 默认拦，避免“填大绕过内容检测”
	if int64(len(raw)) > limit {
		if strings.EqualFold(cfg.OverLimitAction, "pass") {
			return result
		}
		return uploadBlock(weblogbean, "文件上传检测-上传体过大", "上传体超过可检测上限，已拦截")
	}

	mr := multipart.NewReader(bytes.NewReader(raw), boundary)
	for {
		part, e := mr.NextPart()
		if e != nil {
			break
		}
		fn := part.FileName()
		if fn == "" { // 非文件字段跳过（文本字段由 SQLi/XSS 检测覆盖）
			part.Close()
			continue
		}
		declaredCT := part.Header.Get("Content-Type")
		fileContent, _ := io.ReadAll(io.LimitReader(part, limit+1))
		part.Close()

		// 便宜→贵，命中即短路
		if cfg.CheckExt == 1 {
			if bad, ext := matchDangerousExt(fn, cfg.ExtBlacklist); bad {
				return uploadBlock(weblogbean, "文件上传检测-危险扩展名", "检测到危险文件扩展名(."+ext+")，已拦截")
			}
		}
		if cfg.CheckSize == 1 && overUploadSize(len(fileContent), cfg.MaxSizeKB) {
			return uploadBlock(weblogbean, "文件上传检测-文件过大", "上传文件超过大小上限，已拦截")
		}
		head := fileContent
		if len(head) > uploadScanHeadBytes {
			head = head[:uploadScanHeadBytes]
		}
		if cfg.CheckMagic == 1 && isUploadTypeMismatch(fn, declaredCT, head) {
			return uploadBlock(weblogbean, "文件上传检测-类型不符", "文件真实内容与声明类型不符，已拦截")
		}
		if cfg.CheckContent == 1 {
			if hit, sig := scanWebshell(head); hit {
				return uploadBlock(weblogbean, "文件上传检测-Webshell", "检测到Webshell特征("+sig+")，已拦截")
			}
		}
	}
	return result
}
