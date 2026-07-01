package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"bytes"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// staticRespRecorder 用于捕获 http.ServeFile 的响应，以便在写出前应用压缩。
type staticRespRecorder struct {
	header     http.Header
	buf        bytes.Buffer
	statusCode int
}

func (rec *staticRespRecorder) Header() http.Header {
	return rec.header
}

func (rec *staticRespRecorder) Write(b []byte) (int, error) {
	return rec.buf.Write(b)
}

func (rec *staticRespRecorder) WriteHeader(statusCode int) {
	rec.statusCode = statusCode
}

// 敏感文件和路径黑名单
var (
	// 路径穿越攻击模式
	pathTraversalPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\.\.[\\/]`),
		regexp.MustCompile(`[\\/]\.\.[\\/]`),
		regexp.MustCompile(`%2e%2e[\\/]`),
		regexp.MustCompile(`%2e%2e%2f`),
		regexp.MustCompile(`%2e%2e%5c`),
		regexp.MustCompile(`\.\.[\\/%]`),
		regexp.MustCompile(`%252e%252e`),
		regexp.MustCompile(`%c0%ae%c0%ae`),
		regexp.MustCompile(`%uff0e%uff0e`),
		regexp.MustCompile(`[\\/]{2,}`),
		regexp.MustCompile(`\\{2,}`),
	}
)

// splitConfigString 分割配置字符串为数组，去除空白项
func splitConfigString(configStr string) []string {
	if configStr == "" {
		return []string{}
	}

	parts := strings.Split(configStr, ",")
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}

	return result
}

// getDefaultSensitivePathsString 获取默认敏感路径配置字符串
func getDefaultSensitivePathsString() string {
	return "/etc/passwd,/etc/shadow,/etc/group,/etc/gshadow,/etc/hosts,/etc/hostname,/etc/resolv.conf,/etc/ssh/,/var/log/,/.ssh/,/.bash_history,/.profile,/.bashrc,/etc/crontab,/var/spool/cron/,/etc/apache2/,/etc/nginx/,/etc/httpd/,/var/www/,/usr/share/,/var/tmp/,/var/run/,c:\\windows\\,c:\\program files\\,c:\\program files (x86)\\,c:\\users\\,c:\\documents and settings\\,c:\\windows\\system32\\,c:\\windows\\syswow64\\,c:\\boot.ini,c:\\autoexec.bat,c:\\config.sys,\\windows\\,\\program files\\,\\program files (x86)\\,\\users\\,\\documents and settings\\,\\windows\\system32\\,\\windows\\syswow64\\,boot.ini,autoexec.bat,config.sys,ntuser.dat,pagefile.sys,hiberfil.sys,swapfile.sys"
}

// getDefaultSensitiveExtensionsString 获取默认敏感文件扩展名字符串
func getDefaultSensitiveExtensionsString() string {
	return ".key,.pem,.crt,.p12,.pfx,.jks,.bak,.backup,.old,.orig,.save,.sql,.db,.sqlite,.mdb,.env,.htaccess,.htpasswd,.git,.svn,.hg,.bzr,.DS_Store,Thumbs.db,desktop.ini,.tmp,.temp,.lock,.pid"
}

// getDefaultAllowedExtensionsString 获取默认允许的文件扩展名字符串
func getDefaultAllowedExtensionsString() string {
	return ".html,.htm,.css,.js,.mjs,.cjs,.json,.map,.png,.jpg,.jpeg,.gif,.svg,.ico,.webp,.avif,.pdf,.txt,.md,.xml,.woff,.woff2,.ttf,.eot,.otf,.mp4,.webm,.ogg,.mp3,.wav,.zip,.tar,.gz,.rar"
}

// getDefaultSensitivePatternsString 获取默认敏感文件名模式字符串
func getDefaultSensitivePatternsString() string {
	return `(?i)\.git(/|\\),(?i)\.svn(/|\\),(?i)\.env,(?i)database\.(php|xml|json|yaml|yml),(?i)(backup|dump|export)\.(sql|db|tar|zip|gz),(?i)(id_rsa|id_dsa|id_ecdsa|id_ed25519),(?i)\.ssh(/|\\).*,(?i)(access|error|debug)\.log,(?i)web\.config,(?i)phpinfo\.php`
}

// getSensitivePathsFromConfig 从配置获取敏感路径数组
func getSensitivePathsFromConfig(config model.StaticSiteConfig) []string {
	if config.SensitivePaths != "" {
		return splitConfigString(config.SensitivePaths)
	}
	return splitConfigString(getDefaultSensitivePathsString())
}

// getSensitiveExtensionsFromConfig 从配置获取敏感扩展名数组
func getSensitiveExtensionsFromConfig(config model.StaticSiteConfig) []string {
	if config.SensitiveExtensions != "" {
		return splitConfigString(config.SensitiveExtensions)
	}
	return splitConfigString(getDefaultSensitiveExtensionsString())
}

// getAllowedExtensionsFromConfig 从配置获取允许扩展名数组
func getAllowedExtensionsFromConfig(config model.StaticSiteConfig) []string {
	if config.AllowedExtensions != "" {
		return splitConfigString(config.AllowedExtensions)
	}
	return splitConfigString(getDefaultAllowedExtensionsString())
}

// getSensitivePatternsFromConfig 从配置获取敏感模式数组
func getSensitivePatternsFromConfig(config model.StaticSiteConfig) []string {
	if config.SensitivePatterns != "" {
		return splitConfigString(config.SensitivePatterns)
	}
	return splitConfigString(getDefaultSensitivePatternsString())
}

// serveStaticFile 提供静态文件服务
func (waf *WafEngine) serveStaticFile(w http.ResponseWriter, r *http.Request, config model.StaticSiteConfig, weblog *innerbean.WebLog, hostsafe *wafenginmodel.HostSafe) bool {
	// 记录访问尝试
	startTime := time.Now()
	defer func() {
		zlog.Debug("静态文件访问完成",
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
			zap.Duration("duration", time.Since(startTime)))
	}()

	// 只允许GET和HEAD方法
	if r.Method != "GET" && r.Method != "HEAD" {
		waf.logSecurityEvent("非法HTTP方法", r.URL.Path, r.RemoteAddr, "method: "+r.Method, weblog)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}

	// 检查URL长度限制
	if len(r.URL.Path) > 1024 {
		waf.logSecurityEvent("URL过长", r.URL.Path, r.RemoteAddr, "", weblog)
		w.WriteHeader(http.StatusRequestURITooLong)
		return true
	}

	// 提取相对路径（去掉前缀）
	relativePath := strings.TrimPrefix(r.URL.Path, config.StaticSitePrefix)
	if relativePath == "" {
		relativePath = "index.html" // 默认首页
	}

	// URL解码检查
	originalPath := relativePath
	if waf.containsEncodedThreats(relativePath) {
		waf.logSecurityEvent("检测到编码攻击", originalPath, r.RemoteAddr, "", weblog)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden: Encoded threat detected"))
		return true
	}

	// 路径穿越攻击检查
	if waf.containsPathTraversal(relativePath) {
		waf.logSecurityEvent("路径穿越攻击", originalPath, r.RemoteAddr, "", weblog)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden: Path traversal detected"))
		return true
	}

	// 敏感路径检查
	if waf.isSensitivePath(relativePath, config) {
		waf.logSecurityEvent("访问敏感路径", originalPath, r.RemoteAddr, "", weblog)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden: Access to sensitive path denied"))
		return true
	}

	// 敏感文件检查
	if waf.isSensitiveFile(relativePath, config) {
		waf.logSecurityEvent("访问敏感文件", originalPath, r.RemoteAddr, "", weblog)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden: Access to sensitive file denied"))
		return true
	}

	// 清理路径
	cleanPath := path.Clean(relativePath)

	// 二次路径穿越检查（清理后）
	if waf.containsPathTraversal(cleanPath) {
		waf.logSecurityEvent("清理后仍存在路径穿越", originalPath, r.RemoteAddr, "clean_path: "+cleanPath, weblog)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden: Path traversal detected after cleaning"))
		return true
	}

	// 构建完整文件路径
	fullPath := filepath.Join(config.StaticSitePath, cleanPath)

	// 验证文件路径是否在允许的目录内
	absBasePath, err := filepath.Abs(config.StaticSitePath)
	if err != nil {
		zlog.Error("获取基础路径失败", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return true
	}

	absFullPath, err := filepath.Abs(fullPath)
	if err != nil {
		zlog.Error("获取完整路径失败", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return true
	}

	// 确保请求的文件在静态站点目录内
	if !strings.HasPrefix(absFullPath, absBasePath) {
		waf.logSecurityEvent("目录遍历攻击", originalPath, r.RemoteAddr,
			"full_path: "+fullPath+", abs_path: "+absFullPath, weblog)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden: Directory traversal detected"))
		return true
	}

	// spaFallback 内联函数：回退到 index.html（SPA history 模式）
	spaFallback := func() bool {
		if config.SpaFallback != 1 {
			return false
		}
		indexPath := filepath.Join(config.StaticSitePath, "index.html")
		if idxInfo, idxErr := os.Stat(indexPath); idxErr == nil && !idxInfo.IsDir() {
			waf.setSecurityHeaders(w, config)
			http.ServeFile(w, r, indexPath)
			return true
		}
		return false
	}

	// 检查文件是否存在和权限
	fileInfo, err := os.Stat(absFullPath)
	if err != nil {
		if os.IsNotExist(err) {
			// SPA 回退：文件不存在时回退到 index.html（适用于 Vue/React Router history 模式）
			if spaFallback() {
				return true
			}
			zlog.Info("文件未找到", zap.String("remote_addr", r.RemoteAddr))
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("404 Not Found"))
		} else if os.IsPermission(err) {
			waf.logSecurityEvent("文件权限拒绝", originalPath, r.RemoteAddr, "", weblog)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("403 Forbidden: Permission denied"))
		} else {
			zlog.Error("文件状态检查失败", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 Internal Server Error"))
		}
		return true
	}

	// 目录：尝试 index.html，SPA fallback，最后 403
	if fileInfo.IsDir() {
		// 先尝试目录下的 index.html
		indexInDir := filepath.Join(absFullPath, "index.html")
		if idxInfo, idxErr := os.Stat(indexInDir); idxErr == nil && !idxInfo.IsDir() {
			waf.setSecurityHeaders(w, config)
			http.ServeFile(w, r, indexInDir)
			return true
		}
		// SPA fallback
		if spaFallback() {
			return true
		}
		waf.logSecurityEvent("尝试访问目录", originalPath, r.RemoteAddr, "", weblog)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden: Directory access denied"))
		return true
	}

	// 检查文件类型（基于扩展名）；无扩展名的路径在 SPA 模式下 fallback 到 index.html
	if !waf.isAllowedFileType(absFullPath, config) {
		if spaFallback() {
			return true
		}
		waf.logSecurityEvent("不允许的文件类型", originalPath, r.RemoteAddr, "", weblog)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden: File type not allowed"))
		return true
	}

	// 网页防篡改：受保护静态文件的基线比对/回吐（命中 replace 则短路，不再走正常伺服）
	if waf.checkAndServeStaticTamper(w, r, absFullPath, config, weblog, hostsafe) {
		return true
	}

	// 记录合法的静态文件访问到日志队列
	waf.logStaticFileAccess(r.URL.Path, r.RemoteAddr, fileInfo.Size(), weblog, hostsafe)

	// 解析压缩配置
	compressCfg := model.ParseResponseCompressConfig(hostsafe.Host.ResponseCompressJSON)
	if compressCfg.IsEnable != 1 {
		// 压缩未启用，直接服务文件
		waf.setSecurityHeaders(w, config)
		http.ServeFile(w, r, absFullPath)
		return true
	}

	// 用 recorder 捕获 http.ServeFile 的完整响应，再按配置决定是否压缩后写出
	rec := &staticRespRecorder{
		header:     make(http.Header),
		statusCode: http.StatusOK,
	}
	http.ServeFile(rec, r, absFullPath)

	// 仅对 200 OK 且尚无 Content-Encoding 的响应尝试压缩；
	// 304、206 Range、已压缩等情况直接透传。
	if rec.statusCode == http.StatusOK && strings.TrimSpace(rec.header.Get("Content-Encoding")) == "" {
		body := rec.buf.Bytes()
		fakeResp := &http.Response{
			StatusCode: rec.statusCode,
			Header:     rec.header,
		}
		compressed := waf.maybeApplyResponseCompress(r, fakeResp, body, compressCfg)
		// 将 recorder 中的头写入真实 ResponseWriter
		for k, vv := range rec.header {
			for _, v := range vv {
				w.Header().Set(k, v)
			}
		}
		// 若内容被压缩，更新 Content-Length
		if len(compressed) != len(body) {
			w.Header().Set("Content-Length", strconv.FormatInt(int64(len(compressed)), 10))
		}
		waf.setSecurityHeaders(w, config)
		w.WriteHeader(rec.statusCode)
		w.Write(compressed)
	} else {
		// 透传：304 Not Modified、206 Partial Content 或已有编码等
		for k, vv := range rec.header {
			for _, v := range vv {
				w.Header().Set(k, v)
			}
		}
		waf.setSecurityHeaders(w, config)
		w.WriteHeader(rec.statusCode)
		w.Write(rec.buf.Bytes())
	}
	return true
}

// containsPathTraversal 检查路径是否包含路径穿越攻击模式（增强版）
func (waf *WafEngine) containsPathTraversal(filePath string) bool {
	// 转换为小写进行检查
	lowerPath := strings.ToLower(filePath)

	// 使用正则表达式检查
	for _, pattern := range pathTraversalPatterns {
		if pattern.MatchString(lowerPath) {
			return true
		}
	}

	// 额外的字符串检查
	suspiciousPatterns := []string{
		"../", "..\\", ".../", "...\\",
		"%2e%2e%2f", "%2e%2e/", "..%2f",
		"%2e%2e%5c", "..%5c", "\\\\", "//",
		"%252e", "%c0%ae", "%uff0e",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	return false
}

// containsEncodedThreats 检查编码攻击
func (waf *WafEngine) containsEncodedThreats(filePath string) bool {
	lowerPath := strings.ToLower(filePath)

	// 检查各种编码绕过
	encodedThreats := []string{
		"%252e", "%c0%ae", "%uff0e", // 双重编码
		"%2e%2e%2f", "%2e%2e%5c", // URL编码
		"..%c0%af", "..%ef%bc%8f", // UTF-8编码
		"..%c1%9c", "..%c1%pc", // 畸形UTF-8
	}

	for _, threat := range encodedThreats {
		if strings.Contains(lowerPath, threat) {
			return true
		}
	}

	return false
}

// isSensitivePath 检查是否为敏感路径
func (waf *WafEngine) isSensitivePath(filePath string, config model.StaticSiteConfig) bool {
	lowerPath := strings.ToLower(filePath)

	// 从配置获取敏感路径数组
	sensitivePaths := getSensitivePathsFromConfig(config)

	// 检查敏感路径
	for _, sensitivePath := range sensitivePaths {
		if strings.Contains(lowerPath, strings.ToLower(sensitivePath)) {
			return true
		}
	}

	return false
}

// isSensitiveFile 检查是否为敏感文件
func (waf *WafEngine) isSensitiveFile(filePath string, config model.StaticSiteConfig) bool {
	lowerPath := strings.ToLower(filePath)
	fileName := filepath.Base(lowerPath)

	// 从配置获取敏感扩展名数组
	sensitiveExtensions := getSensitiveExtensionsFromConfig(config)

	// 检查敏感文件扩展名
	for _, ext := range sensitiveExtensions {
		if strings.HasSuffix(fileName, ext) {
			return true
		}
	}

	// 从配置获取敏感模式数组
	sensitivePatterns := getSensitivePatternsFromConfig(config)

	// 检查敏感文件名模式
	for _, patternStr := range sensitivePatterns {
		if pattern, err := regexp.Compile(patternStr); err == nil {
			if pattern.MatchString(lowerPath) {
				return true
			}
		}
	}

	// 检查隐藏文件（以.开头，但不是../或./）
	if strings.HasPrefix(fileName, ".") && fileName != "." && fileName != ".." {
		return true
	}

	return false
}

// isAllowedFileType 检查是否为允许的文件类型
func (waf *WafEngine) isAllowedFileType(filePath string, config model.StaticSiteConfig) bool {
	// 从配置获取允许扩展名数组
	allowedExtensions := getAllowedExtensionsFromConfig(config)

	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == "" {
		return false // 没有扩展名的文件不允许
	}

	for _, allowedExt := range allowedExtensions {
		if ext == allowedExt {
			return true
		}
	}

	return false
}

// defaultSecurityHeaders 内置默认安全响应头（挪到前端配置）
var defaultSecurityHeaders = []struct{ name, value string }{}

// setSecurityHeaders 设置安全响应头。
// 若 config.SecurityHeaders 为空，则全部使用默认值；
// 否则以用户配置为准，某项 HeaderValue 为空时该项回退到默认值。
func (waf *WafEngine) setSecurityHeaders(w http.ResponseWriter, config model.StaticSiteConfig) {
	if len(config.SecurityHeaders) == 0 {
		// 未配置，直接写入全部默认头
		for _, h := range defaultSecurityHeaders {
			w.Header().Set(h.name, h.value)
		}
		return
	}

	// 把用户配置转为 map，便于 O(1) 查找
	userHeaders := make(map[string]string, len(config.SecurityHeaders))
	for _, h := range config.SecurityHeaders {
		if h.HeaderName != "" {
			userHeaders[strings.ToLower(h.HeaderName)] = h.HeaderValue
		}
	}

	// 遍历默认头：用户配置了就用用户的，值为空则回退默认
	writtenKeys := make(map[string]bool)
	for _, def := range defaultSecurityHeaders {
		key := strings.ToLower(def.name)
		if val, ok := userHeaders[key]; ok {
			if val == "" {
				w.Header().Set(def.name, def.value) // 值为空，回退默认
			} else {
				w.Header().Set(def.name, val) // 使用用户自定义值
			}
			writtenKeys[key] = true
		} else {
			w.Header().Set(def.name, def.value) // 用户未配置该项，使用默认
		}
	}

	// 写入用户额外配置的非默认头（不在 defaultSecurityHeaders 列表中的）
	for _, h := range config.SecurityHeaders {
		if h.HeaderName == "" || h.HeaderValue == "" {
			continue
		}
		if !writtenKeys[strings.ToLower(h.HeaderName)] {
			w.Header().Set(h.HeaderName, h.HeaderValue)
		}
	}
}

// checkAndServeStaticTamper 静态伺服链路的网页防篡改：命中受保护规则则读盘比对基线。
// 静态站点服务 / 路径路由静态文件走 http.ServeFile 直接落盘伺服、不过 modifyResponse，
// 故在此单独挂钩。返回 true 表示已完整处理（已回吐正确副本并记日志），调用方应直接 return；
// 返回 false 表示未拦截（未开启/非GET/无匹配规则/带参跳过/未学习/一致/仅告警），走正常静态伺服。
func (waf *WafEngine) checkAndServeStaticTamper(w http.ResponseWriter, r *http.Request, absFullPath string, config model.StaticSiteConfig, weblog *innerbean.WebLog, hostsafe *wafenginmodel.HostSafe) bool {
	cfg := model.ParseTamperConfig(hostsafe.Host.TamperJSON)
	if cfg.IsEnable != 1 {
		return false
	}
	// 只对 GET 比对（HEAD 无正文，交由正常伺服）
	if !strings.EqualFold(r.Method, http.MethodGet) {
		return false
	}
	rule := matchTamperRule(hostsafe.TamperRules, r.URL.Path)
	if rule == nil {
		return false
	}
	if rule.IgnoreQuery == 0 && r.URL.RawQuery != "" {
		return false
	}
	// 静态文件即基线原文（磁盘未压缩），直接读盘做哈希基准
	content, err := os.ReadFile(absFullPath)
	if err != nil || len(content) == 0 {
		return false
	}

	switch evaluateTamper(sha256Hex(content), *rule) {
	case tamperCapture:
		waf.captureTamperBaseline(rule, content, staticContentType(absFullPath, content), http.StatusOK, cfg)
		return false
	case tamperPass, tamperSkip:
		return false
	case tamperTampered:
		replaced := cfg.Action != "alert"
		// 统计 + 告警（异步，文案区分是否已替换）
		waf.onTamperDetected(rule, weblog, replaced)
		weblog.RULE = "网页防篡改"
		weblog.RISK_LEVEL = 3
		weblog.GUEST_IDENTIFICATION = "网页篡改"
		if !replaced {
			// 仅告警：不替换，放行原（被篡改）文件，日志由正常流程记录
			return false
		}
		// replace：回吐基线正确副本并短路
		waf.serveStaticTamperBaseline(w, r, rule, config)
		weblog.ACTION = "阻止"
		weblog.STATUS = "200 OK"
		weblog.STATUS_CODE = http.StatusOK
		weblog.RES_CONTENT_LENGTH = int64(len(rule.BaselineContent))
		waf.enqueueTamperLog(weblog, hostsafe.Host.EXCLUDE_URL_LOG)
		return true
	}
	return false
}

// serveStaticTamperBaseline 静态链路回吐基线正确副本（未压缩直出，带安全头）
func (waf *WafEngine) serveStaticTamperBaseline(w http.ResponseWriter, r *http.Request, rule *model.TamperRule, config model.StaticSiteConfig) {
	waf.setSecurityHeaders(w, config)
	ct := rule.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(rule.BaselineContent)))
	w.WriteHeader(http.StatusOK)
	if !strings.EqualFold(r.Method, http.MethodHead) {
		w.Write(rule.BaselineContent)
	}
}

// staticContentType 依扩展名/内容推断静态文件 Content-Type（与 http.ServeFile 行为一致）
func staticContentType(fullPath string, content []byte) string {
	if ct := mime.TypeByExtension(filepath.Ext(fullPath)); ct != "" {
		return ct
	}
	return http.DetectContentType(content)
}

// logStaticFileAccess 记录成功的静态文件访问到传入的weblog
func (waf *WafEngine) logStaticFileAccess(path, remoteAddr string, fileSize int64, weblog *innerbean.WebLog, hostsafe *wafenginmodel.HostSafe) {
	// 更新weblog信息
	weblog.ACTION = "放行"
	weblog.RISK_LEVEL = 0 // 无风险

	// 按照全局日志记录策略决定是否记录
	if global.GWAF_RUNTIME_RECORD_LOG_TYPE == "all" {
		if hostsafe.Host.EXCLUDE_URL_LOG == "" {
			global.GQEQUE_LOG_DB.Enqueue(weblog)
		} else {
			lines := strings.Split(hostsafe.Host.EXCLUDE_URL_LOG, "\n")
			isRecordLog := true
			// 检查每一行
			for _, line := range lines {
				if strings.HasPrefix(weblog.URL, line) {
					isRecordLog = false
				}
			}
			if isRecordLog {
				global.GQEQUE_LOG_DB.Enqueue(weblog)
			}
		}
	} else if global.GWAF_RUNTIME_RECORD_LOG_TYPE == "abnormal" && weblog.ACTION != "放行" {
		// 对于静态文件成功访问，ACTION是"放行"，所以在abnormal模式下不会记录
		// 这里保持逻辑一致性，虽然实际上不会执行
		global.GQEQUE_LOG_DB.Enqueue(weblog)
	}
}

// logSecurityEvent 记录安全事件
func (waf *WafEngine) logSecurityEvent(eventType, path, remoteAddr, details string, weblog *innerbean.WebLog) {
	// 更新weblog信息
	weblog.ACTION = "禁止"
	weblog.RULE = "静态文件安全检查: " + eventType
	weblog.RISK_LEVEL = 3 // 高风险

	// 入队到日志系统
	global.GQEQUE_LOG_DB.Enqueue(weblog)

	// 同时记录到系统日志用于调试
	zlog.Warn("静态文件安全事件",
		zap.String("event_type", eventType),
		zap.String("path", path),
		zap.String("remote_addr", remoteAddr),
		zap.String("details", details))
}

// 初始化静态站点配置的默认值
func InitDefaultStaticSiteConfig() model.StaticSiteConfig {
	return model.StaticSiteConfig{
		IsEnableStaticSite:  0,
		StaticSitePath:      "",
		StaticSitePrefix:    "/",
		SensitivePaths:      getDefaultSensitivePathsString(),
		SensitiveExtensions: getDefaultSensitiveExtensionsString(),
		AllowedExtensions:   getDefaultAllowedExtensionsString(),
		SensitivePatterns:   getDefaultSensitivePatternsString(),
	}
}
