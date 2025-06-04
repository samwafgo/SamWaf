package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"go.uber.org/zap"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// 敏感文件和路径黑名单
var (
	// Linux 敏感路径和文件
	linuxSensitivePaths = []string{
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
		"/etc/hosts", "/etc/hostname", "/etc/resolv.conf",
		"/etc/ssh/", "/root/", "/home/", "/var/log/",
		"/proc/", "/sys/", "/dev/", "/boot/",
		"/.ssh/", "/.bash_history", "/.profile", "/.bashrc",
		"/etc/crontab", "/var/spool/cron/",
		"/etc/apache2/", "/etc/nginx/", "/etc/httpd/",
		"/var/www/", "/usr/share/", "/opt/",
		"/tmp/", "/var/tmp/", "/run/", "/var/run/",
	}

	// Windows 敏感路径和文件
	windowsSensitivePaths = []string{
		"c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\",
		"c:\\users\\", "c:\\documents and settings\\",
		"c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
		"c:\\boot.ini", "c:\\autoexec.bat", "c:\\config.sys",
		"\\windows\\", "\\program files\\", "\\program files (x86)\\",
		"\\users\\", "\\documents and settings\\",
		"\\windows\\system32\\", "\\windows\\syswow64\\",
		"boot.ini", "autoexec.bat", "config.sys",
		"ntuser.dat", "sam", "security", "software", "system",
		"pagefile.sys", "hiberfil.sys", "swapfile.sys",
	}

	// 敏感文件扩展名
	sensitiveExtensions = []string{
		".key", ".pem", ".crt", ".p12", ".pfx", ".jks",
		".conf", ".config", ".ini", ".cfg", ".properties",
		".log", ".bak", ".backup", ".old", ".orig", ".save",
		".sql", ".db", ".sqlite", ".mdb",
		".env", ".htaccess", ".htpasswd",
		".git", ".svn", ".hg", ".bzr",
		".DS_Store", "Thumbs.db", "desktop.ini",
		".tmp", ".temp", ".lock", ".pid",
	}

	// 敏感文件名模式
	sensitiveFilePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\.git(/|\\)`),
		regexp.MustCompile(`(?i)\.svn(/|\\)`),
		regexp.MustCompile(`(?i)\.env`),
		regexp.MustCompile(`(?i)config\.(php|xml|json|yaml|yml)`),
		regexp.MustCompile(`(?i)database\.(php|xml|json|yaml|yml)`),
		regexp.MustCompile(`(?i)(backup|dump|export)\.(sql|db|tar|zip|gz)`),
		regexp.MustCompile(`(?i)(id_rsa|id_dsa|id_ecdsa|id_ed25519)`),
		regexp.MustCompile(`(?i)\.ssh(/|\\).*`),
		regexp.MustCompile(`(?i)(access|error|debug)\.log`),
		regexp.MustCompile(`(?i)web\.config`),
		regexp.MustCompile(`(?i)phpinfo\.php`),
		regexp.MustCompile(`(?i)(admin|administrator|root|test|demo)\.`),
	}

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
	if waf.isSensitivePath(relativePath) {
		waf.logSecurityEvent("访问敏感路径", originalPath, r.RemoteAddr, "", weblog)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden: Access to sensitive path denied"))
		return true
	}

	// 敏感文件检查
	if waf.isSensitiveFile(relativePath) {
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

	// 检查文件是否存在和权限
	fileInfo, err := os.Stat(absFullPath)
	if err != nil {
		if os.IsNotExist(err) {
			waf.logSecurityEvent("文件未找到", originalPath, r.RemoteAddr, "", weblog)
			// 记录404但不详细记录路径信息，防止信息泄露
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

	// 不允许访问目录
	if fileInfo.IsDir() {
		waf.logSecurityEvent("尝试访问目录", originalPath, r.RemoteAddr, "", weblog)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden: Directory access denied"))
		return true
	}

	// 检查文件类型（基于扩展名）
	if !waf.isAllowedFileType(absFullPath) {
		waf.logSecurityEvent("不允许的文件类型", originalPath, r.RemoteAddr, "", weblog)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden: File type not allowed"))
		return true
	}

	// 设置安全头
	waf.setSecurityHeaders(w)

	// 记录合法的静态文件访问到日志队列
	waf.logStaticFileAccess(r.URL.Path, r.RemoteAddr, fileInfo.Size(), weblog, hostsafe)

	// 提供文件服务
	http.ServeFile(w, r, absFullPath)
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
func (waf *WafEngine) isSensitivePath(filePath string) bool {
	lowerPath := strings.ToLower(filePath)

	// 检查Linux敏感路径
	for _, sensitivePath := range linuxSensitivePaths {
		if strings.Contains(lowerPath, strings.ToLower(sensitivePath)) {
			return true
		}
	}

	// 检查Windows敏感路径
	for _, sensitivePath := range windowsSensitivePaths {
		if strings.Contains(lowerPath, strings.ToLower(sensitivePath)) {
			return true
		}
	}

	return false
}

// isSensitiveFile 检查是否为敏感文件
func (waf *WafEngine) isSensitiveFile(filePath string) bool {
	lowerPath := strings.ToLower(filePath)
	fileName := filepath.Base(lowerPath)

	// 检查敏感文件扩展名
	for _, ext := range sensitiveExtensions {
		if strings.HasSuffix(fileName, ext) {
			return true
		}
	}

	// 检查敏感文件名模式
	for _, pattern := range sensitiveFilePatterns {
		if pattern.MatchString(lowerPath) {
			return true
		}
	}

	// 检查隐藏文件（以.开头，但不是../或./）
	if strings.HasPrefix(fileName, ".") && fileName != "." && fileName != ".." {
		return true
	}

	return false
}

// isAllowedFileType 检查是否为允许的文件类型
func (waf *WafEngine) isAllowedFileType(filePath string) bool {
	// 允许的文件扩展名白名单
	allowedExtensions := []string{
		".html", ".htm", ".css", ".js", ".json",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
		".pdf", ".txt", ".md", ".xml",
		".woff", ".woff2", ".ttf", ".eot",
		".mp4", ".webm", ".ogg", ".mp3", ".wav",
		".zip", ".tar", ".gz", ".rar",
	}

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

// setSecurityHeaders 设置安全响应头
func (waf *WafEngine) setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Cache-Control", "public, max-age=3600")
}

// logStaticFileAccess 记录成功的静态文件访问到传入的weblog
func (waf *WafEngine) logStaticFileAccess(path, remoteAddr string, fileSize int64, weblog *innerbean.WebLog, hostsafe *wafenginmodel.HostSafe) {
	// 更新weblog信息
	weblog.ACTION = "放行"
	weblog.RULE = "静态文件访问成功"
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
