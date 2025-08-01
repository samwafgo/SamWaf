package utils

import (
	"SamWaf/common/zlog"
	"fmt"
	"net/http"
	"strings"
)

// 附件检测 - 多种方式综合判断
func checkAttachment(res *http.Response, contentType string) bool {

	contentDisposition := res.Header.Get("Content-Disposition")
	if contentDisposition != "" {
		// 1. 检查 attachment 标识
		if strings.Contains(strings.ToLower(contentDisposition), "attachment") {
			return true
		}
		// 2. 检查 filename 参数（即使没有 attachment，有 filename 也可能是下载）
		if strings.Contains(strings.ToLower(contentDisposition), "filename") {
			return true
		}
	}

	// 3. 检查常见的下载文件 Content-Type
	downloadContentTypes := []string{
		"application/octet-stream",
		"application/force-download",
		"application/download",
		"application/x-download",
		"application/vnd.ms-excel",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", // .xlsx
		"application/vnd.ms-powerpoint",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation", // .pptx
		"application/msword",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document", // .docx
		"application/zip",
		"application/x-zip-compressed",
		"application/rar",
		"application/x-rar-compressed",
		"application/x-7z-compressed",
		"application/gzip",
		"application/x-tar",
	}

	for _, downloadType := range downloadContentTypes {
		if strings.Contains(strings.ToLower(contentType), downloadType) {
			return true
		}
	}

	// 4. 检查 URL 中的下载相关关键词
	if res.Request != nil && res.Request.URL != nil {
		urlPath := strings.ToLower(res.Request.URL.Path)
		urlQuery := strings.ToLower(res.Request.URL.RawQuery)

		// 检查查询参数中的下载标识
		downloadParams := []string{"download=", "export=", "attachment=", "file="}
		for _, param := range downloadParams {
			if strings.Contains(urlQuery, param) {
				return true
			}
		}

		// 5. 检查常见的下载文件扩展名
		downloadExtensions := []string{
			".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
			".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm",
			".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
			".backup",
			".iso", ".img", ".bin",
		}

		for _, ext := range downloadExtensions {
			if strings.HasSuffix(urlPath, ext) {
				return true
			}
		}
	}
	return false
}

// IsStaticAssist 是否是静态资源
func IsStaticAssist(res *http.Response, contentType string) bool {
	//检测附件
	if checkAttachment(res, contentType) {
		zlog.Debug(fmt.Sprintf("检测到附件 %s", res.Request.URL.String()))
		return true
	}
	// 检查请求的Accept头，判断是否为资源类型请求
	if res.Request != nil {
		// 检查Sec-Fetch-Dest头，这是一个更明确的指示
		secFetchDest := res.Request.Header.Get("Sec-Fetch-Dest")
		if secFetchDest == "image" || secFetchDest == "font" ||
			secFetchDest == "audio" || secFetchDest == "video" ||
			secFetchDest == "style" || secFetchDest == "script" {
			return true
		}

		// 2. 检查Accept头时，应该也包含style和script类型
		acceptHeader := res.Request.Header.Get("Accept")
		if acceptHeader != "" {
			// 检查Accept头是否主要请求图片或其他资源类型
			isResourceRequest := strings.HasPrefix(acceptHeader, "image/") ||
				strings.HasPrefix(acceptHeader, "font/") ||
				strings.HasPrefix(acceptHeader, "audio/") ||
				strings.HasPrefix(acceptHeader, "video/") ||
				strings.HasPrefix(acceptHeader, "text/css") ||
				strings.HasPrefix(acceptHeader, "application/javascript") ||
				strings.HasPrefix(acceptHeader, "application/pdf")
			if isResourceRequest {
				return true
			}
		}

		// 3. 检查URL后缀，这是一个常用的判断方法
		if res.Request.URL != nil {
			path := strings.ToLower(res.Request.URL.Path)
			staticExtensions := []string{".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".ico",
				".svg", ".webp", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".wav",
				".mp4", ".webm", ".pdf", ".swf"}

			for _, ext := range staticExtensions {
				if strings.HasSuffix(path, ext) {
					return true
				}
			}
		}
	}

	//如果检测资源后发现还存在，那么进行判断处理
	var textFields = []string{"application/json", "text/xml", "application/xml",
		"text/plain", "text/html", "text/csv", "application/html"}

	for _, textField := range textFields {
		if strings.Contains(contentType, textField) {
			return false
		}
	}

	// 4. 默认返回值应该更保守，如果无法确定是否为静态资源，应该返回false
	return false
}
