package utils

import (
	"net/http"
	"strings"
)

// IsStaticAssist 是否是静态资源
func IsStaticAssist(res *http.Response, contentType string) bool {
	// 1. 静态资源类型列表可以扩充一些常见类型
	var allowedSortFields = []string{"application/javascript", "text/css", "image/jpeg",
		"image/png", "image/gif", "image/x-icon", "text/js", "application/octet-stream",
		"image/svg+xml", "image/webp", "font/woff", "font/woff2", "font/ttf", "font/otf",
		"application/vnd.ms-fontobject", "application/x-font-ttf", "audio/mpeg", "audio/wav",
		"video/mp4", "video/webm", "application/pdf",
		"image/bmp", "video/ogg", "audio/ogg", "application/wasm"}

	for _, allowedField := range allowedSortFields {
		if strings.Contains(contentType, allowedField) {
			return true
		}
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
			isResourceRequest := strings.Contains(acceptHeader, "image/") ||
				strings.Contains(acceptHeader, "font/") ||
				strings.Contains(acceptHeader, "audio/") ||
				strings.Contains(acceptHeader, "video/") ||
				strings.Contains(acceptHeader, "text/css") ||
				strings.Contains(acceptHeader, "application/javascript") ||
				strings.Contains(acceptHeader, "application/pdf")
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
