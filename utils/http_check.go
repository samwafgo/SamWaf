package utils

import (
	"net/http"
	"strings"
)

// IsStaticAssist 是否是静态资源
func IsStaticAssist(res *http.Response, contentType string) bool {
	var allowedSortFields = []string{"application/javascript", "text/css", "image/jpeg",
		"image/png", "image/gif", "image/x-icon", "text/js"}

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
		acceptHeader := res.Request.Header.Get("Accept")
		if acceptHeader != "" {
			// 检查Accept头是否主要请求图片或其他资源类型
			isResourceRequest := strings.Contains(acceptHeader, "image/") ||
				strings.Contains(acceptHeader, "font/") ||
				strings.Contains(acceptHeader, "audio/") ||
				strings.Contains(acceptHeader, "video/")
			if isResourceRequest {
				return true
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
	return false
}
