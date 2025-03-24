package utils

import "strings"

// IsContent 是否是内容
func IsContent(contentType string) bool {
	var allowedSortFields = []string{"application/json", "text/xml", "application/xml",
		"text/plain", "text/html", "text/csv", "application/html"}

	for _, allowedField := range allowedSortFields {
		if strings.Contains(contentType, allowedField) {
			return true
		}
	}
	return false
}

// IsStaticAssist 是否是静态资源
func IsStaticAssist(contentType string) bool {
	var allowedSortFields = []string{"application/javascript", "text/css", "image/jpeg",
		"image/png", "image/gif", "image/x-icon", "text/js"}

	for _, allowedField := range allowedSortFields {
		if strings.Contains(contentType, allowedField) {
			return true
		}
	}
	return false
}
