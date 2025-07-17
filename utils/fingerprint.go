package utils

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"strings"
)

// GenerateFingerprint 生成浏览器指纹
func GenerateFingerprint(r *http.Request) string {
	var parts []string

	// 收集HTTP头信息
	parts = append(parts, r.UserAgent())
	parts = append(parts, r.Header.Get("Accept-Language"))
	parts = append(parts, r.Header.Get("Accept-Encoding"))

	// 拼接所有信息
	data := strings.Join(parts, "|")
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}
