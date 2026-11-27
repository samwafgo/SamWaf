package utils

import (
	"errors"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

func ParseACMEDirectoryURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.Contains(raw, "#") {
		return nil, errors.New("ACME 目录地址无效，必须使用不含用户信息或片段的 HTTPS URL")
	}
	if port := u.Port(); port != "" || strings.HasSuffix(u.Host, ":") {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return nil, errors.New("ACME 目录地址端口无效")
		}
	}
	return u, nil
}

func IsValidACMECAFilename(name string) bool {
	if len(name) > 255 || !strings.EqualFold(filepath.Ext(name), ".pem") || name != filepath.Clean(name) || !filepath.IsLocal(name) {
		return false
	}
	for _, c := range strings.TrimSuffix(name, filepath.Ext(name)) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return len(name) > len(".pem")
}
