package api

import (
	"SamWaf/common/validfield"
	"SamWaf/model"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

func checkCustomRequestHost(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var config model.CustomHeadersConfig
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		return errors.New("自定义请求头配置格式不正确")
	}
	if config.IsEnableCustomHeaders != 1 {
		return nil
	}
	seen := false
	for _, header := range config.Headers {
		if http.CanonicalHeaderKey(header.HeaderName) != "Host" {
			continue
		}
		if seen {
			return errors.New("自定义请求头 Host 只能配置一次")
		}
		seen = true
		switch header.HeaderValue {
		case "", validfield.OriginalRequestHost, validfield.OriginalRequestHostname:
		default:
			if !validfield.ValidRequestHost(header.HeaderValue) {
				return errors.New("自定义请求头 Host 需填写域名或 IP（可带端口），或使用 ${host}、${hostname}")
			}
		}
	}
	return nil
}
