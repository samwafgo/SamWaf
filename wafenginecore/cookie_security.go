package wafenginecore

import (
	"SamWaf/model"
	"strings"
)

// secureSetCookie 对单条 Set-Cookie 头按策略「缺失才补」安全属性。
// 保留原 Set-Cookie 的全部内容（Path/Domain/Max-Age/Expires/未知属性），仅在缺失时追加：
//   - HttpOnly：cfg.HttpOnly==1 且原值无 httponly 时追加
//   - Secure  ：cfg.Secure==1 强制；==2 仅当 isHTTPS；SameSite=None 也强制（None 要求 Secure）
//   - SameSite：cfg.SameSite 非空且原值无 samesite 时追加
//
// 安全要点：HTTP 下 Secure==2 不追加 Secure，否则 cookie 会失效。
func secureSetCookie(raw string, isHTTPS bool, cfg model.CookieSecurityConfig) string {
	if strings.TrimSpace(raw) == "" {
		return raw
	}

	// 提取 cookie 名（第一个 '=' 前的串），命中排除名单则原样返回
	name := raw
	if idx := strings.Index(raw, "="); idx >= 0 {
		name = raw[:idx]
	}
	name = strings.TrimSpace(name)
	if isExcludedCookie(name, cfg.ExcludeCookies) {
		return raw
	}

	lower := strings.ToLower(raw)

	if cfg.HttpOnly == 1 && !strings.Contains(lower, "httponly") {
		raw += "; HttpOnly"
		lower = strings.ToLower(raw)
	}

	needSecure := cfg.Secure == 1 || (cfg.Secure == 2 && isHTTPS) || cfg.SameSite == "None"
	if needSecure && !strings.Contains(lower, "secure") {
		raw += "; Secure"
		lower = strings.ToLower(raw)
	}

	if cfg.SameSite != "" && !strings.Contains(lower, "samesite") {
		raw += "; SameSite=" + cfg.SameSite
	}

	return raw
}

// isExcludedCookie 判断 cookie 名是否在排除名单（逗号分隔，大小写不敏感）
func isExcludedCookie(name, excludeCookies string) bool {
	if excludeCookies == "" {
		return false
	}
	for _, ex := range strings.Split(excludeCookies, ",") {
		ex = strings.TrimSpace(ex)
		if ex != "" && strings.EqualFold(ex, name) {
			return true
		}
	}
	return false
}
