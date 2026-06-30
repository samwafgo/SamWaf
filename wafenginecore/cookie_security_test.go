package wafenginecore

import (
	"SamWaf/model"
	"strings"
	"testing"
)

func TestSecureSetCookie(t *testing.T) {
	full := model.CookieSecurityConfig{IsEnable: 1, HttpOnly: 1, Secure: 2, SameSite: "Lax"}

	tests := []struct {
		name        string
		raw         string
		isHTTPS     bool
		cfg         model.CookieSecurityConfig
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:        "https adds all when missing",
			raw:         "sid=abc; Path=/",
			isHTTPS:     true,
			cfg:         full,
			wantContain: []string{"sid=abc", "Path=/", "HttpOnly", "Secure", "SameSite=Lax"},
		},
		{
			name:        "http secure auto (mode2) does NOT add Secure",
			raw:         "sid=abc; Path=/",
			isHTTPS:     false,
			cfg:         full,
			wantContain: []string{"HttpOnly", "SameSite=Lax"},
			wantAbsent:  []string{"Secure"},
		},
		{
			name:        "secure force (mode1) adds even on http",
			raw:         "sid=abc",
			isHTTPS:     false,
			cfg:         model.CookieSecurityConfig{IsEnable: 1, Secure: 1},
			wantContain: []string{"Secure"},
		},
		{
			name:       "secure off (mode0) never adds",
			raw:        "sid=abc",
			isHTTPS:    true,
			cfg:        model.CookieSecurityConfig{IsEnable: 1, Secure: 0},
			wantAbsent: []string{"Secure"},
		},
		{
			name:        "does not duplicate existing httponly (case-insensitive)",
			raw:         "sid=abc; httponly",
			isHTTPS:     true,
			cfg:         model.CookieSecurityConfig{IsEnable: 1, HttpOnly: 1},
			wantContain: []string{"httponly"},
			wantAbsent:  []string{"HttpOnly"}, // 不应再追加首字母大写的副本
		},
		{
			name:        "does not override existing samesite",
			raw:         "sid=abc; SameSite=Strict",
			isHTTPS:     true,
			cfg:         model.CookieSecurityConfig{IsEnable: 1, SameSite: "Lax"},
			wantContain: []string{"SameSite=Strict"},
			wantAbsent:  []string{"SameSite=Lax"},
		},
		{
			name:        "samesite none forces secure",
			raw:         "sid=abc",
			isHTTPS:     false,
			cfg:         model.CookieSecurityConfig{IsEnable: 1, Secure: 2, SameSite: "None"},
			wantContain: []string{"SameSite=None", "Secure"},
		},
		{
			name:        "excluded cookie untouched",
			raw:         "_ga=GA1.2.3; Path=/",
			isHTTPS:     true,
			cfg:         model.CookieSecurityConfig{IsEnable: 1, HttpOnly: 1, Secure: 1, SameSite: "Lax", ExcludeCookies: "_ga, sso_token"},
			wantContain: []string{"_ga=GA1.2.3; Path=/"},
			wantAbsent:  []string{"HttpOnly", "Secure", "SameSite"},
		},
		{
			name:        "preserves original and unknown attributes",
			raw:         "sid=abc; Path=/app; Domain=example.com; Max-Age=3600; Priority=High",
			isHTTPS:     true,
			cfg:         full,
			wantContain: []string{"Path=/app", "Domain=example.com", "Max-Age=3600", "Priority=High", "HttpOnly", "Secure"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := secureSetCookie(tt.raw, tt.isHTTPS, tt.cfg)
			for _, c := range tt.wantContain {
				if !strings.Contains(got, c) {
					t.Errorf("expected result to contain %q, got %q", c, got)
				}
			}
			for _, a := range tt.wantAbsent {
				if strings.Contains(got, a) {
					t.Errorf("expected result to NOT contain %q, got %q", a, got)
				}
			}
		})
	}
}

func TestSecureSetCookieEmptyRaw(t *testing.T) {
	if got := secureSetCookie("", true, model.CookieSecurityConfig{IsEnable: 1, HttpOnly: 1}); got != "" {
		t.Errorf("empty raw should stay empty, got %q", got)
	}
}

func TestIsExcludedCookie(t *testing.T) {
	if !isExcludedCookie("_ga", "_ga, foo") {
		t.Error("_ga should be excluded")
	}
	if !isExcludedCookie("FOO", "_ga, foo") {
		t.Error("case-insensitive match expected")
	}
	if isExcludedCookie("bar", "_ga, foo") {
		t.Error("bar should not be excluded")
	}
	if isExcludedCookie("bar", "") {
		t.Error("empty exclude list excludes nothing")
	}
}
