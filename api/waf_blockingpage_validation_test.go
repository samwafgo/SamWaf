package api

import (
	"SamWaf/global"
	"strings"
	"testing"
)

func TestValidateUnmatchedHostPage(t *testing.T) {
	oldCode := global.GWAF_GLOBAL_HOST_CODE
	global.GWAF_GLOBAL_HOST_CODE = "global-website-uuid"
	t.Cleanup(func() { global.GWAF_GLOBAL_HOST_CODE = oldCode })
	cases := []struct {
		name, host, code, attack, content, headers string
		valid                                      bool
	}{
		{"default", "global-website-uuid", "403", "", "", "[]", true},
		{"template", "global-website-uuid", "403", "", `<p>[[.SAMWAF_HOST]]</p>`, `[{"name":"Content-Type","value":"text/html; charset=utf-8"}]`, true},
		{"site", "site", "403", "", "", "[]", false},
		{"status", "global-website-uuid", "500", "", "", "[]", false},
		{"attack", "global-website-uuid", "403", "cc_attack", "", "[]", false},
		{"large", "global-website-uuid", "403", "", strings.Repeat("a", 256*1024+1), "[]", false},
		{"syntax", "global-website-uuid", "403", "", `[[if]]`, "[]", false},
		{"context", "global-website-uuid", "403", "", `<a href="[[if .SAMWAF_HOST]]">broken</a>`, "[]", false},
		{"headers", "global-website-uuid", "403", "", "", "wrong", false},
		{"length", "global-website-uuid", "403", "", "", `[{"name":"content-length","value":"1"}]`, false},
		{"header name", "global-website-uuid", "403", "", "", `[{"name":"bad header","value":"1"}]`, false},
		{"header value", "global-website-uuid", "403", "", "", `[{"name":"X-Test","value":"a\r\nb"}]`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUnmatchedHostPage(tc.host, tc.code, tc.attack, tc.content, tc.headers)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, err=%v", tc.valid, err)
			}
		})
	}
}
