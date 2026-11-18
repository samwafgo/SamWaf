package api

import "testing"

func TestCheckCustomRequestHost(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		wantError bool
	}{
		{"missing", "", false},
		{"malformed", `{`, true},
		{"disabled", `{"is_enable_custom_headers":0,"headers":[{"header_name":"Host","header_value":"*.example.test"}]}`, false},
		{"other header", `{"is_enable_custom_headers":1,"headers":[{"header_name":"Referer","header_value":"https://app.example.test/path"}]}`, false},
		{"static host", `{"is_enable_custom_headers":1,"headers":[{"header_name":"hOsT","header_value":"app.example.test"}]}`, false},
		{"ipv6 with port", `{"is_enable_custom_headers":1,"headers":[{"header_name":"Host","header_value":"[2001:db8::1]:4432"}]}`, false},
		{"raw visitor host", `{"is_enable_custom_headers":1,"headers":[{"header_name":"Host","header_value":"${host}"}]}`, false},
		{"visitor hostname", `{"is_enable_custom_headers":1,"headers":[{"header_name":"Host","header_value":"${hostname}"}]}`, false},
		{"empty override", `{"is_enable_custom_headers":1,"headers":[{"header_name":"Host","header_value":""}]}`, false},
		{"wildcard", `{"is_enable_custom_headers":1,"headers":[{"header_name":"Host","header_value":"*.example.test"}]}`, true},
		{"full URL", `{"is_enable_custom_headers":1,"headers":[{"header_name":"Host","header_value":"https://app.example.test/path"}]}`, true},
		{"invalid port", `{"is_enable_custom_headers":1,"headers":[{"header_name":"Host","header_value":"app.example.test:65536"}]}`, true},
		{"control characters", `{"is_enable_custom_headers":1,"headers":[{"header_name":"Host","header_value":"app.example.test\r\n"}]}`, true},
		{"unsupported template", `{"is_enable_custom_headers":1,"headers":[{"header_name":"Host","header_value":"${header:X-Host}"}]}`, true},
		{"case-insensitive duplicate", `{"is_enable_custom_headers":1,"headers":[{"header_name":"Host","header_value":"app.example.test"},{"header_name":"host","header_value":"other.example.test"}]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkCustomRequestHost(tc.raw); (err != nil) != tc.wantError {
				t.Fatalf("checkCustomRequestHost returned %v, want error = %t", err, tc.wantError)
			}
		})
	}
}
