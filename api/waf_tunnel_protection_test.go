package api

import (
	"SamWaf/model"
	"SamWaf/model/request"
	"strings"
	"testing"
)

func TestTunnelProtectionDDNSDomain(t *testing.T) {
	for _, tt := range []struct {
		input string
		want  string
	}{
		{" Home.Example.NET. ", "home.example.net"},
		{"家用.example.net", "xn--fct050d.example.net"},
		{"https://home.example.net", ""},
		{"home.example.net:53", ""},
		{"*.example.net", ""},
		{"home..example.net", ""},
		{"home.example.net..", ""},
		{"127.0.0.1", ""},
		{"::1", ""},
		{"localhost", ""},
		{"-home.example.net", ""},
		{strings.Repeat("a", 64) + ".example.net", ""},
	} {
		t.Run(tt.input, func(t *testing.T) {
			got, err := normalizeTunnelDDNSDomain(tt.input)
			if got != tt.want || (err == nil) != (tt.want != "") {
				t.Fatalf("got %q, %v, want %q", got, err, tt.want)
			}
		})
	}
	duplicate := request.WafTunnelDDNSProtectionReq{Bindings: []model.TunnelDDNSBinding{{Domain: "HOME.example.net.", Family: "ipv4"}, {Domain: "home.example.net", Family: "ipv6"}}}
	if err := validateTunnelDDNS(&duplicate); err == nil {
		t.Fatal("canonical duplicate should be rejected")
	}
}

func TestTunnelProtectionRegionRule(t *testing.T) {
	base := model.TunnelRegionRule{Name: "  中国来源  ", Operator: "ne", Country: "cn", Action: "deny", Enabled: true}
	req := request.WafTunnelRegionProtectionReq{Rules: []model.TunnelRegionRule{base}}
	if err := validateTunnelRegion(&req); err != nil {
		t.Fatal(err)
	}
	if req.Rules[0].Country != "CN" || req.Rules[0].Name != "中国来源" {
		t.Fatalf("normalization=%+v", req.Rules[0])
	}
	for _, rule := range []model.TunnelRegionRule{
		{Name: "Unknown", Operator: "ne", Country: "ZZ", Action: "deny"},
		{Name: "Invalid action", Operator: "ne", Country: "CN", Action: "pass"},
		{Name: "Invalid operator", Operator: "regexp", Country: "CN", Action: "deny"},
		{Name: strings.Repeat("国", 61), Operator: "eq", Country: "CN", Action: "allow"},
		{Name: "Line\nBreak", Operator: "eq", Country: "CN", Action: "allow"},
	} {
		req.Rules[0] = rule
		if err := validateTunnelRegion(&req); err == nil {
			t.Fatalf("invalid rule accepted: %+v", rule)
		}
	}
}
