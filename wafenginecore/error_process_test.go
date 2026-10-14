package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestTemplateSourceIP(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want string
	}{
		{"IPv4", "203.0.113.10", "203.0.113.10"},
		{"IPv6", "2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"mapped IPv4", "::ffff:203.0.113.10", "203.0.113.10"},
		{"empty", "", ""},
		{"invalid", "unknown", ""},
		{"HTML suffix", "203.0.113.10<b>", ""},
		{"quoted value", `"203.0.113.10"`, ""},
		{"IPv4 port", "203.0.113.10:443", ""},
		{"IPv6 port", "[2001:db8::1]:443", ""},
		{"zone", "fe80::1%eth0", ""},
		{"CIDR", "203.0.113.0/24", ""},
		{"list", "203.0.113.10, 203.0.113.11", ""},
		{"spaces", " 203.0.113.10 ", ""},
		{"newline", "203.0.113.10\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := templateSourceIP(tc.ip); got != tc.want {
				t.Fatalf("templateSourceIP(%q) = %q, want %q", tc.ip, got, tc.want)
			}
		})
	}
}

func TestErrorPageTemplatesSourceIP(t *testing.T) {
	const reqUUID = "12345678-1234-1234-1234-123456789abc"
	const customTemplate = `uuid=[[.SAMWAF_REQ_UUID]] ip=[[.SAMWAF_IP]]`
	const legacyTemplate = `<p>legacy uuid=[[.SAMWAF_REQ_UUID]]</p>`
	inputs := []struct {
		name string
		ip   string
		want string
	}{
		{"IPv4", "203.0.113.10", "203.0.113.10"},
		{"IPv6", "2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"invalid", "203.0.113.10<b>", ""},
		{"empty", "", ""},
	}

	for _, entry := range []string{"request", "response", "backend"} {
		for _, mode := range []string{"default", "host", "global", "legacy"} {
			for _, input := range inputs {
				t.Run(entry+"/"+mode+"/"+input.name, func(t *testing.T) {
					hostSafe := &wafenginmodel.HostSafe{BlockingPage: map[string]model.BlockingPage{}}
					globalSafe := &wafenginmodel.HostSafe{BlockingPage: map[string]model.BlockingPage{}}
					content := customTemplate
					if mode == "default" {
						content = global.GLOBAL_DEFAULT_BLOCK_INFO
					} else if mode == "legacy" {
						content = legacyTemplate
					}
					configuredPage := model.BlockingPage{ResponseCode: "403", ResponseContent: content}
					if mode == "global" {
						globalSafe.BlockingPage["403"] = configuredPage
					} else if mode != "default" || entry == "backend" {
						hostSafe.BlockingPage["403"] = configuredPage
					}
					log := &innerbean.WebLog{REQ_UUID: reqUUID, SRC_IP: input.ip}
					var got string
					switch entry {
					case "request":
						r := httptest.NewRequest("GET", "http://example.test/", nil)
						r.RemoteAddr = "198.51.100.20:12345"
						r.Header.Set("X-Forwarded-For", "192.0.2.30")
						w := httptest.NewRecorder()
						code := EchoErrorInfo(w, r, log, "test", "blocked", hostSafe, globalSafe, false, "")
						if code != 403 || w.Code != 403 {
							t.Fatalf("unexpected status: returned=%d response=%d", code, w.Code)
						}
						got = w.Body.String()
					case "response":
						resp := newBackendResp(200, "200 OK", "text/plain", []byte("backend"))
						EchoResponseErrorInfo(resp, log, "test", "blocked", hostSafe, globalSafe, false, "")
						got = string(readBody(t, resp))
						if resp.StatusCode != 403 || resp.ContentLength != int64(len(got)) || resp.Header.Get("Content-Length") != strconv.Itoa(len(got)) {
							t.Fatalf("response metadata differs from rendered page: %+v", resp)
						}
					case "backend":
						resp := newBackendResp(403, "403 Forbidden", "text/html", nil)
						p := resolveCustomErrorPage(hostSafe, globalSafe, 403)
						if p == nil {
							t.Fatal("configured backend page not resolved")
						}
						result := applyCustomErrorPage(resp, p, 403, resp.Status, log.REQ_UUID, log.SRC_IP)
						if !result.TemplateApplied {
							t.Fatal("backend page not rendered")
						}
						got = string(readBody(t, resp))
						if resp.StatusCode != 403 || resp.ContentLength != int64(len(got)) || resp.Header.Get("Content-Length") != strconv.Itoa(len(got)) {
							t.Fatalf("backend response metadata differs from rendered page: %+v", resp)
						}
					}

					if mode == "legacy" {
						if want := "<p>legacy uuid=" + reqUUID + "</p>"; got != want {
							t.Fatalf("legacy template changed: got %q, want %q", got, want)
						}
					} else if mode == "default" {
						for _, want := range []string{
							"访问识别码：" + reqUUID,
							`<p class="source-ip">您的 IP：` + input.want + "</p>",
							"访问识别码和您的 IP 发给管理员",
							"overflow-wrap: anywhere;",
							"width: calc(100% - 32px);",
							"box-sizing: border-box;",
						} {
							if !strings.Contains(got, want) {
								t.Fatalf("default page missing %q", want)
							}
						}
						if strings.Index(got, "您的 IP：") < strings.Index(got, "访问识别码：") {
							t.Fatal("IP should appear below request UUID")
						}
					} else if want := "uuid=" + reqUUID + " ip=" + input.want; got != want {
						t.Fatalf("rendered page = %q, want %q", got, want)
					}
					if log.SRC_IP != input.ip {
						t.Fatalf("log source IP changed: %q", log.SRC_IP)
					}
				})
			}
		}
	}
}
