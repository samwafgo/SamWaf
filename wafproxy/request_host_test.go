package wafproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestCustomRequestHostAtOrigin(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Host+"|"+r.Header.Get("X-Config"))
	}))
	defer origin.Close()
	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, key, value, passDomain string
		visitors, want               []string
	}{
		{"default", "", "", "0", []string{"app.example.test:4432"}, []string{"app.example.test:4432"}},
		{"fixed host", "Host", "upstream.example.test", "0", []string{"app.example.test:4432"}, []string{"upstream.example.test"}},
		{"mixed case takes precedence", "hOsT", "upstream.example.test:8080", "1", []string{"app.example.test:4432"}, []string{"upstream.example.test:8080"}},
		{"original host with port", "Host", "${host}", "1", []string{"app.example.test:4432"}, []string{"app.example.test:4432"}},
		{"hostname on reused proxy", "Host", "${hostname}", "1", []string{"app.example.test:4432", "other.example.test:8443", "[2001:db8::1]:4432", "[2001:db8::2]", "other.example.test"}, []string{"app.example.test", "other.example.test", "[2001:db8::1]", "[2001:db8::2]", "other.example.test"}},
		{"empty uses backend domain", "Host", "", "1", []string{"app.example.test:4432"}, []string{target.Hostname()}},
		{"invalid uses backend domain", "Host", "https://upstream.example.test/path", "1", []string{"app.example.test:4432"}, []string{target.Hostname()}},
		{"invalid keeps visitor host", "Host", "upstream.example.test:65536", "0", []string{"app.example.test:4432"}, []string{"app.example.test:4432"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{"X-Config": "saved"}
			if tc.key != "" {
				headers[tc.key] = tc.value
			}
			proxy := NewSingleHostReverseProxyCustomHeader(target, headers, map[string]string{"IsTransBackDomain": tc.passDomain})
			for i, visitorHost := range tc.visitors {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Host = visitorHost
				recorder := httptest.NewRecorder()
				proxy.ServeHTTP(recorder, req)
				want := tc.want[i] + "|saved"
				if recorder.Code != http.StatusOK || recorder.Body.String() != want {
					t.Fatalf("Host %q: got status %d with %q, want 200 with %q", visitorHost, recorder.Code, recorder.Body.String(), want)
				}
				if req.Host != visitorHost {
					t.Fatalf("inbound Host changed to %q", req.Host)
				}
			}
		})
	}
}
