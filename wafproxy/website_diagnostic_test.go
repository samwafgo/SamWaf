package wafproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

type diagnosticCaptureTransport func(*http.Request) (*http.Response, error)

func (f diagnosticCaptureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestWebsiteDiagnosticBuilderMatchesProxy(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		backDomain   string
		custom       map[string]string
	}{
		{"host and escaped path", "https://origin.test:9443/base?source=1", "1", map[string]string{"X-Config": "saved", "X-Remove": "", "X-Forwarded-For": "192.0.2.1"}},
		{"host without port", "http://origin.test/base", "1", nil},
		{"preserve host", "http://origin.test:8080/", "0", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("HEAD", "https://visitor.test/api/a%2Fb?q=2", nil)
			req.RemoteAddr = ""
			req.Header = http.Header{"X-Config": {"input"}, "X-Remove": {"remove"}, "Connection": {"X-Hop"}, "X-Hop": {"remove"}, "Te": {"trailers"}}
			before := req.Clone(req.Context())
			target, err := url.Parse(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			config := map[string]string{"IsTransBackDomain": tc.backDomain}
			planned := BuildDiagnosticRequest(req, target, tc.custom, config)
			proxy := NewSingleHostReverseProxyCustomHeader(target, tc.custom, config)
			var actual *http.Request
			proxy.Transport = diagnosticCaptureTransport(func(out *http.Request) (*http.Response, error) {
				actual = out.Clone(out.Context())
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
			})
			proxy.ServeHTTP(httptest.NewRecorder(), req)
			if actual == nil {
				t.Fatal("proxy did not construct an outgoing request")
			}
			if actual.URL.String() != planned.URL.String() || actual.Host != planned.Host || !reflect.DeepEqual(actual.Header, planned.Header) {
				t.Fatalf("planned %s host=%s headers=%v; actual %s host=%s headers=%v", planned.URL, planned.Host, planned.Header, actual.URL, actual.Host, actual.Header)
			}
			if !reflect.DeepEqual(req.Header, before.Header) || req.URL.String() != before.URL.String() || req.Host != before.Host {
				t.Fatal("request builder changed caller request")
			}
		})
	}
}
