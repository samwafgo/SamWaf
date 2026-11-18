package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafproxy"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func configureBackendUnavailablePage(waf *WafEngine, content string) {
	waf.withWriteTable(func(rt *routingTable) {
		rt.HostTarget[global.GWAF_GLOBAL_HOST_NAME] = &wafenginmodel.HostSafe{
			BlockingPage: map[string]model.BlockingPage{
				model.BlockingPageTypeBackendUnavailable: {
					BlockingType:    model.BlockingPageTypeBackendUnavailable,
					ResponseContent: content,
					ResponseHeader:  `[{"name":"Retry-After","value":"30"},{"name":"Content-Length","value":"1"}]`,
				},
			},
		}
	})
}

func TestBackendUnavailableResponseStatuses(t *testing.T) {
	waf := &WafEngine{}
	waf.InitRouting()
	configureBackendUnavailablePage(waf, `<p>[[.SAMWAF_HOST]] [[.SAMWAF_STATUS_CODE]]</p>`)
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"origin error", errors.New("connection refused"), http.StatusServiceUnavailable},
		{"origin EOF", io.EOF, http.StatusBadGateway},
		{"origin timeout", context.DeadlineExceeded, http.StatusGatewayTimeout},
		{"client canceled", context.Canceled, 499},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			weblog := &innerbean.WebLog{HOST: `<visitor>:8080`}
			r = r.WithContext(context.WithValue(r.Context(), "waf_context", innerbean.WafHttpContextData{Weblog: weblog}))
			w := httptest.NewRecorder()
			waf.errorResponse()(w, r, tc.err)
			if w.Code != tc.status || weblog.STATUS_CODE != tc.status {
				t.Fatalf("response status %d, log status %d, want %d", w.Code, weblog.STATUS_CODE, tc.status)
			}
			if tc.status == 499 {
				if w.Body.String() != global.GLOBAL_DEFAULT_BACKEND_UNAVAILABLE || w.Header().Get("Retry-After") != "" {
					t.Fatalf("unexpected cancellation response: %s %v", w.Body.String(), w.Header())
				}
				return
			}
			want := "<p>&lt;visitor&gt;:8080 " + strconv.Itoa(tc.status) + "</p>"
			if w.Body.String() != want || w.Header().Get("Retry-After") != "30" || w.Header().Get("Content-Length") != "" {
				t.Fatalf("response body %q, want %q, headers %v", w.Body.String(), want, w.Header())
			}
		})
	}
}

func TestBackendUnavailableResponseFallback(t *testing.T) {
	waf := &WafEngine{}
	waf.InitRouting()
	for _, content := range []string{"", "  ", `[[.UNKNOWN]]`} {
		configureBackendUnavailablePage(waf, content)
		r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		w := httptest.NewRecorder()
		waf.errorResponse()(w, r, io.EOF)
		if w.Code != http.StatusBadGateway || w.Body.String() != global.GLOBAL_DEFAULT_BACKEND_UNAVAILABLE || w.Header().Get("Retry-After") != "" {
			t.Fatalf("fallback for %q, got %d %q %v", content, w.Code, w.Body.String(), w.Header())
		}
	}
	r := httptest.NewRequest(http.MethodHead, "http://example.test/", nil)
	w := httptest.NewRecorder()
	waf.errorResponse()(w, r, io.EOF)
	if w.Code != http.StatusBadGateway || w.Body.Len() != 0 {
		t.Fatalf("HEAD returned %d %q", w.Code, w.Body.String())
	}
}

func TestBackendUnavailableResponseOriginStatusIsolation(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "origin response")
	}))
	defer backend.Close()
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	waf := &WafEngine{}
	waf.InitRouting()
	configureBackendUnavailablePage(waf, "custom proxy error")
	proxy := wafproxy.NewSingleHostReverseProxyCustomHeader(target, nil, nil)
	proxy.ErrorHandler = waf.errorResponse()
	proxy.ModifyResponse = waf.modifyResponse()
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))
	if w.Code != http.StatusServiceUnavailable || w.Body.String() != "origin response" {
		t.Fatalf("origin response: got %d %q", w.Code, w.Body.String())
	}
	backend.Close()
	w = httptest.NewRecorder()
	proxy.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))
	if w.Code != http.StatusServiceUnavailable || w.Body.String() != "custom proxy error" {
		t.Fatalf("proxy failure: got %d %q", w.Code, w.Body.String())
	}
	waf.UpdateHostByKey(global.GWAF_GLOBAL_HOST_NAME, func(host *wafenginmodel.HostSafe) {
		host.BlockingPage = nil
	})
	w = httptest.NewRecorder()
	proxy.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))
	if w.Code != http.StatusServiceUnavailable || w.Body.String() != global.GLOBAL_DEFAULT_BACKEND_UNAVAILABLE {
		t.Fatalf("after config reload: got %d %q", w.Code, w.Body.String())
	}
}
