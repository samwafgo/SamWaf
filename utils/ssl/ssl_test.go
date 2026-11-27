package ssl

import (
	"SamWaf/global"
	"SamWaf/model"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestACMEDirectoryRetryInOrders(t *testing.T) {
	settings := global.GACME_CONFIG
	global.GACME_CONFIG.DirectoryMaxRetries = 1
	t.Cleanup(func() { global.GACME_CONFIG = settings })
	for _, tt := range []struct {
		name string
		run  func(context.Context, model.SslOrder, string, string, string, string, string) (model.SslOrder, error)
	}{
		{"apply", RegistrationSSL},
		{"renew", ReNewSSL},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/directory" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				if attempts.Add(1) == 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
				} else {
					w.WriteHeader(http.StatusForbidden)
				}
			}))
			defer s.Close()
			dir := t.TempDir()
			certPath := filepath.Join(dir, "test-ca.pem")
			if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("LEGO_CA_CERTIFICATES", certPath)
			t.Setenv("LEGO_CA_SYSTEM_CERT_POOL", "false")
			t.Setenv("LEGO_CA_SERVER_NAME", "")
			_, err := tt.run(t.Context(), model.SslOrder{ApplyDomain: "example.test", ApplyMethod: "http01"}, dir, s.URL+"/directory", "letsencrypt", "", "")
			if err == nil || !strings.Contains(err.Error(), "HTTP 403") || attempts.Load() != 2 {
				t.Fatalf("attempts=%d, err=%v, want two attempts and HTTP 403", attempts.Load(), err)
			}
		})
	}
}
