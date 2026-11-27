package ssl

import (
	"SamWaf/global"
	"SamWaf/model"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/registration"
)

const testACMECAPEM = "test-ca.pem"

func useACMETrust(t *testing.T, cert *x509.Certificate, directories ...string) string {
	t.Helper()
	previous := global.GACME_CONFIG
	global.GACME_CONFIG = global.DefaultACMEConfig()
	global.GACME_CONFIG.DirectoryMaxRetries = 0
	global.GACME_CONFIG.TrustedCAs = make(map[string]global.ACMETrustedCA)
	t.Cleanup(func() { global.GACME_CONFIG = previous })
	for _, directory := range directories {
		global.GACME_CONFIG.TrustedCAs[directory] = global.ACMETrustedCA{CAFile: testACMECAPEM}
	}
	t.Setenv("SamWafIDE", "1")
	t.Setenv("LEGO_CA_CERTIFICATES", "")
	t.Setenv("LEGO_CA_SERVER_NAME", "")
	base := t.TempDir()
	t.Chdir(base)
	caDir := filepath.Join(base, "conf", "acme-ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(caDir, testACMECAPEM)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestACMETrustedCAIsScopedToDirectoryAndOrigin(t *testing.T) {
	var extraRequests atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extraRequests.Add(1)
		writeTestACMEDirectory(w, r)
	}))
	defer other.Close()
	var requests atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/directory":
			writeTestACMEDirectory(w, r)
		case "/same-origin-redirect":
			http.Redirect(w, r, "/directory", http.StatusFound)
		case "/cross-origin-redirect":
			http.Redirect(w, r, other.URL+"/directory", http.StatusFound)
		case "/cross-origin-endpoint":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce": other.URL + "/nonce", "newAccount": "https://" + r.Host + "/new-account",
				"newOrder": "https://" + r.Host + "/new-order",
			})
		case "/new-nonce":
			w.Header().Set("Replay-Nonce", "test-nonce")
			w.WriteHeader(http.StatusNoContent)
		case "/new-account":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:serverInternal","detail":"test account request"}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer s.Close()
	path := useACMETrust(t, s.Certificate(), s.URL+"/directory", s.URL+"/same-origin-redirect", s.URL+"/cross-origin-redirect", s.URL+"/cross-origin-endpoint")
	user := testACMEConfig(t, s).User.(*MyUser)
	for _, path := range []string{"/directory", "/same-origin-redirect"} {
		client, err := newACMEClient(t.Context(), user, " "+s.URL+path+" ", false)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		var problem *acme.ProblemDetails
		if !errors.As(err, &problem) || problem.HTTPStatus != http.StatusServiceUnavailable {
			t.Fatalf("want the response from the original CA's account endpoint, got %v", err)
		}
	}
	for _, address := range []string{s.URL + "/other-dir", other.URL + "/directory"} {
		if _, err := newACMEClient(t.Context(), user, address, false); err == nil || !strings.Contains(err.Error(), "TLS") {
			t.Fatalf("unconfigured CA must not use the private root: %v", err)
		}
	}
	if _, err := newACMEClient(t.Context(), user, s.URL+"/cross-origin-redirect", false); err == nil || !strings.Contains(err.Error(), "同源") {
		t.Fatalf("unexpected cross-origin redirect result: %v", err)
	}
	client, err := newACMEClient(t.Context(), user, s.URL+"/cross-origin-endpoint", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true}); err == nil || !strings.Contains(err.Error(), "同源") {
		t.Fatalf("unexpected cross-origin endpoint result: %v", err)
	}
	if extraRequests.Load() != 0 {
		t.Fatal("cross-origin server received an ACME request")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	before := requests.Load()
	if _, err := newACMEClient(t.Context(), user, s.URL+"/directory", false); err == nil || !strings.Contains(err.Error(), "不存在或不可访问") || requests.Load() != before {
		t.Fatalf("missing PEM must fail before a request: %v", err)
	}
}

func TestACMETrustedCAInOrders(t *testing.T) {
	var requests atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer s.Close()
	directory := s.URL + "/directory"
	useACMETrust(t, s.Certificate(), directory)
	t.Setenv("LEGO_CA_CERTIFICATES", filepath.Join(t.TempDir(), "missing.pem"))
	t.Setenv("LEGO_CA_SERVER_NAME", "legacy-name.example.test")
	order := model.SslOrder{ApplyDomain: "example.test", ApplyMethod: "http01"}
	for _, tt := range []struct {
		name string
		run  func(context.Context, model.SslOrder, string, string, string, string, string) (model.SslOrder, error)
	}{
		{"apply", RegistrationSSL}, {"renew", ReNewSSL},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.run(t.Context(), order, t.TempDir(), directory, "pebble", "", ""); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
				t.Fatalf("wanted the CA response without legacy PEM env: %v", err)
			}
		})
	}
	if requests.Load() != 2 {
		t.Fatalf("got %d CA requests, want one per order", requests.Load())
	}
}

func TestACMETrustedCARequiresMatchingHostname(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(writeTestACMEDirectory))
	defer s.Close()
	useACMETrust(t, s.Certificate())
	roots, err := loadACMECAFile(".", testACMECAPEM)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := url.Parse("https://wrong.example.test/directory")
	if err != nil {
		t.Fatal(err)
	}
	config := newTrustedACMEConfig(testACMEConfig(t, s).User.(*MyUser), roots)
	config.CADirURL = alias.String()
	transport := config.HTTPClient.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("custom CA must use a direct connection")
	}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
	}
	if _, err := openACMEClient(t.Context(), alias, config, time.Second, 0, waitACMERetry); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("invalid TLS hostname was not rejected: %v", err)
	}
}

func TestACMETrustedCAOriginComparison(t *testing.T) {
	for _, tt := range []struct {
		allowed, target string
		match           bool
	}{
		{"https://ACME.example.test", "https://acme.example.test:443", true},
		{"https://bücher.example.test", "https://xn--bcher-kva.example.test", true},
		{"https://σ.example.test", "https://ς.example.test", false},
		{"https://[0:0:0:0:0:0:0:1]", "https://[::1]:443", true},
		{"https://127.0.0.1:14000", "https://127.0.0.1:14001", false},
	} {
		allowed, err := url.Parse(tt.allowed)
		if err != nil {
			t.Fatal(err)
		}
		target, err := url.Parse(tt.target)
		if err != nil {
			t.Fatal(err)
		}
		if got := sameACMEOrigin(allowed, target); got != tt.match {
			t.Errorf("origin match for %s and %s = %t, want %t", tt.allowed, tt.target, got, tt.match)
		}
	}
}

func TestLoadACMECAFile(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	validPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	if _, err := parseACMECARoots([]byte(validPEM + validPEM)); err != nil {
		t.Fatalf("valid CA bundle: %v", err)
	}
	base := t.TempDir()
	store := filepath.Join(base, "conf", "acme-ca")
	if err := os.MkdirAll(store, 0700); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, contents, wantError string
	}{
		{"invalid.pem", "not a certificate", "PEM"},
		{"empty.pem", "", "为空"},
		{"big.pem", strings.Repeat("a", maxACMECAPEMBytes+1), "超过"},
		{"bad.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0}})), "无法解析"},
		{"mixed.pem", "-----BEGIN CERTIFICATE-----\ninvalid base64!\n-----END CERTIFICATE-----\n" + validPEM, "无效"},
	} {
		if err := os.WriteFile(filepath.Join(store, tt.name), []byte(tt.contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadACMECAFile(base, tt.name); err == nil || !strings.Contains(err.Error(), tt.wantError) {
			t.Fatalf("%s: unexpected error %v", tt.name, err)
		}
	}
	if err := os.Mkdir(filepath.Join(store, "folder.pem"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadACMECAFile(base, "folder.pem"); err == nil || !strings.Contains(err.Error(), "普通文件") {
		t.Fatalf("directory not rejected: %v", err)
	}
}

func TestLoadACMECAFileRejectsLinkedDirectory(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "conf"), 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "conf", "acme-ca")
	target := t.TempDir()
	if runtime.GOOS == "windows" {
		if output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Skipf("cannot create a junction: %v %s", err, output)
		}
	} else if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symbolic link: %v", err)
	}
	if _, err := loadACMECAFile(base, testACMECAPEM); err == nil || !strings.Contains(err.Error(), "普通目录") {
		t.Fatalf("linked directory not rejected: %v", err)
	}
}
