package wafenginecore

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafowasp"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

func TestLargeMultipartUploadProxy(t *testing.T) {
	queues := newNotifyClassificationQueues(t)
	oldDesensitize := global.GCONFIG_RECORD_LOG_DESENSITIZE
	t.Cleanup(func() { global.GCONFIG_RECORD_LOG_DESENSITIZE = oldDesensitize })
	global.GCONFIG_RECORD_LOG_DESENSITIZE = 0

	const fileSize = 14 << 20
	const fileName = "report.txt"
	const uploadConfig = `{"is_enable":1,"check_size":1,"max_size_kb":10240,"over_limit_action":"pass"}`
	const phase2RuleID = 1074
	var phase2Runs atomic.Int32
	root := filepath.Join("..", "cmd", "samwaf", "exedata", "owasp")
	cfg := coraza.NewWAFConfig().
		WithDirectivesFromFile(filepath.Join(root, "coraza.conf")).
		WithDirectivesFromFile(filepath.Join(root, "coreruleset", "crs-setup.conf")).
		WithDirectivesFromFile(filepath.Join(root, "coreruleset", "rules", "*.conf")).
		WithDirectives(`SecAction "id:1074,phase:2,pass,log,msg:'Multipart upload test'"`).
		WithErrorCallback(func(rule types.MatchedRule) {
			if rule.Rule().ID() == phase2RuleID {
				phase2Runs.Add(1)
			}
		})
	defaultEngine, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tunedEngine, err := coraza.NewWAF(cfg.WithDirectives("SecRequestBodyLimit 33554432"))
	if err != nil {
		t.Fatal(err)
	}
	oldOWASP, oldManager := global.GWAF_OWASP, global.GWAF_OWASP_MANAGER
	oldLimit := wafowasp.GetBodyInspectLimit()
	t.Cleanup(func() {
		global.GWAF_OWASP, global.GWAF_OWASP_MANAGER = oldOWASP, oldManager
		wafowasp.SetBodyInspectLimit(int(oldLimit))
	})
	global.GWAF_OWASP_MANAGER = nil
	wafowasp.SetBodyInspectLimit(0)

	file := bytes.Repeat([]byte("0123456789abcde\n"), fileSize/16)
	wantSHA := sha256.Sum256(file)
	body, contentType := buildMultipart(t, "file", fileName, "application/octet-stream", file)
	raw := body.Bytes()

	for _, mode := range []struct {
		name       string
		engine     coraza.WAF
		wantStatus int
		wantPhase2 int32
	}{
		{name: "upload_pass", wantStatus: http.StatusNoContent},
		{name: "owasp_and_upload_pass", engine: tunedEngine, wantStatus: http.StatusNoContent, wantPhase2: 1},
		{name: "owasp_default_limit", engine: defaultEngine, wantStatus: http.StatusForbidden},
	} {
		for _, chunked := range []bool{false, true} {
			framing := "fixed_length"
			if chunked {
				framing = "chunked"
			}
			t.Run(mode.name+"/"+framing, func(t *testing.T) {
				var originHits atomic.Int32
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					originHits.Add(1)
					if err := verifyLargeMultipartOrigin(r, int64(len(raw)), fileSize, fileName, wantSHA, chunked); err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				defer origin.Close()

				var enabled int
				global.GWAF_OWASP = nil
				if mode.engine != nil {
					enabled = 1
					global.GWAF_OWASP = &wafowasp.WafOWASP{IsActive: true, WAF: mode.engine}
				}
				waf := newNotifyClassificationEngine(t, model.HostsDefense{DEFENSE_OWASP_SET: enabled})
				waf.UpdateHost(notifyClassificationHostCode, func(h *wafenginmodel.HostSafe) {
					h.PathRules = nil
					h.TargetHost = origin.URL
					h.Host.UploadSecurityJSON = uploadConfig
				})
				front := httptest.NewServer(waf)
				defer front.Close()
				client := front.Client()
				client.Timeout = 15 * time.Second

				var reader io.Reader = bytes.NewReader(raw)
				if chunked {
					// Hide the reader's length so the client uses HTTP/1.1 chunked framing.
					reader = io.NopCloser(reader)
				}
				req, err := http.NewRequest(http.MethodPost, front.URL+"/upload", reader)
				if err != nil {
					t.Fatal(err)
				}
				req.Host = waf.rt().HostTarget[waf.rt().HostCode[notifyClassificationHostCode]].Host.Host
				req.Header.Set("Content-Type", contentType)

				before := phase2Runs.Load()
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != mode.wantStatus {
					detail, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
					t.Fatalf("upload response status = %d, want %d, response = %q", resp.StatusCode, mode.wantStatus, detail)
				}
				if got := phase2Runs.Load() - before; got != mode.wantPhase2 {
					t.Errorf("Coraza request-body phase ran %d times, want %d", got, mode.wantPhase2)
				}
				if mode.wantStatus == http.StatusForbidden {
					queues.expected++
					if originHits.Load() != 0 {
						t.Error("rejected upload reached the origin")
					}
				}
			})
		}
	}
}

func TestOwaspUploadBodyLimitHotReload(t *testing.T) {
	queues := newNotifyClassificationQueues(t)
	oldDesensitize := global.GCONFIG_RECORD_LOG_DESENSITIZE
	t.Cleanup(func() { global.GCONFIG_RECORD_LOG_DESENSITIZE = oldDesensitize })
	global.GCONFIG_RECORD_LOG_DESENSITIZE = 0

	oldOWASP, oldManager := global.GWAF_OWASP, global.GWAF_OWASP_MANAGER
	oldMode, oldLimit := wafowasp.GetEngineMode(), wafowasp.GetBodyInspectLimit()
	t.Cleanup(func() {
		global.GWAF_OWASP, global.GWAF_OWASP_MANAGER = oldOWASP, oldManager
		wafowasp.SetEngineMode(oldMode)
		wafowasp.SetBodyInspectLimit(int(oldLimit))
	})

	dir := t.TempDir()
	assets := filepath.Join("..", "cmd", "samwaf", "exedata", "owasp")
	if err := os.CopyFS(filepath.Join(dir, "data", "owasp"), os.DirFS(assets)); err != nil {
		t.Fatal(err)
	}
	manager := wafowasp.NewOwaspManager(dir)
	if manager.Current() == nil {
		t.Fatal("OWASP manager failed to load bundled rules")
	}
	global.GWAF_OWASP = nil
	global.GWAF_OWASP_MANAGER = manager

	const fileName = "report.txt"
	file := bytes.Repeat([]byte("0123456789abcde\n"), (14<<20)/16)
	body, contentType := buildMultipart(t, "file", fileName, "application/octet-stream", file)
	raw, checksum := body.Bytes(), sha256.Sum256(file)
	var originHits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		if err := verifyLargeMultipartOrigin(r, int64(len(raw)), int64(len(file)), fileName, checksum, false); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	waf := newNotifyClassificationEngine(t, model.HostsDefense{DEFENSE_OWASP_SET: 1})
	waf.UpdateHost(notifyClassificationHostCode, func(h *wafenginmodel.HostSafe) {
		h.PathRules = nil
		h.TargetHost = origin.URL
	})
	front := httptest.NewServer(waf)
	defer front.Close()
	client := front.Client()
	client.Timeout = 15 * time.Second
	tuning := wafowasp.DefaultTuning()
	tuning.RuleEngine = "On"

	for _, tc := range []struct {
		name       string
		limit      int
		wantStatus int
	}{
		{"raise_limit", 32 << 20, http.StatusNoContent},
		{"lower_limit", 8 << 20, http.StatusForbidden},
		{"raise_limit_again", 32 << 20, http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tuning.RequestBodyLimit = tc.limit
			if err := manager.ApplyTuning(tuning); err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodPost, front.URL+"/upload", bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			req.Host = waf.rt().HostTarget[waf.rt().HostCode[notifyClassificationHostCode]].Host.Host
			req.Header.Set("Content-Type", contentType)
			before := originHits.Load()
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				detail, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				t.Fatalf("limit=%d status=%d, want %d, response=%q", tc.limit, resp.StatusCode, tc.wantStatus, detail)
			}
			if tc.wantStatus == http.StatusForbidden {
				queues.expected++
				if originHits.Load() != before {
					t.Error("rejected upload reached the origin")
				}
			}
		})
	}
}

func verifyLargeMultipartOrigin(r *http.Request, wantBodyLen, wantFileLen int64, fileName string, wantSHA [sha256.Size]byte, chunked bool) error {
	if chunked {
		if r.ContentLength != -1 || !slices.Contains(r.TransferEncoding, "chunked") {
			return fmt.Errorf("origin framing = length %d, encoding %v, want chunked", r.ContentLength, r.TransferEncoding)
		}
	} else if r.ContentLength != wantBodyLen {
		return fmt.Errorf("origin Content-Length = %d, want %d", r.ContentLength, wantBodyLen)
	}
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return err
	}
	body := &io.LimitedReader{R: r.Body, N: wantBodyLen + 1}
	form := multipart.NewReader(body, params["boundary"])
	part, err := form.NextPart()
	if err != nil {
		return fmt.Errorf("read file part: %w", err)
	}
	if part.FormName() != "file" || part.FileName() != fileName {
		return fmt.Errorf("origin part = %q/%q, want file/%s", part.FormName(), part.FileName(), fileName)
	}
	hash := sha256.New()
	n, err := io.Copy(hash, part)
	if err != nil {
		return fmt.Errorf("read file after %d bytes: %w", n, err)
	}
	if n != wantFileLen || !bytes.Equal(hash.Sum(nil), wantSHA[:]) {
		return fmt.Errorf("origin file = %d bytes, SHA-256 %x, want %d bytes, SHA-256 %x", n, hash.Sum(nil), wantFileLen, wantSHA)
	}
	if _, err := form.NextPart(); err != io.EOF {
		return fmt.Errorf("end of multipart form: got %v, want EOF", err)
	}
	if _, err := io.Copy(io.Discard, body); err != nil {
		return fmt.Errorf("read remaining body: %w", err)
	}
	if n := wantBodyLen + 1 - body.N; n != wantBodyLen {
		return fmt.Errorf("origin body = %d bytes, want %d", n, wantBodyLen)
	}
	return nil
}
