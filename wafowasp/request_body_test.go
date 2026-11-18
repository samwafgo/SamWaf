package wafowasp

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestProcessRequestBodyPreservesLargeUpload(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 33554432
`))
	if err != nil {
		t.Fatal(err)
	}
	w := &WafOWASP{WAF: waf}
	originalLimit := GetBodyInspectLimit()
	t.Cleanup(func() { SetBodyInspectLimit(int(originalLimit)) })
	body := bytes.Repeat([]byte("file data\n"), (14<<20)/10+1)
	wantHash := sha256.Sum256(body)

	for _, tc := range []struct {
		name       string
		configured int
		wantRead   int
	}{
		{"default budget", 0, maxRequestBodyBytes},
		{"configured budget", 32 << 10, 32 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SetBodyInspectLimit(tc.configured)
			source := bytes.NewReader(body)
			r := httptest.NewRequest(http.MethodPost, "/upload", source)
			originalLength := r.ContentLength
			tx := waf.NewTransaction()
			defer tx.Close()
			if err := w.processRequestBody(tx, r, nil); err != nil {
				t.Fatal(err)
			}

			h := sha256.New()
			n, err := io.Copy(h, r.Body)
			if err != nil || n != int64(len(body)) || !bytes.Equal(h.Sum(nil), wantHash[:]) || r.ContentLength != originalLength {
				t.Fatalf("replayed %d/%d bytes (hash %x), ContentLength=%d, err=%v", n, len(body), h.Sum(nil), r.ContentLength, err)
			}

			inspected, err := tx.RequestBodyReader()
			if err != nil {
				t.Fatal(err)
			}
			h.Reset()
			n, err = io.Copy(h, inspected)
			wantPrefixHash := sha256.Sum256(body[:tc.wantRead])
			if err != nil || n != int64(tc.wantRead) || !bytes.Equal(h.Sum(nil), wantPrefixHash[:]) {
				t.Fatalf("Coraza received %d/%d bytes (hash %x), err=%v", n, tc.wantRead, h.Sum(nil), err)
			}
		})
	}
}
