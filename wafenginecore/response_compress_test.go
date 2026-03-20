package wafenginecore

import (
	"SamWaf/model"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestChooseCompressEncoding(t *testing.T) {
	if chooseCompressEncoding("gzip, deflate", "br_first") != "gzip" {
		t.Fatal("expected gzip")
	}
	if chooseCompressEncoding("br, gzip", "br_first") != "br" {
		t.Fatal("expected br")
	}
	if chooseCompressEncoding("gzip, deflate", "gzip_only") != "gzip" {
		t.Fatal("expected gzip_only")
	}
	if chooseCompressEncoding("gzip, deflate", "br_only") != "" {
		t.Fatal("br_only should not pick gzip")
	}
	if chooseCompressEncoding("", "gzip_only") != "" {
		t.Fatal("empty accept should not compress")
	}
}

func TestMaybeApplyResponseCompress_SkipsWhenAlreadyEncoded(t *testing.T) {
	waf := &WafEngine{}
	req, _ := http.NewRequest("GET", "/a.html", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}, "Content-Encoding": []string{"gzip"}},
		Request:    req,
	}
	body := []byte(strings.Repeat("x", 300))
	out := waf.maybeApplyResponseCompress(req, resp, body, model.ResponseCompressConfig{IsEnable: 1, Prefer: "gzip_only", MinLength: 10})
	if !bytes.Equal(out, body) {
		t.Fatal("should pass through when already encoded")
	}
}

func TestMaybeApplyResponseCompress_GzipWhenUnencoded(t *testing.T) {
	waf := &WafEngine{}
	req, _ := http.NewRequest("GET", "/page.html", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Request:    req,
	}
	plain := []byte(strings.Repeat("hello world ", 40))
	cfg := model.ResponseCompressConfig{IsEnable: 1, Prefer: "gzip_only", MinLength: 50}
	out := waf.maybeApplyResponseCompress(req, resp, plain, cfg)
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected Content-Encoding gzip, got %q", resp.Header.Get("Content-Encoding"))
	}
	r, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestMaybeApplyResponseCompress_MinLength(t *testing.T) {
	waf := &WafEngine{}
	req, _ := http.NewRequest("GET", "/a.html", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}, Request: req}
	small := []byte("short")
	out := waf.maybeApplyResponseCompress(req, resp, small, model.ResponseCompressConfig{IsEnable: 1, Prefer: "gzip_only", MinLength: 256})
	if !bytes.Equal(out, small) || resp.Header.Get("Content-Encoding") != "" {
		t.Fatal("should skip small body")
	}
}

func TestMaybeApplyResponseCompress_ExcludeExt(t *testing.T) {
	waf := &WafEngine{}
	req, _ := http.NewRequest("GET", "/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/javascript"}},
		Request:    req,
	}
	body := []byte(strings.Repeat("x", 300))
	cfg := model.ResponseCompressConfig{IsEnable: 1, Prefer: "gzip_only", MinLength: 10, ExcludeExtensions: ".js"}
	out := waf.maybeApplyResponseCompress(req, resp, body, cfg)
	if !bytes.Equal(out, body) || resp.Header.Get("Content-Encoding") != "" {
		t.Fatal("should exclude .js")
	}
}

func TestMimeMatchesIncludeList_Default(t *testing.T) {
	if !mimeMatchesIncludeList("text/html", "") {
		t.Fatal("text/html should match default")
	}
	if mimeMatchesIncludeList("application/octet-stream", "") {
		t.Fatal("octet-stream should not match default")
	}
}
