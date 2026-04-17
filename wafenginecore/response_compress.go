package wafenginecore

import (
	"SamWaf/model"
	"SamWaf/utils"
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// maybeApplyResponseCompress 在上游未设置 Content-Encoding 时，按站点配置与 Accept-Encoding 压缩响应体。
// 若已存在 Content-Encoding（含经 compressContent 按上游格式重压的情况），则不处理。
func (waf *WafEngine) maybeApplyResponseCompress(req *http.Request, resp *http.Response, body []byte, cfg model.ResponseCompressConfig) []byte {
	if cfg.IsEnable != 1 || len(body) == 0 {
		return body
	}
	if ce := strings.TrimSpace(resp.Header.Get("Content-Encoding")); ce != "" {
		return body
	}
	if resp.StatusCode != http.StatusOK {
		return body
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Cache-Control")), "no-transform") {
		return body
	}
	minLen := cfg.MinLength
	if minLen <= 0 {
		minLen = 256
	}
	if len(body) < minLen {
		return body
	}
	if req == nil {
		return body
	}
	urlPath := req.URL.Path
	if matchResponseCompressExcludePath(urlPath, cfg.ExcludePaths) {
		return body
	}
	if ext := pathExtensionLower(urlPath); ext != "" && matchResponseCompressExcludeExt(ext, cfg.ExcludeExtensions) {
		return body
	}
	if !responseCompressTypeOrExtMatches(resp.Header.Get("Content-Type"), urlPath, cfg) {
		return body
	}
	enc := chooseCompressEncoding(req.Header.Get("Accept-Encoding"), cfg.Prefer)
	if enc == "" {
		return body
	}
	var out []byte
	var err error
	switch enc {
	case "br":
		out, err = utils.BrotliEncode(body)
	case "gzip":
		out, err = utils.GZipEncode(body)
	case "zstd":
		out, err = utils.ZstdEncode(body)
	default:
		return body
	}
	if err != nil || len(out) >= len(body) {
		return body
	}
	resp.Header.Set("Content-Encoding", enc)
	appendVaryAcceptEncoding(resp.Header)
	return out
}

// maybeCompressStaticAssistResponse 对静态协助类响应读体后尝试压缩（需配置 compress_when_static_assist）。
func (waf *WafEngine) maybeCompressStaticAssistResponse(req *http.Request, resp *http.Response, cfg model.ResponseCompressConfig) {
	if cfg.IsEnable != 1 || cfg.CompressWhenStaticAssist != 1 {
		return
	}
	if resp == nil || req == nil || resp.Body == nil || resp.Body == http.NoBody {
		return
	}
	if strings.TrimSpace(resp.Header.Get("Content-Encoding")) != "" {
		return
	}
	if resp.Header.Get("Accept-Ranges") == "bytes" {
		return
	}
	if resp.StatusCode != http.StatusOK {
		return
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Cache-Control")), "no-transform") {
		return
	}
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return
	}
	if len(raw) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return
	}
	minLen := cfg.MinLength
	if minLen <= 0 {
		minLen = 256
	}
	if len(raw) < minLen {
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(raw)), 10))
		return
	}
	urlPath := req.URL.Path
	if matchResponseCompressExcludePath(urlPath, cfg.ExcludePaths) {
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(raw)), 10))
		return
	}
	if ext := pathExtensionLower(urlPath); ext != "" && matchResponseCompressExcludeExt(ext, cfg.ExcludeExtensions) {
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(raw)), 10))
		return
	}
	if !responseCompressTypeOrExtMatches(resp.Header.Get("Content-Type"), urlPath, cfg) {
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(raw)), 10))
		return
	}
	enc := chooseCompressEncoding(req.Header.Get("Accept-Encoding"), cfg.Prefer)
	if enc == "" {
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(raw)), 10))
		return
	}
	var out []byte
	switch enc {
	case "br":
		out, err = utils.BrotliEncode(raw)
	case "gzip":
		out, err = utils.GZipEncode(raw)
	case "zstd":
		out, err = utils.ZstdEncode(raw)
	default:
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(raw)), 10))
		return
	}
	if err != nil || len(out) >= len(raw) {
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(raw)), 10))
		return
	}
	resp.Header.Set("Content-Encoding", enc)
	appendVaryAcceptEncoding(resp.Header)
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(out)), 10))
	resp.Body = io.NopCloser(bytes.NewReader(out))
}

func appendVaryAcceptEncoding(h http.Header) {
	v := h.Get("Vary")
	if v == "" {
		h.Set("Vary", "Accept-Encoding")
		return
	}
	lower := strings.ToLower(v)
	if strings.Contains(lower, "accept-encoding") {
		return
	}
	h.Set("Vary", v+", Accept-Encoding")
}

func chooseCompressEncoding(acceptEncoding, prefer string) string {
	ae := strings.ToLower(acceptEncoding)
	switch strings.ToLower(strings.TrimSpace(prefer)) {
	case "gzip_only":
		if acceptEncodingSupportsGzip(ae) {
			return "gzip"
		}
		return ""
	case "br_only":
		if strings.Contains(ae, "br") {
			return "br"
		}
		return ""
	case "zstd_only":
		if strings.Contains(ae, "zstd") {
			return "zstd"
		}
		return ""
	case "zstd_first":
		if strings.Contains(ae, "zstd") {
			return "zstd"
		}
		if strings.Contains(ae, "br") {
			return "br"
		}
		if acceptEncodingSupportsGzip(ae) {
			return "gzip"
		}
		return ""
	default: // br_first
		if strings.Contains(ae, "br") {
			return "br"
		}
		if acceptEncodingSupportsGzip(ae) {
			return "gzip"
		}
		if strings.Contains(ae, "zstd") {
			return "zstd"
		}
		return ""
	}
}

func acceptEncodingSupportsGzip(ae string) bool {
	if ae == "" {
		return false
	}
	return strings.Contains(ae, "gzip") || strings.Contains(ae, "x-gzip")
}

func stripMIMECharset(ct string) string {
	ct = strings.TrimSpace(ct)
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return strings.ToLower(ct)
}

func responseCompressTypeOrExtMatches(contentType, urlPath string, cfg model.ResponseCompressConfig) bool {
	ct := stripMIMECharset(contentType)
	typeMatch := mimeMatchesIncludeList(ct, cfg.IncludeTypes)
	extMatch := pathMatchesIncludeExtensions(urlPath, cfg.IncludeExtensions)
	if strings.TrimSpace(cfg.IncludeExtensions) != "" {
		return typeMatch || extMatch
	}
	return typeMatch
}

func mimeMatchesIncludeList(ct string, includeTypes string) bool {
	types := splitResponseCompressDelimited(includeTypes)
	if len(types) == 0 {
		for _, def := range model.DefaultResponseCompressMimeTypes() {
			if ct == strings.ToLower(def) {
				return true
			}
		}
		return false
	}
	for _, t := range types {
		t = strings.TrimSpace(strings.ToLower(t))
		if t == "" {
			continue
		}
		if ct == t || strings.HasPrefix(ct, t) {
			return true
		}
	}
	return false
}

func pathMatchesIncludeExtensions(urlPath string, includeExt string) bool {
	parts := splitResponseCompressDelimited(includeExt)
	if len(parts) == 0 {
		return false
	}
	ext := pathExtensionLower(urlPath)
	if ext == "" {
		return false
	}
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, ".") {
			p = "." + p
		}
		if ext == p {
			return true
		}
	}
	return false
}

func pathExtensionLower(path string) string {
	path = strings.ToLower(path)
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i:]
	}
	if i := strings.LastIndex(path, "."); i >= 0 && i < len(path)-1 {
		return path[i:]
	}
	return ""
}

func matchResponseCompressExcludeExt(ext string, exclude string) bool {
	ext = strings.ToLower(strings.TrimSpace(ext))
	for _, p := range splitResponseCompressDelimited(exclude) {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, ".") {
			p = "." + p
		}
		if ext == p {
			return true
		}
	}
	return false
}

func matchResponseCompressExcludePath(urlPath string, excludePaths string) bool {
	urlPath = strings.ToLower(urlPath)
	for _, line := range strings.Split(excludePaths, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, p := range strings.Split(line, ";") {
			p = strings.TrimSpace(strings.ToLower(p))
			if p == "" {
				continue
			}
			if strings.HasPrefix(urlPath, p) {
				return true
			}
		}
	}
	return false
}

func splitResponseCompressDelimited(s string) []string {
	s = strings.ReplaceAll(s, "\n", ";")
	var out []string
	for _, p := range strings.Split(s, ";") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
