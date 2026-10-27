package wafdiagnose

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const redacted = "[redacted]"

var privateInputPattern = regexp.MustCompile(`(?is)<input\b[^>]*(?:type\s*=\s*["']?password|name\s*=\s*["']?(?:password|passwd|pwd|secret|token|csrf|api[_-]?key|authorization|credential|access[_-]?key))`)

var fieldPattern = regexp.MustCompile(`(?i)(["']?(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|credential|access[_-]?key|private[_-]?key)["']?\s*[:=]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s&;,<>]+)`)

func sensitive(key string) bool {
	key = strings.ToLower(key)
	for _, part := range []string{"authorization", "cookie", "password", "passwd", "secret", "token", "credential", "apikey", "api-key", "api_key", "private-key", "private_key", "access-key", "access_key"} {
		if strings.Contains(key, part) {
			return true
		}
	}
	return key == "pwd"
}

type sanitizer struct{ secrets []string }

func newSanitizer(t Target) sanitizer {
	s := sanitizer{}
	add := func(v string) {
		if v != "" && len(v) <= MaxHeaderBytes {
			s.secrets = append(s.secrets, v, url.QueryEscape(v), url.PathEscape(v))
		}
	}
	for key, values := range t.Headers {
		for _, value := range values {
			if len(value) >= 4 {
				add(value)
			}
			if sensitive(key) {
				for _, item := range strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ';' || r == '=' || r == ',' }) {
					if len(item) >= 4 {
						add(item)
					}
				}
			}
		}
	}
	if u, err := url.Parse(t.URL); err == nil {
		if u.User != nil {
			add(u.User.Username())
			p, _ := u.User.Password()
			add(p)
		}
		for _, values := range u.Query() {
			for _, v := range values {
				if len(v) >= 4 {
					add(v)
				}
			}
		}
	}
	sort.Slice(s.secrets, func(i, j int) bool { return len(s.secrets[i]) > len(s.secrets[j]) })
	return s
}

func bounded(s string, limit int) string {
	if len(s) > limit {
		s = s[:limit]
	}
	return strings.ToValidUTF8(s, "�")
}

func (s sanitizer) plain(v string, limit int) string {
	v = bounded(v, limit)
	// One pass prevents replacement markers from being rewritten by short values.
	if len(s.secrets) > 0 {
		pairs := make([]string, 0, len(s.secrets)*2)
		for _, secret := range s.secrets {
			pairs = append(pairs, secret, redacted)
		}
		v = strings.NewReplacer(pairs...).Replace(v)
	}
	v = fieldPattern.ReplaceAllString(v, "${1}"+redacted)
	if len(v) > limit {
		v = v[:limit]
	}
	return v
}

func (s sanitizer) text(v string) string { return s.plain(v, MaxHeaderBytes) }

func (s sanitizer) headers(h http.Header, request bool) http.Header {
	out := make(http.Header, len(h))
	for key, values := range h {
		for _, value := range values {
			if request || sensitive(key) {
				value = redacted
			} else {
				value = s.text(value)
			}
			out[s.text(key)] = append(out[s.text(key)], value)
		}
	}
	return out
}

func (s sanitizer) url(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid URL]"
	}
	u.User = nil
	q := u.Query()
	for key := range q {
		q[key] = []string{redacted}
	}
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return s.plain(u.String(), 4096)
}

func redactJSON(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		for k, value := range x {
			if sensitive(k) {
				x[k] = redacted
			} else {
				x[k] = redactJSON(value)
			}
		}
	case []interface{}:
		for i := range x {
			x[i] = redactJSON(x[i])
		}
	}
	return v
}

func (s sanitizer) body(raw []byte, contentType string, truncated bool) string {
	if !utf8.Valid(raw) || strings.IndexByte(string(raw), 0) >= 0 {
		return "[binary body omitted]"
	}
	if strings.Contains(strings.ToLower(contentType), "json") {
		var value interface{}
		if truncated || json.Unmarshal(raw, &value) != nil {
			return "[incomplete JSON body omitted]"
		}
		if b, err := json.MarshalIndent(redactJSON(value), "", "  "); err == nil {
			return s.plain(string(b), MaxBodyBytes)
		}
	}
	if contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "text/") && !strings.Contains(contentType, "xml") && !strings.Contains(contentType, "javascript") && !strings.Contains(contentType, "x-www-form-urlencoded") {
		return "[body omitted]"
	}
	if privateInputPattern.Match(raw) {
		return "[body with credential form fields omitted]"
	}
	return s.plain(string(raw), MaxBodyBytes)
}
