package wafdiagnose

import (
	"context"
	"net/http"
)

const (
	MaxHeaderBytes = 32 << 10
	MaxBodyBytes   = 64 << 10
)

type Target struct {
	URL                string
	Method             string
	Headers            http.Header
	Host               string
	FixedAddress       string
	Fallback           bool
	InsecureSkipVerify bool
	Public             bool
	// AllowProxy lets a public target follow system proxy settings (HTTP_PROXY etc.).
	AllowProxy bool
	// DialGuard receives each resolved numeric host:port before connecting.
	DialGuard func(string) error
}

type Attempt struct {
	Address string  `json:"address"`
	Status  string  `json:"status"`
	Reason  string  `json:"reason,omitempty"`
	MS      float64 `json:"ms"`
}

type Timings struct {
	DNSMS       float64 `json:"dns_ms"`
	TCPMS       float64 `json:"tcp_ms"`
	TLSMS       float64 `json:"tls_ms"`
	FirstByteMS float64 `json:"first_byte_ms"`
	TotalMS     float64 `json:"total_ms"`
}

type Certificate struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	DNSNames  []string `json:"dns_names,omitempty"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	SHA256    string   `json:"sha256"`
}

type TLSInfo struct {
	Version      string        `json:"version,omitempty"`
	CipherSuite  string        `json:"cipher_suite,omitempty"`
	Verified     bool          `json:"verified"`
	Verification string        `json:"verification"`
	Certificates []Certificate `json:"certificates,omitempty"`
}

type Result struct {
	StartedAt       string      `json:"started_at"`
	FinishedAt      string      `json:"finished_at"`
	Stage           string      `json:"stage"`
	Status          string      `json:"status"`
	Reason          string      `json:"reason,omitempty"`
	Evidence        []string    `json:"evidence,omitempty"`
	URL             string      `json:"url"`
	Host            string      `json:"host"`
	SNI             string      `json:"sni,omitempty"`
	ActualAddress   string      `json:"actual_address,omitempty"`
	Attempts        []Attempt   `json:"attempts"`
	Timings         Timings     `json:"timings"`
	TLS             *TLSInfo    `json:"tls,omitempty"`
	Request         string      `json:"request,omitempty"`
	Response        string      `json:"response,omitempty"`
	RequestHeaders  http.Header `json:"request_headers,omitempty"`
	ResponseHeaders http.Header `json:"response_headers,omitempty"`
	ResponseBody    string      `json:"response_body,omitempty"`
	BodyTruncated   bool        `json:"body_truncated"`
	StatusCode      int         `json:"status_code,omitempty"`
	HTTPWritten     bool        `json:"http_written"`
}

// Runner is useful for adapters that inject a diagnostic implementation.
type Runner func(context.Context, Target) Result
