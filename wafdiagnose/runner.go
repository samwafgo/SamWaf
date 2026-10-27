package wafdiagnose

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"SamWaf/utils"
)

const maxDuration = 10 * time.Second

type recorder struct {
	sync.Mutex
	result                    Result
	start, dnsStart, tlsStart time.Time
	connectStart              map[string]time.Time
}

func millis(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// Run performs one bounded request without following redirects or retaining connections.
func Run(parent context.Context, target Target) (result Result) {
	started := time.Now()
	if len(target.URL) > 8192 || len(target.Host) > 255 || len(target.FixedAddress) > 128 || !boundedHeaders(target.Headers) {
		return Result{StartedAt: started.UTC().Format(time.RFC3339Nano), FinishedAt: time.Now().UTC().Format(time.RFC3339Nano), Stage: "validation", Status: "error", Reason: "target input exceeds diagnostic limits", Attempts: []Attempt{}}
	}
	s := newSanitizer(target)
	r := &recorder{start: started, connectStart: make(map[string]time.Time), result: Result{StartedAt: started.UTC().Format(time.RFC3339Nano), Stage: "validation", Status: "error", URL: s.url(target.URL), Attempts: []Attempt{}}}
	defer func() {
		r.Lock()
		r.result.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		r.result.Timings.TotalMS = millis(time.Since(started))
		result = r.result
		r.Unlock()
		result = sanitizeResult(result, s)
	}()
	ctx, cancel := context.WithTimeout(parent, maxDuration)
	defer cancel()
	fail := func(stage string, err error) {
		r.Lock()
		defer r.Unlock()
		if stage != "" {
			r.result.Stage = stage
		}
		r.result.Reason = err.Error()
	}
	u, err := url.Parse(target.URL)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || len(target.URL) > 8192 {
		fail("validation", errors.New("invalid HTTP target URL"))
		return
	}
	method := target.Method
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodHead {
		fail("validation", errors.New("only GET and HEAD are supported"))
		return
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	n, portErr := strconv.Atoi(port)
	if portErr != nil || n < 1 || n > 65535 {
		fail("validation", errors.New("invalid target port"))
		return
	}
	if target.Public && target.FixedAddress != "" {
		fail("validation", errors.New("public targets cannot override the connection address"))
		return
	}
	if target.FixedAddress != "" {
		host, fixedPort, e := net.SplitHostPort(target.FixedAddress)
		fixedNumber, fixedError := strconv.Atoi(fixedPort)
		if e != nil || net.ParseIP(host) == nil || fixedError != nil || fixedNumber < 1 || fixedNumber > 65535 {
			fail("validation", errors.New("fixed address must contain a numeric IP and valid port"))
			return
		}
	}
	host := target.Host
	if host == "" {
		host = u.Host
	}
	if strings.ContainsAny(host, "\r\n/\\@?# \t") || len(host) > 255 {
		fail("validation", errors.New("invalid Host override"))
		return
	}
	sni := u.Hostname()
	r.result.Host = host
	if u.Scheme == "https" {
		r.result.SNI = sni
	}
	if target.Public {
		check := make(chan error, 1)
		go func() {
			if ok, reason := utils.IsAllowedOutboundURL(target.URL); !ok {
				check <- errors.New(reason)
			} else {
				check <- nil
			}
		}()
		select {
		case e := <-check:
			if e != nil {
				fail("validation", e)
				return
			}
		case <-ctx.Done():
			fail("dns", ctx.Err())
			return
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, target.URL, nil)
	if err != nil {
		fail("validation", err)
		return
	}
	request.Host = host
	request.Header = make(http.Header)
	headerBytes := len(host)
	for key, values := range target.Headers {
		if !validHeaderName(key) || forbiddenHeader(key) {
			fail("validation", errors.New("unsupported request header"))
			return
		}
		for _, value := range values {
			headerBytes += len(key) + len(value) + 4
			if strings.ContainsAny(value, "\r\n\x00") || headerBytes > MaxHeaderBytes {
				fail("validation", errors.New("invalid or oversized request headers"))
				return
			}
			request.Header.Add(key, value)
		}
	}
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", "SamWaf-Diagnostic")
	}
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { r.Lock(); r.dnsStart = time.Now(); r.result.Stage = "dns"; r.Unlock() },
		DNSDone: func(info httptrace.DNSDoneInfo) {
			r.Lock()
			r.result.Timings.DNSMS += millis(time.Since(r.dnsStart))
			r.Unlock()
		},
		ConnectStart: func(_, addr string) { r.Lock(); r.result.Stage = "tcp"; r.connectStart[addr] = time.Now(); r.Unlock() },
		ConnectDone: func(_, addr string, e error) {
			r.Lock()
			defer r.Unlock()
			d := millis(time.Since(r.connectStart[addr]))
			r.result.Timings.TCPMS += d
			a := Attempt{Address: addr, Status: "success", MS: d}
			if e != nil {
				a.Status = "error"
				a.Reason = e.Error()
			}
			if len(r.result.Attempts) < 32 {
				r.result.Attempts = append(r.result.Attempts, a)
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			r.Lock()
			r.result.ActualAddress = info.Conn.RemoteAddr().String()
			r.Unlock()
		},
		TLSHandshakeStart: func() { r.Lock(); r.tlsStart = time.Now(); r.result.Stage = "tls"; r.Unlock() },
		TLSHandshakeDone: func(state tls.ConnectionState, e error) {
			r.Lock()
			defer r.Unlock()
			r.result.Timings.TLSMS = millis(time.Since(r.tlsStart))
			r.result.TLS = tlsInfo(state, e, target.Public || !target.InsecureSkipVerify)
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err != nil {
				return
			}
			r.Lock()
			defer r.Unlock()
			r.result.Stage = "response"
			r.result.HTTPWritten = true
			r.result.RequestHeaders = s.headers(request.Header, true)
			r.result.Request = normalizedRequest(request, s)
		},
		GotFirstResponseByte: func() { r.Lock(); r.result.Timings.FirstByteMS = millis(time.Since(started)); r.Unlock() },
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	var transport *http.Transport
	if target.Public {
		if target.AllowProxy {
			transport = utils.SafeOutboundProxyTransport(target.DialGuard)
		} else {
			transport = utils.SafeOutboundDirectTransport(target.DialGuard)
		}
	} else {
		transport = &http.Transport{Proxy: nil, DialContext: localDial(target, u.Hostname(), port)}
	}
	transport.TLSClientConfig = &tls.Config{ServerName: sni, InsecureSkipVerify: target.InsecureSkipVerify && !target.Public} // Saved source setting.
	transport.DisableKeepAlives = true
	transport.DisableCompression = true
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	transport.MaxResponseHeaderBytes = MaxHeaderBytes
	transport.TLSHandshakeTimeout = maxDuration
	transport.ResponseHeaderTimeout = maxDuration
	baseDial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := baseDial(ctx, network, address)
		if err == nil {
			r.Lock()
			r.result.ActualAddress = conn.RemoteAddr().String()
			r.Unlock()
		}
		return conn, err
	}
	defer transport.CloseIdleConnections()
	r.result.Stage = "tcp"
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		fail("", err)
		return
	}
	defer response.Body.Close()
	r.Lock()
	r.result.Stage = "body"
	r.result.StatusCode = response.StatusCode
	r.result.ResponseHeaders = s.headers(response.Header, false)
	r.result.Response = normalizedResponse(response, s)
	r.Unlock()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxBodyBytes+1))
	truncated := len(body) > MaxBodyBytes
	if truncated {
		body = body[:MaxBodyBytes]
	}
	r.Lock()
	r.result.BodyTruncated = truncated
	r.result.ResponseBody = s.body(body, response.Header.Get("Content-Type"), truncated)
	r.result.Response += r.result.ResponseBody
	r.result.Response = s.plain(r.result.Response, MaxBodyBytes+MaxHeaderBytes)
	r.result.Request = s.plain(r.result.Request, MaxHeaderBytes+4096)
	if err == nil {
		r.result.Stage = "complete"
		r.result.Status = "success"
	}
	r.Unlock()
	if err != nil {
		fail("body", err)
	}
	return
}

func localDial(t Target, hostname, port string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		dialer := &net.Dialer{}
		dial := func(address string) (net.Conn, error) {
			if t.DialGuard != nil {
				if err := t.DialGuard(address); err != nil {
					return nil, err
				}
			}
			return dialer.DialContext(ctx, network, address)
		}
		if t.FixedAddress != "" {
			conn, err := dial(t.FixedAddress)
			if err == nil || !t.Fallback || ctx.Err() != nil {
				return conn, err
			}
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("no DNS addresses")
		}
		var last error
		for i, ip := range ips {
			if i == 16 {
				break
			}
			conn, err := dial(net.JoinHostPort(ip.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, last
	}
}

func tlsInfo(state tls.ConnectionState, err error, strict bool) *TLSInfo {
	info := &TLSInfo{Verified: strict && err == nil && len(state.VerifiedChains) > 0, Verification: "failed"}
	if !strict {
		info.Verification = "skipped"
	} else if info.Verified {
		info.Verification = "verified"
	}
	if state.Version != 0 {
		info.Version = tls.VersionName(state.Version)
		info.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	}
	certs := state.PeerCertificates
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		certs = verification.UnverifiedCertificates
	}
	for i, cert := range certs {
		if i == 5 {
			break
		}
		hash := sha256.Sum256(cert.Raw)
		names := cert.DNSNames
		if len(names) > 32 {
			names = names[:32]
		}
		info.Certificates = append(info.Certificates, Certificate{Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), DNSNames: append([]string(nil), names...), NotBefore: cert.NotBefore.UTC().Format(time.RFC3339), NotAfter: cert.NotAfter.UTC().Format(time.RFC3339), SHA256: hex.EncodeToString(hash[:])})
	}
	// Some TLS implementations return the certificate in the underlying verification error.
	if len(info.Certificates) == 0 {
		var unknown x509.UnknownAuthorityError
		if errors.As(err, &unknown) && unknown.Cert != nil {
			state.PeerCertificates = []*x509.Certificate{unknown.Cert}
			return tlsInfo(state, nil, false)
		}
	}
	return info
}

func boundedHeaders(headers http.Header) bool {
	if len(headers) > 128 {
		return false
	}
	total, count := 0, 0
	for key, values := range headers {
		for _, value := range values {
			total += len(key) + len(value) + 4
			count++
			if total > MaxHeaderBytes || count > 128 {
				return false
			}
		}
	}
	return true
}

func validHeaderName(key string) bool {
	if key == "" {
		return false
	}
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}
func forbiddenHeader(key string) bool {
	switch strings.ToLower(key) {
	case "host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection", "upgrade", "trailer", "te":
		return true
	}
	return false
}
func headerText(h http.Header) string {
	keys := make([]string, 0, len(h))
	for key := range h {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		for _, value := range h[key] {
			fmt.Fprintf(&b, "%s: %s\r\n", key, value)
		}
	}
	return b.String()
}
func normalizedRequest(req *http.Request, s sanitizer) string {
	u := *req.URL
	u.Scheme = ""
	u.Host = ""
	return req.Method + " " + s.url(u.String()) + " HTTP/1.1\r\nHost: " + s.text(req.Host) + "\r\n" + headerText(s.headers(req.Header, true)) + "\r\n"
}
func normalizedResponse(resp *http.Response, s sanitizer) string {
	return s.text(resp.Proto+" "+resp.Status) + "\r\n" + headerText(s.headers(resp.Header, false)) + "\r\n"
}
func sanitizeResult(r Result, s sanitizer) Result {
	r.Reason = s.text(r.Reason)
	r.Host = s.text(r.Host)
	r.SNI = s.text(r.SNI)
	r.ActualAddress = s.text(r.ActualAddress)
	for i := range r.Attempts {
		r.Attempts[i].Address = s.text(r.Attempts[i].Address)
		r.Attempts[i].Reason = s.text(r.Attempts[i].Reason)
	}
	if r.TLS != nil {
		for i := range r.TLS.Certificates {
			c := &r.TLS.Certificates[i]
			c.Subject = s.text(c.Subject)
			c.Issuer = s.text(c.Issuer)
			for j := range c.DNSNames {
				c.DNSNames[j] = s.text(c.DNSNames[j])
			}
		}
	}
	return r
}
