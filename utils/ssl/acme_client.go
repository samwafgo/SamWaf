package ssl

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/utils"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-acme/lego/v4/lego"
)

const maxACMEDirectoryBackoff = 30 * time.Second

func newACMEClient(ctx context.Context, user *MyUser, address string, isIP bool) (*lego.Client, error) {
	settings := global.GACME_CONFIG
	address = strings.TrimSpace(address)
	var config *lego.Config
	var scope *url.URL
	if trust, ok := settings.TrustedCAs[address]; ok {
		if trust.ConfigError != "" {
			return nil, fmt.Errorf("ACME 自定义 CA 配置无效：%s", trust.ConfigError)
		}
		var err error
		scope, err = utils.ParseACMEDirectoryURL(address)
		if err != nil {
			return nil, err
		}
		roots, err := loadACMECAFile(utils.GetCurrentDir(), trust.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ACME 自定义 CA 配置无效：%w", err)
		}
		config = newTrustedACMEConfig(user, roots)
	} else {
		config = lego.NewConfig(user)
	}
	config.CADirURL = address
	config.Certificate.DisableCommonName = isIP
	return openACMEClient(ctx, scope, config, time.Duration(settings.DirectoryTimeoutSeconds)*time.Second, settings.DirectoryMaxRetries, waitACMERetry)
}

func openACMEClient(ctx context.Context, scope *url.URL, config *lego.Config, timeout time.Duration, retries int, wait func(context.Context, time.Duration) error) (*lego.Client, error) {
	directoryURL, err := utils.ParseACMEDirectoryURL(config.CADirURL)
	if err != nil {
		return nil, err
	}
	caHost := directoryURL.Hostname()
	base, ok := config.HTTPClient.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("ACME 客户端缺少 HTTP Transport")
	}
	// 目录阶段独立计时，不修改 lego 后续 ACME 请求的传输配置。
	directoryTransport := base.Clone()
	directoryTransport.ResponseHeaderTimeout = 0
	directoryTransport.TLSHandshakeTimeout = 0
	defer directoryTransport.CloseIdleConnections()
	dispatch := &acmeOrderTransport{ctx: ctx, transport: directoryTransport, directory: true, scope: scope}
	for attempt := 1; attempt <= retries+1; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		started := time.Now()
		attemptConfig := *config
		httpClient := *config.HTTPClient
		httpClient.Transport = dispatch
		httpClient.Timeout = timeout
		httpClient.CheckRedirect = checkACMEDirectoryRedirect
		attemptConfig.HTTPClient = &httpClient
		client, err := lego.NewClient(&attemptConfig)
		if err == nil {
			dispatch.transport = base
			dispatch.directory = false
			httpClient.Timeout = config.HTTPClient.Timeout
			httpClient.CheckRedirect = config.HTTPClient.CheckRedirect
			if scope != nil {
				context.AfterFunc(ctx, base.CloseIdleConnections)
			}
			if attempt > 1 {
				zlog.Info(fmt.Sprintf("%sACME 目录读取恢复 CA=%s 尝试=%d/%d 耗时=%s", acmeLogPrefix, caHost, attempt, retries+1, time.Since(started).Round(time.Millisecond)))
			}
			return client, nil
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		status, again := acmeDirectoryFailure(err)
		failure := fmt.Errorf("ACME 目录读取失败 CA=%s 尝试=%d/%d 耗时=%s：%s", caHost, attempt, retries+1, time.Since(started).Round(time.Millisecond), status)
		if !again || attempt > retries {
			return nil, failure
		}
		delay := (time.Second << (attempt - 1)) + time.Duration(rand.IntN(500))*time.Millisecond
		var responseErr *acmeDirectoryHTTPError
		if errors.As(err, &responseErr) {
			if after := acmeRetryAfter(responseErr.retryAfter, time.Now()); after > delay {
				if after > maxACMEDirectoryBackoff {
					return nil, fmt.Errorf("%w；CA 要求稍后再试，本次停止重试", failure)
				}
				delay = after
			}
		}
		zlog.Warn(fmt.Sprintf("%s%v，%s 后重试", acmeLogPrefix, failure, delay))
		if err := wait(ctx, delay); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("ACME 目录重试次数无效")
}

func checkACMEDirectoryRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 || req.URL.Scheme != "https" || req.URL.User != nil {
		return errors.New("ACME 目录重定向无效")
	}
	req.Header.Del("Referer")
	return nil
}

type acmeOrderTransport struct {
	ctx       context.Context
	transport http.RoundTripper
	directory bool
	scope     *url.URL
}

func (t *acmeOrderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.ctx.Err(); err != nil {
		return nil, err
	}
	if t.scope != nil && !sameACMEOrigin(t.scope, req.URL) {
		return nil, errACMEOriginMismatch
	}
	ctx, cancel := context.WithCancel(req.Context())
	stop := context.AfterFunc(t.ctx, cancel)
	release := func() {
		stop()
		cancel()
	}
	resp, err := t.transport.RoundTrip(req.Clone(ctx))
	if err != nil {
		release()
		return nil, err
	}
	if t.directory && resp.StatusCode >= http.StatusBadRequest {
		resp.Body.Close()
		release()
		return nil, &acmeDirectoryHTTPError{status: resp.StatusCode, retryAfter: resp.Header.Get("Retry-After")}
	}
	if req.Method == http.MethodHead || resp.Body == http.NoBody || resp.ContentLength == 0 {
		release()
	} else {
		resp.Body = &acmeOrderBody{ReadCloser: resp.Body, release: release}
	}
	return resp, nil
}

type acmeOrderBody struct {
	io.ReadCloser
	release func()
}

func (b *acmeOrderBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.release()
	}
	return n, err
}

func (b *acmeOrderBody) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}

type acmeDirectoryHTTPError struct {
	status     int
	retryAfter string
}

func (e *acmeDirectoryHTTPError) Error() string { return fmt.Sprintf("HTTP %d", e.status) }

func acmeDirectoryFailure(err error) (string, bool) {
	if errors.Is(err, errACMEOriginMismatch) {
		return errACMEOriginMismatch.Error(), false
	}
	var status *acmeDirectoryHTTPError
	if errors.As(err, &status) {
		switch status.status {
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return status.Error(), true
		default:
			return status.Error(), false
		}
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "CA 的 TLS 证书校验失败", false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "CA 域名解析失败", !dnsErr.IsNotFound && (dnsErr.IsTimeout || dnsErr.IsTemporary)
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return "请求超时", true
	}
	var opErr *net.OpError
	isNetworkIO := errors.As(err, &opErr) && (opErr.Op == "dial" || opErr.Op == "read" || opErr.Op == "write")
	if isNetworkIO || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) {
		return "网络连接中断或不可达", true
	}
	return "CA 目录响应无效或连接配置错误", false
}

func acmeRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil || errors.Is(err, strconv.ErrRange) {
		if seconds > uint64(maxACMEDirectoryBackoff/time.Second) {
			return maxACMEDirectoryBackoff + time.Second
		}
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil {
		return date.Sub(now)
	}
	return 0
}

func waitACMERetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
