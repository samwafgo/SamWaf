package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// customErrorPageResult 自定义错误页的处理结果
type customErrorPageResult struct {
	// TemplateApplied true=用自定义模版覆盖了后端响应；false=按「优先后端响应」原样透传了后端内容
	TemplateApplied bool
	// BackendBody 后端原始响应体（能解码就是解码后的明文），用于访问日志与模板变量
	BackendBody []byte
}

// decodeResponseBodyBytes 按 Content-Encoding 把响应体解压成明文字节。
//
// 与 getOrgContent 里的解压分支职责相同，但那边是 reader 流水线（后面还要接字符集探测），
// 这里只需要"字节进、字节出"，因此单独实现，不去改动编码探测那条主链路。
// 不认识的编码原样返回；解压失败返回错误，由调用方决定是否回退到原始字节。
func decodeResponseBodyBytes(contentEncoding string, body []byte) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}
	var reader io.Reader
	switch contentEncoding {
	case "gzip":
		gzipReader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, fmt.Errorf("gzip解压失败: %v", err)
		}
		defer gzipReader.Close()
		reader = gzipReader
	case "deflate":
		deflateReader := flate.NewReader(bytes.NewReader(body))
		defer deflateReader.Close()
		reader = deflateReader
	case "br":
		reader = brotli.NewReader(bytes.NewReader(body))
	case "zstd":
		zstdReader, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, fmt.Errorf("zstd解压失败: %v", err)
		}
		defer zstdReader.Close()
		reader = zstdReader
	default:
		// 未压缩或未知编码，原样返回
		return body, nil
	}
	plain, err := io.ReadAll(reader)
	if err != nil {
		return body, fmt.Errorf("解压响应体失败(%s): %v", contentEncoding, err)
	}
	return plain, nil
}

// resolveCustomErrorPage 按「后端真实返回的状态码」查找自定义错误页配置，网站级优先于全局级。
//
// 只处理后端返回的状态码（403/404/500/502…）；WAF 自身的拦截走 EchoErrorInfo，
// 是另一条完全独立的路径，不经过这里。
func resolveCustomErrorPage(hostSafe, globalHostSafe *wafenginmodel.HostSafe, backendStatusCode int) *model.BlockingPage {
	statusCodeKey := strconv.Itoa(backendStatusCode)
	if hostSafe != nil {
		if page, ok := hostSafe.BlockingPage[statusCodeKey]; ok {
			return &page
		}
	}
	if globalHostSafe != nil {
		if page, ok := globalHostSafe.BlockingPage[statusCodeKey]; ok {
			return &page
		}
	}
	return nil
}

// applyCustomErrorPage 对后端返回的错误响应应用自定义错误页，调用前需保证 page != nil。
//
// resp.Body 会被完整读走，两条分支各自负责把 body 重新填回去：
//   - 「优先后端响应」且后端确有内容 → 原样还原（状态码/响应头/压缩编码/Content-Type 全不动）
//   - 其余情况 → 渲染模版覆盖
func applyCustomErrorPage(resp *http.Response, page *model.BlockingPage,
	backendStatusCode int, backendStatus string, reqUUID string) customErrorPageResult {

	var rawBody []byte
	if resp.Body != nil && resp.Body != http.NoBody {
		rawBody, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	// 后端可能开了 gzip/br/deflate/zstd。必须先解码：
	// 一是"后端到底有没有回内容"要按明文判断（gzip 的空 body 也有二十来字节，按原始字节判会永远非空）；
	// 二是模板变量 SAMWAF_BACKEND_BODY 和访问日志都得拿到人能看懂的内容。
	plainBody, decodeErr := decodeResponseBodyBytes(resp.Header.Get("Content-Encoding"), rawBody)
	if decodeErr != nil {
		zlog.Debug(fmt.Sprintf("自定义错误页解码后端响应体失败，按原始字节处理: %v", decodeErr))
		plainBody = rawBody
	}

	// 「优先后端响应」模式：后端自己已经回了内容（比如接口的 JSON 错误详情）就原样透传，
	// 只有后端没给响应体时才用自定义模版兜底。见 gitee issue IK8KA7
	if page.IsBackendContentFirst() && len(bytes.TrimSpace(plainBody)) > 0 {
		resp.Body = io.NopCloser(bytes.NewBuffer(rawBody))
		return customErrorPageResult{TemplateApplied: false, BackendBody: plainBody}
	}

	renderData := map[string]interface{}{
		"SAMWAF_REQ_UUID":       reqUUID,
		"SAMWAF_BACKEND_STATUS": backendStatus,
		"SAMWAF_BACKEND_CODE":   backendStatusCode,
		"SAMWAF_BACKEND_BODY":   string(plainBody),
	}

	resBytes, err := renderTemplate(page.ResponseContent, renderData)
	if err != nil {
		resBytes = []byte(page.ResponseContent)
		zlog.Warn(fmt.Sprintf("模板渲染失败: %v, 使用原始内容", err))
	}

	// 设置自定义响应码（如果配置了）
	customResponseCode := backendStatusCode
	if page.ResponseCode != "" {
		if code, convErr := strconv.Atoi(page.ResponseCode); convErr == nil {
			customResponseCode = code
		}
	}

	// 模版是未压缩的明文，必须清掉后端留下的 Content-Encoding，
	// 否则客户端会拿 gzip/br 去解一段纯 HTML，页面直接解码失败——
	// 而后端开压缩是常态，这条不清就等于自定义错误页在多数站点上不可用。
	resp.Header.Del("Content-Encoding")

	// 应用用户配置的响应头（放在 Del 之后，用户若显式配了同名头以用户为准）
	var headers []map[string]string
	if err := json.Unmarshal([]byte(page.ResponseHeader), &headers); err == nil {
		for _, header := range headers {
			if name, ok := header["name"]; ok {
				if value, ok := header["value"]; ok && value != "" {
					resp.Header.Set(name, value)
				}
			}
		}
	}

	resp.StatusCode = customResponseCode
	resp.Status = http.StatusText(customResponseCode)
	resp.Body = io.NopCloser(bytes.NewBuffer(resBytes))
	resp.ContentLength = int64(len(resBytes))
	resp.Header.Set("Content-Length", strconv.FormatInt(int64(len(resBytes)), 10))

	return customErrorPageResult{TemplateApplied: true, BackendBody: plainBody}
}
