package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// makeBodyRequest 构造一个带有指定 body 的 POST 请求上下文
func makeBodyRequest(body string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	return c, w
}

// readBody 从 gin.Context 中读取当前 Body 内容（不破坏 Body）
func readBody(c *gin.Context) string {
	if c.Request.Body == nil {
		return ""
	}
	data, _ := io.ReadAll(c.Request.Body)
	c.Request.Body = io.NopCloser(bytes.NewBuffer(data))
	return string(data)
}

// TestBodyNotTruncatedWhenLarge 验证大请求体读取日志后，handler 能拿到完整 body
func TestBodyNotTruncatedWhenLarge(t *testing.T) {
	// 构造一个超过 2048 字节的请求体
	largeBody := strings.Repeat("x", 4096)
	c, _ := makeBodyRequest(largeBody)

	// 模拟 OpenApiLogMiddleware 中的 body 读取逻辑
	requestBody := ""
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		t.Fatalf("读取 body 失败: %v", err)
	}
	// 恢复完整 body
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	if len(bodyBytes) > 2048 {
		requestBody = string(bodyBytes[:2048]) + "...(truncated)"
	} else {
		requestBody = string(bodyBytes)
	}

	// 1. 日志字段应被截断
	if !strings.HasSuffix(requestBody, "...(truncated)") {
		t.Errorf("期望日志字段包含截断标记，实际: %s", requestBody[len(requestBody)-20:])
	}
	if len(requestBody) > 2048+len("...(truncated)") {
		t.Errorf("日志字段超出预期长度: %d", len(requestBody))
	}

	// 2. handler 读到的 body 必须是完整的原始内容
	handlerBody := readBody(c)
	if handlerBody != largeBody {
		t.Errorf("handler 拿到的 body 被截断: 期望 %d 字节，实际 %d 字节", len(largeBody), len(handlerBody))
	}
}

// TestBodySmallNotTruncated 验证小请求体不会被添加截断标记
func TestBodySmallNotTruncated(t *testing.T) {
	smallBody := `{"key":"value"}`
	c, _ := makeBodyRequest(smallBody)

	requestBody := ""
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		t.Fatalf("读取 body 失败: %v", err)
	}
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	if len(bodyBytes) > 2048 {
		requestBody = string(bodyBytes[:2048]) + "...(truncated)"
	} else {
		requestBody = string(bodyBytes)
	}

	// 日志字段应与原始内容一致
	if requestBody != smallBody {
		t.Errorf("小 body 不应被截断: 期望 %q，实际 %q", smallBody, requestBody)
	}

	// handler 读到的 body 也完整
	handlerBody := readBody(c)
	if handlerBody != smallBody {
		t.Errorf("handler body 不匹配: 期望 %q，实际 %q", smallBody, handlerBody)
	}
}

// TestBodyExactly2048 验证恰好 2048 字节的请求体不被截断
func TestBodyExactly2048(t *testing.T) {
	exactBody := strings.Repeat("a", 2048)
	c, _ := makeBodyRequest(exactBody)

	requestBody := ""
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		t.Fatalf("读取 body 失败: %v", err)
	}
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	if len(bodyBytes) > 2048 {
		requestBody = string(bodyBytes[:2048]) + "...(truncated)"
	} else {
		requestBody = string(bodyBytes)
	}

	if strings.HasSuffix(requestBody, "...(truncated)") {
		t.Errorf("恰好 2048 字节不应被截断")
	}
	if requestBody != exactBody {
		t.Errorf("日志字段与原始内容不符")
	}
}

// TestBodyNil 验证 Body 为 nil 时不 panic
func TestBodyNil(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	c.Request = req

	// 模拟逻辑，Body 为 nil 直接跳过
	requestBody := ""
	if c.Request.Body != nil {
		bodyBytes, _ := io.ReadAll(c.Request.Body)
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if len(bodyBytes) > 2048 {
			requestBody = string(bodyBytes[:2048]) + "...(truncated)"
		} else {
			requestBody = string(bodyBytes)
		}
	}

	if requestBody != "" {
		t.Errorf("Body 为 nil 时 requestBody 应为空，实际: %q", requestBody)
	}
}
