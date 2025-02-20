package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReplaceBodyContent(t *testing.T) {
	// 测试用例表格
	tests := []struct {
		name        string
		inputBody   string
		oldString   string
		newString   string
		wantBody    string
		wantError   bool
		contentType string
	}{
		{
			name:      "basic replacement",
			inputBody: "Hello world",
			oldString: "world",
			newString: "golang",
			wantBody:  "Hello golang",
		},
		{
			name:      "multiple occurrences",
			inputBody: "banana",
			oldString: "na",
			newString: "no",
			wantBody:  "banono",
		},
		{
			name:      "empty body",
			inputBody: "",
			oldString: "test",
			newString: "demo",
			wantBody:  "",
		},
		{
			name:      "chinese characters",
			inputBody: "你好世界",
			oldString: "世界",
			newString: "Golang",
			wantBody:  "你好Golang",
		},
		{
			name:      "binary data",
			inputBody: string([]byte{0x48, 0x65, 0x00, 0x6c, 0x6c, 0x6f}), // 包含null字节
			oldString: string([]byte{0x00}),
			newString: " ",
			wantBody:  "He llo",
		},
		{
			name:      "case sensitive",
			inputBody: "Go is Cool, go is fun",
			oldString: "go",
			newString: "GO",
			wantBody:  "Go is Cool, GO is fun",
		},
		{
			name:        "json content",
			contentType: "application/json",
			inputBody:   `{"message":"hello"}`,
			oldString:   "hello",
			newString:   "hola",
			wantBody:    `{"message":"hola"}`,
		},
	}

	waf := &WafEngine{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建测试请求
			req := httptest.NewRequest("POST", "/", bytes.NewBufferString(tt.inputBody))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			// 执行替换操作
			err := waf.ReplaceBodyContent(req, tt.oldString, tt.newString)
			if (err != nil) != tt.wantError {
				t.Fatalf("ReplaceBodyContent() error = %v, wantError %v", err, tt.wantError)
			}

			// 读取修改后的Body
			gotBody, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal("Failed to read modified body:", err)
			}

			// 验证结果
			if string(gotBody) != tt.wantBody {
				t.Errorf("Body mismatch\nWant: %q\nGot:  %q", tt.wantBody, string(gotBody))
			}

			// 验证Content-Type是否保留
			if ct := req.Header.Get("Content-Type"); ct != tt.contentType {
				t.Errorf("Content-Type changed unexpectedly\nWas: %q\nNow: %q", tt.contentType, ct)
			}
		})
	}
}
func TestReplaceURLContent(t *testing.T) {
	t.Parallel()

	//初始化日志
	zlog.InitZLog(global.GWAF_RELEASE)
	if v := recover(); v != nil {
		zlog.Error("error")
	}
	// 模拟原始请求
	req := httptest.NewRequest("GET", "http://origin.com/test%20/scan?q=hello%2520world&n=1%2B1", nil)
	waf := &WafEngine{}

	// 执行替换：将"test "替换为"demo"
	err := waf.ReplaceURLContent(req, "test ", "demo")
	if err != nil {
		t.Fatal(err)
	}

	// 验证路径编码
	if req.URL.Path != "/demo/scan" {
		t.Errorf("RawPath mismatch: %s", req.URL.RawPath)
	}

	// 模拟代理服务器接收的请求
	proxyReq := &http.Request{
		Method: req.Method,
		URL:    req.URL,
		Header: req.Header,
	}

	// 验证代理看到的URL
	if proxyReq.URL.String() != req.URL.String() {
		t.Errorf("Proxy URL mismatch: %s", proxyReq.URL.String())
	}
}
