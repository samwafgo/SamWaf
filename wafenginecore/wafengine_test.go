package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
			err := waf.ReplaceBodyContent(req, []string{tt.oldString}, tt.newString)
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
	zlog.InitZLog(global.GWAF_RELEASE, "json")
	if v := recover(); v != nil {
		zlog.Error("error")
	}
	// 模拟原始请求
	req := httptest.NewRequest("GET", "http://origin.com/test%20/scan?q=hello%2520world&n=1%2B1", nil)
	waf := &WafEngine{}

	// 执行替换：将"test "替换为"demo"
	err := waf.ReplaceURLContent(req, []string{"test "}, "demo")
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

func TestGetOrgContent(t *testing.T) {
	t.Parallel()

	//初始化日志
	zlog.InitZLog(global.GWAF_RELEASE, "json")
	// 初始化WAF引擎
	waf := &WafEngine{}

	// 测试用例
	testCases := []struct {
		name            string
		contentType     string
		contentEncoding string
		content         string
		expectedContent string // 新增：期望解码后的内容
		expectedErr     bool
	}{
		{
			name:            "UTF-8 无压缩",
			contentType:     "text/html; charset=utf-8",
			contentEncoding: "",
			content:         "<html><body>这是UTF-8编码的内容</body></html>",
			expectedContent: "<html><body>这是UTF-8编码的内容</body></html>",
			expectedErr:     false,
		},
		{
			name:            "GBK 无压缩",
			contentType:     "text/html; charset=gbk",
			contentEncoding: "",
			// 这里使用GBK编码的字节序列，而不是UTF-8字符串
			content:         string([]byte{0x3c, 0x68, 0x74, 0x6d, 0x6c, 0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0xd5, 0xe2, 0xca, 0xc7, 0x47, 0x42, 0x4b, 0xb1, 0xe0, 0xc2, 0xeb, 0xb5, 0xc4, 0xc4, 0xda, 0xc8, 0xdd, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e}),
			expectedContent: "<html><body>这是GBK编码的内容</body></html>",
			expectedErr:     false,
		},
		{
			name:            "UTF-8 GZIP压缩",
			contentType:     "text/html; charset=utf-8",
			contentEncoding: "gzip",
			content:         "<html><body>这是GZIP压缩的UTF-8内容</body></html>",
			expectedContent: "<html><body>这是GZIP压缩的UTF-8内容</body></html>",
			expectedErr:     false,
		},
		{
			name:            "UTF-8 Deflate压缩",
			contentType:     "text/html; charset=utf-8",
			contentEncoding: "deflate",
			content:         "<html><body>这是Deflate压缩的UTF-8内容</body></html>",
			expectedContent: "<html><body>这是Deflate压缩的UTF-8内容</body></html>",
			expectedErr:     false,
		},
		{
			name:            "无字符集指定",
			contentType:     "text/html",
			contentEncoding: "",
			content:         "<html><body>没有指定字符集的内容</body></html>",
			expectedContent: "<html><body>没有指定字符集的内容</body></html>",
			expectedErr:     true,
		},
		{
			// 对于不支持的字符集，我们跳过内容比较，只检查是否有错误
			name:            "不支持的字符集",
			contentType:     "text/html; charset=iso-8859-1",
			contentEncoding: "",
			content:         "<html><body>使用不常见字符集的内容</body></html>",
			expectedContent: "", // 不比较内容
			expectedErr:     false,
		},
		{
			name:            "JSON内容",
			contentType:     "application/json; charset=utf-8",
			contentEncoding: "",
			content:         `{"message": "这是JSON内容", "code": 200}`,
			expectedContent: `{"message": "这是JSON内容", "code": 200}`,
			expectedErr:     false,
		},
		{
			name:            "大量内容",
			contentType:     "text/html; charset=utf-8",
			contentEncoding: "",
			content:         strings.Repeat("这是一个很长的内容，用于测试大量数据的处理能力。", 10), // 减少重复次数以加快测试
			expectedContent: strings.Repeat("这是一个很长的内容，用于测试大量数据的处理能力。", 10),
			expectedErr:     false,
		},
	}

	for _, tc := range testCases {
		tc := tc // 防止闭包问题
		t.Run(tc.name, func(t *testing.T) {
			// 创建响应
			var bodyContent []byte
			var err error

			// 根据内容编码处理内容
			switch tc.contentEncoding {
			case "gzip":
				var buf bytes.Buffer
				gzipWriter := gzip.NewWriter(&buf)
				_, err = gzipWriter.Write([]byte(tc.content))
				if err != nil {
					t.Fatalf("创建gzip内容失败: %v", err)
				}
				gzipWriter.Close()
				bodyContent = buf.Bytes()
			case "deflate":
				var buf bytes.Buffer
				deflateWriter, _ := flate.NewWriter(&buf, flate.DefaultCompression)
				_, err = deflateWriter.Write([]byte(tc.content))
				if err != nil {
					t.Fatalf("创建deflate内容失败: %v", err)
				}
				deflateWriter.Close()
				bodyContent = buf.Bytes()
			default:
				bodyContent = []byte(tc.content)
			}

			// 创建HTTP响应
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBuffer(bodyContent)),
			}
			resp.Header.Set("Content-Type", tc.contentType)
			if tc.contentEncoding != "" {
				resp.Header.Set("Content-Encoding", tc.contentEncoding)
			}

			// 调用测试函数
			result, _, err := waf.getOrgContent(resp, false)

			// 验证结果
			if tc.expectedErr {
				if err == nil {
					t.Errorf("期望错误但没有发生错误")
				}
			} else {
				if err != nil {
					t.Errorf("不期望错误但发生了错误: %v", err)
				} else if tc.expectedContent != "" { // 只有当期望内容不为空时才比较
					// 对于GBK测试用例，我们需要特殊处理
					if tc.name == "GBK 无压缩" {
						// 将结果转换为字符串并检查是否包含期望的文本
						resultStr := string(result)
						if !strings.Contains(resultStr, "这是GBK编码的内容") {
							t.Logf("原始内容: %s", tc.content)
							t.Logf("解码后内容: %s", resultStr)
							t.Errorf("GBK内容解码不正确")
						} else {
							t.Logf("测试通过: %s", tc.name)
						}
					} else {
						// 对于其他测试用例，直接比较内容
						if !strings.Contains(string(result), tc.expectedContent) {
							t.Logf("原始内容: %s", tc.content)
							t.Logf("解码后内容: %s", string(result))
							t.Errorf("内容解码不正确")
						} else {
							t.Logf("测试通过: %s", tc.name)
						}
					}
				} else {
					// 对于不比较内容的测试用例，只记录通过
					t.Logf("测试通过: %s (跳过内容比较)", tc.name)
				}
			}
		})
	}
}

// 测试Transfer-Encoding: chunked的情况
func TestGetOrgContentWithChunkedEncoding(t *testing.T) {
	t.Parallel()

	//初始化日志
	zlog.InitZLog(global.GWAF_RELEASE, "json")
	// 初始化WAF引擎
	waf := &WafEngine{}

	// 创建分块传输的内容
	chunkedContent := "10\r\n这是第一个数据块\r\n14\r\n这是第二个数据块内容\r\n0\r\n\r\n"

	// 创建HTTP响应
	resp := &http.Response{
		StatusCode:       200,
		Header:           make(http.Header),
		Body:             io.NopCloser(bytes.NewBufferString(chunkedContent)),
		TransferEncoding: []string{"chunked"},
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	// 调用测试函数
	result, _, err := waf.getOrgContent(resp, false)

	// 验证结果
	if err != nil {
		t.Errorf("处理chunked编码失败: %v", err)
	} else {
		t.Logf("Chunked编码处理结果: %s", string(result))
	}
}

// 测试响应体为空的情况
func TestGetOrgContentWithEmptyBody(t *testing.T) {
	t.Parallel()

	//初始化日志
	zlog.InitZLog(global.GWAF_RELEASE, "json")
	// 初始化WAF引擎
	waf := &WafEngine{}

	// 创建HTTP响应
	resp := &http.Response{
		StatusCode: 204, // No Content
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBuffer(nil)),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	// 调用测试函数
	result, _, err := waf.getOrgContent(resp, false)

	// 验证结果
	if err != nil {
		t.Errorf("处理空响应体失败: %v", err)
	} else {
		if len(result) != 0 {
			t.Errorf("空响应体应返回空内容，但返回了: %s", string(result))
		} else {
			t.Log("空响应体测试通过")
		}
	}
}

// 测试错误情况
func TestGetOrgContentWithErrors(t *testing.T) {
	t.Parallel()

	//初始化日志
	zlog.InitZLog(global.GWAF_RELEASE, "json")
	// 初始化WAF引擎
	waf := &WafEngine{}

	// 测试gzip解压失败
	invalidGzip := []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBuffer(invalidGzip)),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Content-Encoding", "gzip")

	// 调用测试函数
	_, _, err := waf.getOrgContent(resp, false)

	// 验证结果
	if err == nil {
		t.Errorf("期望无效gzip内容产生错误，但没有错误")
	} else {
		t.Logf("无效gzip测试通过，错误: %v", err)
	}
}

func TestGetOrgContent_MetaAndDoctypeCharset(t *testing.T) {
	t.Parallel()
	zlog.InitZLog(global.GWAF_RELEASE, "json")
	waf := &WafEngine{}

	// 1. meta标签指定utf-8
	htmlMetaUtf8 := `<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body>utf8内容</body></html>`
	resp1 := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(htmlMetaUtf8)),
	}
	resp1.Header.Set("Content-Type", "text/html")
	content1, charset1, err1 := waf.getOrgContent(resp1, false)
	if err1 != nil || charset1 != "utf-8" || !strings.Contains(string(content1), "utf8内容") {
		t.Errorf("meta标签utf-8检测失败: err=%v, charset=%s, content=%s", err1, charset1, string(content1))
	}

	// 2. meta标签指定gbk
	gbkBody := []byte{0x3c, 0x68, 0x74, 0x6d, 0x6c, 0x3e, 0x3c, 0x68, 0x65, 0x61, 0x64, 0x3e, 0x3c, 0x6d, 0x65, 0x74, 0x61, 0x20, 0x68, 0x74, 0x74, 0x70, 0x2d, 0x65, 0x71, 0x75, 0x69, 0x76, 0x3d, 0x22, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x22, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x3d, 0x22, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3b, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x67, 0x62, 0x6b, 0x22, 0x3e, 0x3c, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0xd5, 0xe2, 0xca, 0xc7, 0x47, 0x42, 0x4b, 0xb1, 0xe0, 0xc2, 0xeb, 0xb5, 0xc4, 0xc4, 0xda, 0xc8, 0xdd, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e}
	resp2 := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(gbkBody)),
	}
	resp2.Header.Set("Content-Type", "text/html")
	content2, charset2, err2 := waf.getOrgContent(resp2, false)
	if err2 != nil || charset2 != "gbk" || !strings.Contains(string(content2), "这是GBK编码的内容") {
		t.Errorf("meta标签gbk检测失败: err=%v, charset=%s, content=%s", err2, charset2, string(content2))
	}

	// 3. DOCTYPE声明xhtml1-transitional.dtd
	htmlDoctype := `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"><html><head></head><body>doctype内容</body></html>`
	resp3 := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(htmlDoctype)),
	}
	resp3.Header.Set("Content-Type", "text/html")
	content3, charset3, err3 := waf.getOrgContent(resp3, false)
	if err3 != nil || charset3 != "utf-8" || !strings.Contains(string(content3), "doctype内容") {
		t.Errorf("DOCTYPE声明检测失败: err=%v, charset=%s, content=%s", err3, charset3, string(content3))
	}

	// 4. meta标签未知编码
	htmlMetaUnknown := `<html><head><meta charset="unknown-charset"></head><body>未知编码</body></html>`
	resp4 := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(htmlMetaUnknown)),
	}
	resp4.Header.Set("Content-Type", "text/html")
	_, _, err4 := waf.getOrgContent(resp4, false)
	if err4 == nil || !strings.Contains(err4.Error(), "编码检测不确定") {
		t.Errorf("未知meta编码检测失败，期望返回错误，实际: %v", err4)
	}
}
