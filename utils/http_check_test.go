package utils

import (
	"net/http"
	"net/url"
	"testing"
)

func TestIsStaticAssist(t *testing.T) {
	// 创建测试用例
	tests := []struct {
		name        string
		contentType string
		request     *http.Request
		expected    bool
	}{
		// 1. 基于Content-Type的测试 - 静态资源类型
		{
			name:        "JavaScript Content Type",
			contentType: "application/javascript; charset=utf-8",
			request:     nil,
			expected:    true,
		},
		{
			name:        "CSS Content Type",
			contentType: "text/css; charset=utf-8",
			request:     nil,
			expected:    true,
		},
		{
			name:        "Image JPEG Content Type",
			contentType: "image/jpeg",
			request:     nil,
			expected:    true,
		},
		{
			name:        "Image PNG Content Type",
			contentType: "image/png",
			request:     nil,
			expected:    true,
		},
		{
			name:        "Image GIF Content Type",
			contentType: "image/gif",
			request:     nil,
			expected:    true,
		},
		{
			name:        "Image Icon Content Type",
			contentType: "image/x-icon",
			request:     nil,
			expected:    true,
		},
		{
			name:        "Text JS Content Type",
			contentType: "text/js",
			request:     nil,
			expected:    true,
		},
		{
			name:        "Octet Stream Content Type",
			contentType: "application/octet-stream",
			request:     nil,
			expected:    true,
		},
		{
			name:        "SVG Content Type",
			contentType: "image/svg+xml",
			request:     nil,
			expected:    true,
		},
		{
			name:        "WebP Content Type",
			contentType: "image/webp",
			request:     nil,
			expected:    true,
		},
		{
			name:        "WOFF Font Content Type",
			contentType: "font/woff",
			request:     nil,
			expected:    true,
		},
		{
			name:        "WOFF2 Font Content Type",
			contentType: "font/woff2",
			request:     nil,
			expected:    true,
		},
		{
			name:        "TTF Font Content Type",
			contentType: "font/ttf",
			request:     nil,
			expected:    true,
		},
		{
			name:        "OTF Font Content Type",
			contentType: "font/otf",
			request:     nil,
			expected:    true,
		},
		{
			name:        "MS Font Object Content Type",
			contentType: "application/vnd.ms-fontobject",
			request:     nil,
			expected:    true,
		},
		{
			name:        "X-Font-TTF Content Type",
			contentType: "application/x-font-ttf",
			request:     nil,
			expected:    true,
		},
		{
			name:        "Audio MPEG Content Type",
			contentType: "audio/mpeg",
			request:     nil,
			expected:    true,
		},
		{
			name:        "Audio WAV Content Type",
			contentType: "audio/wav",
			request:     nil,
			expected:    true,
		},
		{
			name:        "Video MP4 Content Type",
			contentType: "video/mp4",
			request:     nil,
			expected:    true,
		},
		{
			name:        "Video WebM Content Type",
			contentType: "video/webm",
			request:     nil,
			expected:    true,
		},
		{
			name:        "PDF Content Type",
			contentType: "application/pdf",
			request:     nil,
			expected:    true,
		},
		{
			name:        "BMP Content Type",
			contentType: "image/bmp",
			request:     nil,
			expected:    true,
		},
		{
			name:        "Video OGG Content Type",
			contentType: "video/ogg",
			request:     nil,
			expected:    true,
		},
		{
			name:        "Audio OGG Content Type",
			contentType: "audio/ogg",
			request:     nil,
			expected:    true,
		},
		{
			name:        "WASM Content Type",
			contentType: "application/wasm",
			request:     nil,
			expected:    true,
		},

		// 2. 基于Content-Type的测试 - 文本类型
		{
			name:        "HTML Content Type",
			contentType: "text/html; charset=utf-8",
			request:     nil,
			expected:    false,
		},
		{
			name:        "JSON Content Type",
			contentType: "application/json; charset=utf-8",
			request:     nil,
			expected:    false,
		},
		{
			name:        "XML Content Type",
			contentType: "text/xml",
			request:     nil,
			expected:    false,
		},
		{
			name:        "Application XML Content Type",
			contentType: "application/xml",
			request:     nil,
			expected:    false,
		},
		{
			name:        "Plain Text Content Type",
			contentType: "text/plain",
			request:     nil,
			expected:    false,
		},
		{
			name:        "CSV Content Type",
			contentType: "text/csv",
			request:     nil,
			expected:    false,
		},
		{
			name:        "Application HTML Content Type",
			contentType: "application/html",
			request:     nil,
			expected:    false,
		},

		// 3. 基于Sec-Fetch-Dest的测试
		{
			name:        "Sec-Fetch-Dest: image",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Sec-Fetch-Dest": "image"}),
			expected:    true,
		},
		{
			name:        "Sec-Fetch-Dest: font",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Sec-Fetch-Dest": "font"}),
			expected:    true,
		},
		{
			name:        "Sec-Fetch-Dest: audio",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Sec-Fetch-Dest": "audio"}),
			expected:    true,
		},
		{
			name:        "Sec-Fetch-Dest: video",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Sec-Fetch-Dest": "video"}),
			expected:    true,
		},
		{
			name:        "Sec-Fetch-Dest: style",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Sec-Fetch-Dest": "style"}),
			expected:    true,
		},
		{
			name:        "Sec-Fetch-Dest: script",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Sec-Fetch-Dest": "script"}),
			expected:    true,
		},
		{
			name:        "Sec-Fetch-Dest: document",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Sec-Fetch-Dest": "document"}),
			expected:    false,
		},
		{
			name:        "Sec-Fetch-Dest: empty",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Sec-Fetch-Dest": ""}),
			expected:    false,
		},

		// 4. 基于Accept的测试
		{
			name:        "Accept: image/*",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Accept": "image/*"}),
			expected:    true,
		},
		{
			name:        "Accept: font/*",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Accept": "font/*"}),
			expected:    true,
		},
		{
			name:        "Accept: audio/*",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Accept": "audio/*"}),
			expected:    true,
		},
		{
			name:        "Accept: video/*",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Accept": "video/*"}),
			expected:    true,
		},
		{
			name:        "Accept: text/css",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Accept": "text/css"}),
			expected:    true,
		},
		{
			name:        "Accept: application/javascript",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Accept": "application/javascript"}),
			expected:    true,
		},
		{
			name:        "Accept: application/pdf",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Accept": "application/pdf"}),
			expected:    true,
		},
		{
			name:        "Accept: text/html",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Accept": "text/html"}),
			expected:    false,
		},
		{
			name:        "Accept: */*",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeaders(map[string]string{"Accept": "*/*"}),
			expected:    false,
		},

		// 5. 基于URL后缀的测试
		{
			name:        "URL with .js extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/script.js"),
			expected:    true,
		},
		{
			name:        "URL with .css extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/style.css"),
			expected:    true,
		},
		{
			name:        "URL with .jpg extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/image.jpg"),
			expected:    true,
		},
		{
			name:        "URL with .jpeg extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/image.jpeg"),
			expected:    true,
		},
		{
			name:        "URL with .png extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/image.png"),
			expected:    true,
		},
		{
			name:        "URL with .gif extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/image.gif"),
			expected:    true,
		},
		{
			name:        "URL with .ico extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/favicon.ico"),
			expected:    true,
		},
		{
			name:        "URL with .svg extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/image.svg"),
			expected:    true,
		},
		{
			name:        "URL with .webp extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/image.webp"),
			expected:    true,
		},
		{
			name:        "URL with .woff extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/font.woff"),
			expected:    true,
		},
		{
			name:        "URL with .woff2 extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/font.woff2"),
			expected:    true,
		},
		{
			name:        "URL with .ttf extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/font.ttf"),
			expected:    true,
		},
		{
			name:        "URL with .otf extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/font.otf"),
			expected:    true,
		},
		{
			name:        "URL with .eot extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/font.eot"),
			expected:    true,
		},
		{
			name:        "URL with .mp3 extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/audio.mp3"),
			expected:    true,
		},
		{
			name:        "URL with .wav extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/audio.wav"),
			expected:    true,
		},
		{
			name:        "URL with .mp4 extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/video.mp4"),
			expected:    true,
		},
		{
			name:        "URL with .webm extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/video.webm"),
			expected:    true,
		},
		{
			name:        "URL with .pdf extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/document.pdf"),
			expected:    true,
		},
		{
			name:        "URL with .swf extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/flash.swf"),
			expected:    true,
		},
		{
			name:        "URL with .html extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/page.html"),
			expected:    false,
		},
		{
			name:        "URL with .php extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/page.php"),
			expected:    false,
		},
		{
			name:        "URL with no extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/page"),
			expected:    false,
		},

		// 6. 复合测试 - 多个条件组合
		{
			name:        "Static Content-Type with static URL extension",
			contentType: "image/jpeg",
			request:     createRequestWithURL("https://example.com/image.jpg"),
			expected:    true,
		},
		{
			name:        "Static Content-Type with non-static URL extension",
			contentType: "image/jpeg",
			request:     createRequestWithURL("https://example.com/image.html"),
			expected:    true, // Content-Type优先
		},
		{
			name:        "Non-static Content-Type with static URL extension",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithURL("https://example.com/image.jpg"),
			expected:    true, // URL后缀优先
		},
		{
			name:        "Static Content-Type with Sec-Fetch-Dest: document",
			contentType: "image/jpeg",
			request:     createRequestWithHeadersAndURL(map[string]string{"Sec-Fetch-Dest": "document"}, "https://example.com/image"),
			expected:    true, // Content-Type优先
		},
		{
			name:        "Non-static Content-Type with Sec-Fetch-Dest: image",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeadersAndURL(map[string]string{"Sec-Fetch-Dest": "image"}, "https://example.com/page"),
			expected:    true, // Sec-Fetch-Dest优先
		},
		{
			name:        "Non-static Content-Type with Accept: image/*",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeadersAndURL(map[string]string{"Accept": "image/*"}, "https://example.com/page"),
			expected:    true, // Accept优先
		},
		{
			name:        "All conditions non-static",
			contentType: "text/html; charset=utf-8",
			request:     createRequestWithHeadersAndURL(map[string]string{"Sec-Fetch-Dest": "document", "Accept": "text/html"}, "https://example.com/page.html"),
			expected:    false, // 所有条件都不满足
		},

		// 7. 边界情况
		{
			name:        "Empty Content-Type",
			contentType: "",
			request:     nil,
			expected:    false,
		},
		{
			name:        "Content-Type with only charset",
			contentType: "charset=utf-8",
			request:     nil,
			expected:    false,
		},
		{
			name:        "Unknown Content-Type",
			contentType: "application/unknown",
			request:     nil,
			expected:    false,
		},
		{
			name:        "Nil Request",
			contentType: "text/html; charset=utf-8",
			request:     nil,
			expected:    false,
		},
		{
			name:        "Request with nil URL",
			contentType: "text/html; charset=utf-8",
			request:     &http.Request{},
			expected:    false,
		},
	}

	// 执行测试
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建响应对象
			resp := &http.Response{
				Request: tt.request,
				Header:  make(http.Header),
			}

			// 设置响应的Content-Type
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}

			// 调用被测试函数
			result := IsStaticAssist(resp, tt.contentType)

			// 验证结果
			if result != tt.expected {
				t.Errorf("IsStaticAssist() = %v, want %v for test: %s", result, tt.expected, tt.name)
			}
		})
	}
}

// 辅助函数：创建带有指定头部的请求
func createRequestWithHeaders(headers map[string]string) *http.Request {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req
}

// 辅助函数：创建带有指定URL的请求
func createRequestWithURL(urlStr string) *http.Request {
	parsedURL, _ := url.Parse(urlStr)
	req, _ := http.NewRequest("GET", urlStr, nil)
	req.URL = parsedURL
	return req
}

// 辅助函数：创建带有指定头部和URL的请求
func createRequestWithHeadersAndURL(headers map[string]string, urlStr string) *http.Request {
	parsedURL, _ := url.Parse(urlStr)
	req, _ := http.NewRequest("GET", urlStr, nil)
	req.URL = parsedURL
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req
}
