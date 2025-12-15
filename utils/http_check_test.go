package utils

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsStaticAssist_ContentType 测试响应Content-Type判断静态资源
func TestIsStaticAssist_ContentType(t *testing.T) {
	t.Parallel()

	//初始化日志
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "console")
	if v := recover(); v != nil {
		zlog.Error("error")
	}
	tests := []struct {
		name        string
		contentType string
		wantStatic  bool
		description string
	}{
		{
			name:        "图片-jpeg",
			contentType: "image/jpeg",
			wantStatic:  true,
			description: "标准的image/jpeg应该被识别为静态资源",
		},
		{
			name:        "图片-jpeg-带charset",
			contentType: "image/jpeg;charset=UTF-8",
			wantStatic:  true,
			description: "带charset的image/jpeg应该被识别为静态资源",
		},
		{
			name:        "图片-png",
			contentType: "image/png",
			wantStatic:  true,
			description: "image/png应该被识别为静态资源",
		},
		{
			name:        "图片-gif",
			contentType: "image/gif",
			wantStatic:  true,
			description: "image/gif应该被识别为静态资源",
		},
		{
			name:        "图片-webp",
			contentType: "image/webp",
			wantStatic:  true,
			description: "image/webp应该被识别为静态资源",
		},
		{
			name:        "图片-svg",
			contentType: "image/svg+xml",
			wantStatic:  true,
			description: "image/svg+xml应该被识别为静态资源",
		},
		{
			name:        "CSS样式",
			contentType: "text/css",
			wantStatic:  true,
			description: "text/css应该被识别为静态资源",
		},
		{
			name:        "JavaScript",
			contentType: "application/javascript",
			wantStatic:  true,
			description: "application/javascript应该被识别为静态资源",
		},
		{
			name:        "字体-woff2",
			contentType: "font/woff2",
			wantStatic:  true,
			description: "font/woff2应该被识别为静态资源",
		},
		{
			name:        "视频-mp4",
			contentType: "video/mp4",
			wantStatic:  true,
			description: "video/mp4应该被识别为静态资源",
		},
		{
			name:        "音频-mp3",
			contentType: "audio/mpeg",
			wantStatic:  true,
			description: "audio/mpeg应该被识别为静态资源",
		},
		{
			name:        "HTML页面",
			contentType: "text/html",
			wantStatic:  false,
			description: "text/html不应该被识别为静态资源",
		},
		{
			name:        "JSON数据",
			contentType: "application/json",
			wantStatic:  false,
			description: "application/json不应该被识别为静态资源",
		},
		{
			name:        "XML数据",
			contentType: "text/xml",
			wantStatic:  false,
			description: "text/xml不应该被识别为静态资源",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建一个模拟的HTTP请求
			req := httptest.NewRequest("GET", "http://localhost/test", nil)
			// 模拟浏览器的标准Accept头（即使是图片请求，浏览器也会发送这样的头）
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")

			// 创建一个模拟的HTTP响应
			res := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Request:    req,
			}
			res.Header.Set("Content-Type", tt.contentType)

			// 调用测试方法
			got := IsStaticAssist(res, tt.contentType)

			// 验证结果
			if got != tt.wantStatic {
				t.Errorf("IsStaticAssist() = %v, want %v\n说明: %s\nContent-Type: %s",
					got, tt.wantStatic, tt.description, tt.contentType)
			} else {
				t.Logf("✓ 测试通过: %s\n  Content-Type: %s\n  结果: %v (期望: %v)\n  说明: %s",
					tt.name, tt.contentType, got, tt.wantStatic, tt.description)
			}
		})
	}
}

// TestIsStaticAssist_RealWorldScenario 测试真实场景：浏览器直接访问图片URL
func TestIsStaticAssist_RealWorldScenario(t *testing.T) {
	t.Parallel()

	//初始化日志
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "console")
	if v := recover(); v != nil {
		zlog.Error("error")
	}
	t.Run("浏览器直接访问图片URL", func(t *testing.T) {
		// 模拟用户在浏览器地址栏输入图片URL的场景
		req := httptest.NewRequest("GET", "http://localhost:9999/image.jpg", nil)

		// 浏览器会发送标准的Accept头，而不是image/*开头的
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
		req.Header.Set("Cache-Control", "max-age=0")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Host", "localhost:9999")
		req.Header.Set("Sec-Ch-Ua", `"Google Chrome";v="143", "Not A(Brand";v="24"`)
		req.Header.Set("Sec-Ch-Ua-Mobile", "70")

		// 服务器返回图片
		res := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    req,
		}
		res.Header.Set("Content-Type", "image/jpeg;charset=UTF-8")
		res.Header.Set("Date", "Mon, 08 Dec 2025 13:22:50 GMT")
		res.Header.Set("Transfer-Encoding", "chunked")

		contentType := res.Header.Get("Content-Type")
		got := IsStaticAssist(res, contentType)

		if !got {
			t.Errorf("真实场景测试失败！\n"+
				"场景: 浏览器直接访问图片URL\n"+
				"URL: %s\n"+
				"Content-Type: %s\n"+
				"Accept: %s\n"+
				"结果: %v (期望: true)\n"+
				"问题: 即使响应Content-Type是image/jpeg，也没有被正确识别为静态资源",
				req.URL.String(), contentType, req.Header.Get("Accept"), got)
		} else {
			t.Logf("✓ 真实场景测试通过！\n"+
				"场景: 浏览器直接访问图片URL\n"+
				"URL: %s\n"+
				"Content-Type: %s\n"+
				"Accept: %s\n"+
				"结果: 正确识别为静态资源",
				req.URL.String(), contentType, req.Header.Get("Accept"))
		}
	})
}
