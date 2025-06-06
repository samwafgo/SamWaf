package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func TestCheckAntiLeech(t *testing.T) {
	// 初始化日志
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "json")

	// 初始化 WAF 引擎
	waf := &WafEngine{
		HostTarget: make(map[string]*wafenginmodel.HostSafe),
	}

	// 构造防盗链配置JSON
	antiLeechConfig := model.AntiLeechConfig{
		IsEnableAntiLeech: 1,
		FileTypes:         "gif|jpg|jpeg|png|bmp|swf",
		ValidReferers:     "none;server_names;*.example.com;~\\.google\\.;~\\.baidu\\.",
		Action:            "redirect",
		RedirectURL:       "https://example.com/403.jpg",
	}
	antiLeechJSON, _ := json.Marshal(antiLeechConfig)

	// 创建测试主机配置，模拟绑定多个域名
	hostTarget := &wafenginmodel.HostSafe{
		Host: model.Hosts{
			AntiLeechJSON: string(antiLeechJSON),
			BindMoreHost:  "alias1.com\nalias2.com",
		},
	}

	// 创建全局主机配置
	globalHostTarget := &wafenginmodel.HostSafe{}

	// 测试用例
	testCases := []struct {
		name          string
		url           string
		referer       string
		host          string
		expectBlocked bool
	}{
		{
			name:          "允许的Referer",
			url:           "/images/test.jpg",
			referer:       "https://sub.example.com/page",
			host:          "mysite.com",
			expectBlocked: false,
		},
		{
			name:          "允许的搜索引擎Referer",
			url:           "/images/test.png",
			referer:       "https://www.google.com/search",
			host:          "mysite.com",
			expectBlocked: false,
		},
		{
			name:          "无Referer但允许none",
			url:           "/images/test.gif",
			referer:       "",
			host:          "mysite.com",
			expectBlocked: false,
		},
		{
			name:          "同站点Referer",
			url:           "/images/test.jpeg",
			referer:       "https://mysite.com/page",
			host:          "mysite.com",
			expectBlocked: false,
		},
		{
			name:          "非法Referer",
			url:           "/images/test.bmp",
			referer:       "https://attacker.com/page",
			host:          "mysite.com",
			expectBlocked: true,
		},
		{
			name:          "非防盗链文件类型",
			url:           "/documents/test.pdf",
			referer:       "https://attacker.com/page",
			host:          "mysite.com",
			expectBlocked: false,
		},
		// 新增后置场景测试
		{
			name:          "带查询参数的图片",
			url:           "/images/test.jpg?ver=1.2",
			referer:       "https://attacker.com/page",
			host:          "mysite.com",
			expectBlocked: true,
		},
		{
			name:          "带锚点的图片",
			url:           "/images/test.png#section",
			referer:       "https://attacker.com/page",
			host:          "mysite.com",
			expectBlocked: true,
		},
		{
			name:          "路径末尾带斜杠",
			url:           "/images/test.jpg/",
			referer:       "https://attacker.com/page",
			host:          "mysite.com",
			expectBlocked: false, // 这种情况一般不会被正则识别为图片文件
		},
		{
			name:          "文件名大写扩展名",
			url:           "/images/TEST.JPG",
			referer:       "https://attacker.com/page",
			host:          "mysite.com",
			expectBlocked: true,
		},
		{
			name:          "带参数和锚点的图片",
			url:           "/images/test.jpeg?foo=bar#anchor",
			referer:       "https://attacker.com/page",
			host:          "mysite.com",
			expectBlocked: true,
		},
		{
			name:          "重定向目标再次访问",
			url:           "/403.jpg",
			referer:       "https://attacker.com/page",
			host:          "example.com", // 与RedirectURL主机一致
			expectBlocked: true,          // 推荐阻断，防止重定向循环
		},
		{
			name:          "绑定域名alias1.com同站点Referer",
			url:           "/images/test.jpeg",
			referer:       "https://alias1.com/page",
			host:          "alias1.com",
			expectBlocked: false,
		},
		{
			name:          "绑定域名alias2.com同站点Referer",
			url:           "/images/test.jpeg",
			referer:       "https://alias2.com/page",
			host:          "alias2.com",
			expectBlocked: false,
		},
		{
			name:          "绑定域名alias1.com非法Referer",
			url:           "/images/test.jpeg",
			referer:       "https://evil.com/page",
			host:          "alias1.com",
			expectBlocked: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tc.url, nil)
			req.Host = tc.host
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			weblog := &innerbean.WebLog{
				URL: tc.url,
			}
			result := waf.CheckAntiLeech(req, weblog, url.Values{}, hostTarget, globalHostTarget)
			if result.IsBlock != tc.expectBlocked {
				t.Errorf("测试 '%s' 失败: 期望阻止=%v, 实际=%v", tc.name, tc.expectBlocked, result.IsBlock)
			}
		})
	}
}
