package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
	"testing"
)

func TestCheckDenyURL(t *testing.T) {
	t.Parallel()

	//初始化日志
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "json")
	// 初始化 WAF 引擎
	waf := &WafEngine{
		HostTarget: make(map[string]*wafenginmodel.HostSafe),
	}

	// 设置全局主机
	global.GWAF_GLOBAL_HOST_NAME = "全局网站"
	waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME] = &wafenginmodel.HostSafe{
		Host: model.Hosts{
			GUARD_STATUS: 1, // 启用防护
		},
		UrlBlockLists: []model.URLBlockList{
			{
				CompareType: "等于",
				Url:         "/admin",
			},
			{
				CompareType: "前缀匹配",
				Url:         "/api/v1",
			},
			{
				CompareType: "后缀匹配",
				Url:         ".php",
			},
			{
				CompareType: "包含匹配",
				Url:         "password",
			},
		},
	}

	// 创建本地主机配置
	localHost := &wafenginmodel.HostSafe{
		Host: model.Hosts{
			GUARD_STATUS: 1, // 启用防护
		},
		UrlBlockLists: []model.URLBlockList{
			{
				CompareType: "等于",
				Url:         "/local/admin",
			},
			{
				CompareType: "前缀匹配",
				Url:         "/local/api",
			},
			{
				CompareType: "后缀匹配",
				Url:         ".aspx",
			},
			{
				CompareType: "包含匹配",
				Url:         "secret",
			},
		},
	}

	// 测试用例
	testCases := []struct {
		name          string
		url           string
		expectedBlock bool
		expectedTitle string
		isGlobalRule  bool
	}{
		// 本地规则测试 - 大小写匹配
		{
			name:          "本地规则 - 等于匹配 (大小写相同)",
			url:           "/local/admin",
			expectedBlock: true,
			expectedTitle: "URL黑名单",
			isGlobalRule:  false,
		},
		{
			name:          "本地规则 - 等于匹配 (大小写不同)",
			url:           "/LOCAL/ADMIN",
			expectedBlock: true,
			expectedTitle: "URL黑名单",
			isGlobalRule:  false,
		},
		{
			name:          "本地规则 - 前缀匹配 (大小写不同)",
			url:           "/LOCAL/API/users",
			expectedBlock: true,
			expectedTitle: "URL黑名单",
			isGlobalRule:  false,
		},
		{
			name:          "本地规则 - 后缀匹配 (大小写不同)",
			url:           "/page.ASPX",
			expectedBlock: true,
			expectedTitle: "URL黑名单",
			isGlobalRule:  false,
		},
		{
			name:          "本地规则 - 包含匹配 (大小写不同)",
			url:           "/get-SECRET-data",
			expectedBlock: true,
			expectedTitle: "URL黑名单",
			isGlobalRule:  false,
		},

		// 全局规则测试
		{
			name:          "全局规则 - 等于匹配 (大小写不同)",
			url:           "/ADMIN",
			expectedBlock: true,
			expectedTitle: "【全局】URL黑名单",
			isGlobalRule:  true,
		},
		{
			name:          "全局规则 - 前缀匹配 (大小写不同)",
			url:           "/API/v1/users",
			expectedBlock: true,
			expectedTitle: "【全局】URL黑名单",
			isGlobalRule:  true,
		},
		{
			name:          "全局规则 - 后缀匹配 (大小写不同)",
			url:           "/script.PHP",
			expectedBlock: true,
			expectedTitle: "【全局】URL黑名单",
			isGlobalRule:  true,
		},
		{
			name:          "全局规则 - 包含匹配 (大小写不同)",
			url:           "/reset-PASSWORD",
			expectedBlock: true,
			expectedTitle: "【全局】URL黑名单",
			isGlobalRule:  true,
		},

		// 不匹配的测试
		{
			name:          "不匹配任何规则",
			url:           "/normal/page",
			expectedBlock: false,
			expectedTitle: "",
			isGlobalRule:  false,
		},
	}

	for _, tc := range testCases {
		tc := tc // 防止闭包问题
		t.Run(tc.name, func(t *testing.T) {
			// 创建请求和WebLog
			req, _ := http.NewRequest("GET", "http://example.com"+tc.url, nil)
			weblog := &innerbean.WebLog{
				URL: tc.url,
			}

			// 创建空的表单值
			formValues := url.Values{}

			// 调用测试函数
			var result detection.Result
			if tc.isGlobalRule {
				// 测试全局规则 - 使用空的本地主机配置，确保只测试全局规则
				emptyLocalHost := &wafenginmodel.HostSafe{
					Host: model.Hosts{
						GUARD_STATUS: 1,
					},
					// 不设置任何URL黑名单
				}
				result = waf.CheckDenyURL(req, weblog, formValues, emptyLocalHost, waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME])
			} else {
				// 测试本地规则 - 使用禁用的全局主机配置，确保只测试本地规则
				disabledGlobalHost := &wafenginmodel.HostSafe{
					Host: model.Hosts{
						GUARD_STATUS: 0, // 禁用全局防护
					},
				}
				result = waf.CheckDenyURL(req, weblog, formValues, localHost, disabledGlobalHost)
			}

			// 验证结果
			if result.IsBlock != tc.expectedBlock {
				t.Errorf("期望阻止状态为 %v，但得到 %v", tc.expectedBlock, result.IsBlock)
			}

			if tc.expectedBlock && result.Title != tc.expectedTitle {
				t.Errorf("期望标题为 %s，但得到 %s", tc.expectedTitle, result.Title)
			}
		})
	}

	// 添加组合测试 - 同时测试本地规则和全局规则
	t.Run("组合测试 - 本地规则和全局规则", func(t *testing.T) {
		// 创建一个既匹配本地规则又匹配全局规则的URL
		url := "/local/api/password"
		req, _ := http.NewRequest("GET", "http://example.com"+url, nil)
		weblog := &innerbean.WebLog{
			URL: url,
		}

		// 调用测试函数
		result := waf.CheckDenyURL(req, weblog, nil, localHost, waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME])

		// 验证结果 - 应该匹配本地规则（因为本地规则优先）
		if !result.IsBlock {
			t.Errorf("期望阻止状态为 true，但得到 false")
		}

		if result.Title != "URL黑名单" {
			t.Errorf("期望标题为 URL黑名单，但得到 %s", result.Title)
		}
	})
}
