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

func TestCheckAllowURL(t *testing.T) {
	t.Parallel()

	//初始化日志
	zlog.InitZLog(global.GWAF_RELEASE)
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
		UrlWhiteLists: []model.URLAllowList{
			{
				CompareType: "等于",
				Url:         "/public",
			},
			{
				CompareType: "前缀匹配",
				Url:         "/static/",
			},
			{
				CompareType: "后缀匹配",
				Url:         ".css",
			},
			{
				CompareType: "包含匹配",
				Url:         "assets",
			},
		},
	}

	// 创建本地主机配置
	localHost := &wafenginmodel.HostSafe{
		Host: model.Hosts{
			GUARD_STATUS: 1, // 启用防护
		},
		UrlWhiteLists: []model.URLAllowList{
			{
				CompareType: "等于",
				Url:         "/local/public",
			},
			{
				CompareType: "前缀匹配",
				Url:         "/local/static/",
			},
			{
				CompareType: "后缀匹配",
				Url:         ".js",
			},
			{
				CompareType: "包含匹配",
				Url:         "resources",
			},
		},
	}

	// 测试用例
	testCases := []struct {
		name              string
		url               string
		expectedJumpGuard bool
		isGlobalRule      bool
	}{
		// 本地规则测试 - 大小写匹配
		{
			name:              "本地规则 - 等于匹配 (大小写相同)",
			url:               "/local/public",
			expectedJumpGuard: true,
			isGlobalRule:      false,
		},
		{
			name:              "本地规则 - 等于匹配 (大小写不同)",
			url:               "/LOCAL/PUBLIC",
			expectedJumpGuard: true,
			isGlobalRule:      false,
		},
		{
			name:              "本地规则 - 前缀匹配 (大小写不同)",
			url:               "/LOCAL/STATIC/image.png",
			expectedJumpGuard: true,
			isGlobalRule:      false,
		},
		{
			name:              "本地规则 - 后缀匹配 (大小写不同)",
			url:               "/script.JS",
			expectedJumpGuard: true,
			isGlobalRule:      false,
		},
		{
			name:              "本地规则 - 包含匹配 (大小写不同)",
			url:               "/get-RESOURCES-data",
			expectedJumpGuard: true,
			isGlobalRule:      false,
		},

		// 全局规则测试
		{
			name:              "全局规则 - 等于匹配 (大小写不同)",
			url:               "/PUBLIC",
			expectedJumpGuard: true,
			isGlobalRule:      true,
		},
		{
			name:              "全局规则 - 前缀匹配 (大小写不同)",
			url:               "/STATIC/style.css",
			expectedJumpGuard: true,
			isGlobalRule:      true,
		},
		{
			name:              "全局规则 - 后缀匹配 (大小写不同)",
			url:               "/style.CSS",
			expectedJumpGuard: true,
			isGlobalRule:      true,
		},
		{
			name:              "全局规则 - 包含匹配 (大小写不同)",
			url:               "/get-ASSETS-data",
			expectedJumpGuard: true,
			isGlobalRule:      true,
		},

		// 不匹配的测试
		{
			name:              "不匹配任何规则",
			url:               "/restricted/page",
			expectedJumpGuard: false,
			isGlobalRule:      false,
		},
	}

	for _, tc := range testCases {
		tc := tc // 防止闭包问题
		t.Run(tc.name, func(t *testing.T) {
			// 创建请求和WebLog
			req, _ := http.NewRequest("GET", "http://example.com"+tc.url, nil)
			weblog := innerbean.WebLog{
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
					// 不设置任何URL白名单
				}
				result = waf.CheckAllowURL(req, weblog, formValues, emptyLocalHost, waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME])
			} else {
				// 测试本地规则 - 使用禁用的全局主机配置，确保只测试本地规则
				disabledGlobalHost := &wafenginmodel.HostSafe{
					Host: model.Hosts{
						GUARD_STATUS: 0, // 禁用全局防护
					},
				}
				result = waf.CheckAllowURL(req, weblog, formValues, localHost, disabledGlobalHost)
			}

			// 验证结果
			if result.JumpGuardResult != tc.expectedJumpGuard {
				t.Errorf("期望跳过防护状态为 %v，但得到 %v", tc.expectedJumpGuard, result.JumpGuardResult)
			}
		})
	}

	// 添加组合测试 - 同时测试本地规则和全局规则
	t.Run("组合测试 - 本地规则和全局规则", func(t *testing.T) {
		// 创建一个既匹配本地规则又匹配全局规则的URL
		url := "/local/static/assets/style.css"
		req, _ := http.NewRequest("GET", "http://example.com"+url, nil)
		weblog := innerbean.WebLog{
			URL: url,
		}

		// 调用测试函数
		result := waf.CheckAllowURL(req, weblog, nil, localHost, waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME])

		// 验证结果 - 应该匹配本地规则或全局规则，导致跳过防护
		if !result.JumpGuardResult {
			t.Errorf("期望跳过防护状态为 true，但得到 false")
		}
	})
}
