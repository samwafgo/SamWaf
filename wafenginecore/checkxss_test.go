package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
	"testing"
)

func newTestWafForXSS() (*WafEngine, *wafenginmodel.HostSafe) {
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "json")
	waf := &WafEngine{
		HostTarget: make(map[string]*wafenginmodel.HostSafe),
	}
	global.GWAF_GLOBAL_HOST_NAME = "全局网站"
	waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME] = &wafenginmodel.HostSafe{
		Host: model.Hosts{GUARD_STATUS: 1},
	}
	hostSafe := &wafenginmodel.HostSafe{
		Host: model.Hosts{GUARD_STATUS: 1},
	}
	return waf, hostSafe
}

func TestCheckXss(t *testing.T) {
	waf, hostSafe := newTestWafForXSS()
	globalHost := waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME]

	tests := []struct {
		name        string
		rawQuery    string
		postForm    string
		formValues  url.Values
		expectBlock bool
		desc        string
	}{
		// --- 误报修复 ---
		{
			name:        "误报修复-style参数名在RawQuery中",
			rawQuery:    "style=ptype&ptypeid=000050004500108&orderid=1615",
			expectBlock: false,
			desc:        "参数名 style 不应触发 XSS 拦截",
		},
		{
			name:        "误报修复-filter和class参数名",
			rawQuery:    "filter=name&class=active&id=123",
			expectBlock: false,
			desc:        "参数名 filter/class/id 不应触发 XSS 拦截",
		},
		{
			name:        "误报修复-href和src参数名",
			rawQuery:    "href=home&src=logo&action=submit",
			expectBlock: false,
			desc:        "参数名 href/src/action 不应触发 XSS 拦截",
		},

		// --- 正常请求 ---
		{
			name:        "正常-分页参数",
			rawQuery:    "page=1&size=20&keyword=hello",
			expectBlock: false,
			desc:        "正常分页参数不应被拦截",
		},
		{
			name:        "正常-空查询串",
			rawQuery:    "",
			expectBlock: false,
			desc:        "空查询串不应被拦截",
		},

		// --- 真实 XSS ---
		{
			name:        "真实XSS-script标签在RawQuery值中",
			rawQuery:    "name=<script>alert(1)</script>",
			expectBlock: true,
			desc:        "参数值包含 <script> 应被拦截",
		},
		{
			name:        "真实XSS-img_onerror在RawQuery值中",
			rawQuery:    `q="><img src=x onerror=alert(1)>`,
			expectBlock: true,
			desc:        "参数值包含 img onerror 应被拦截",
		},
		{
			name:        "真实XSS-script标签在POST_FORM中",
			postForm:    "comment=<script>alert(1)</script>&submit=ok",
			expectBlock: true,
			desc:        "POST 表单参数值含 <script> 应被拦截",
		},
		{
			name:     "formValues检测暂未启用-不拦截",
			rawQuery: "page=1",
			formValues: url.Values{
				"input": []string{"<script>alert(1)</script>"},
			},
			expectBlock: false,
			desc:        "formValue 检测当前暂时禁用（业务存在误报风险），不触发拦截",
		},
		{
			name:        "真实XSS-svg在值中",
			rawQuery:    "data=<svg/onload=alert(1)>",
			expectBlock: true,
			desc:        "参数值包含 svg onload 应被拦截",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com/path?"+tt.rawQuery, nil)
			weblog := &innerbean.WebLog{
				RawQuery:  tt.rawQuery,
				POST_FORM: tt.postForm,
			}
			formValues := tt.formValues
			if formValues == nil {
				formValues = url.Values{}
			}

			result := waf.CheckXss(req, weblog, formValues, hostSafe, globalHost)

			if result.IsBlock != tt.expectBlock {
				t.Errorf("[%s] IsBlock = %v, 期望 %v (query=%q, postForm=%q)",
					tt.desc, result.IsBlock, tt.expectBlock, tt.rawQuery, tt.postForm)
			}
			if tt.expectBlock {
				if result.Title != "XSS跨站注入" {
					t.Errorf("期望 Title 为 'XSS跨站注入', 实际为 %q", result.Title)
				}
				if weblog.RISK_LEVEL != 2 {
					t.Errorf("期望 RISK_LEVEL = 2, 实际为 %d", weblog.RISK_LEVEL)
				}
			}
		})
	}
}
