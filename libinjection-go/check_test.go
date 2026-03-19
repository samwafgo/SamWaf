package libinjection

import (
	"testing"
)

func TestContainsXSSChars(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"空字符串", "", false},
		{"普通字母数字", "hello123", false},
		{"普通URL参数值", "ptype", false},
		{"纯数字", "000050004500108", false},
		{"含小于号", "<script>", true},
		{"含大于号", "tag>", true},
		{"含双引号", `"value"`, true},
		{"含单引号", "it's", true},
		{"含左括号", "alert(", true},
		{"含右括号", ")drop", true},
		{"含反引号", "`cmd`", true},
		{"含斜杠", "a/b", true},
		{"中文字符", "你好世界", false},
		{"中划线下划线", "hello-world_test", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsXSSChars(tt.input)
			if got != tt.expected {
				t.Errorf("containsXSSChars(%q) = %v, 期望 %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsXSSInQueryValues(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected bool
		desc     string
	}{
		// --- 误报修复场景 ---
		{
			name:     "误报-style参数名",
			query:    "style=ptype&ptypeid=000050004500108&orderid=1615",
			expected: false,
			desc:     "参数名 style 不应触发 XSS，只检测值",
		},
		{
			name:     "误报-filter和class参数名",
			query:    "filter=name&class=active&id=123",
			expected: false,
			desc:     "参数名 filter/class/id 不应触发 XSS",
		},
		{
			name:     "误报-href参数名",
			query:    "href=home&src=logo&action=submit",
			expected: false,
			desc:     "参数名 href/src/action 不应触发 XSS",
		},
		{
			name:     "误报-on前缀参数名",
			query:    "onclick=submit&onload=1",
			expected: false,
			desc:     "参数名 onclick 不应触发 XSS，因为其值不含特殊字符",
		},

		// --- 正常请求场景 ---
		{
			name:     "正常-分页参数",
			query:    "page=1&size=20&keyword=hello",
			expected: false,
			desc:     "正常分页参数不应触发 XSS",
		},
		{
			name:     "正常-中文参数值",
			query:    "keyword=你好世界&type=news",
			expected: false,
			desc:     "中文参数值不应触发 XSS",
		},
		{
			name:     "正常-空字符串",
			query:    "",
			expected: false,
			desc:     "空字符串不应触发 XSS",
		},
		{
			name:     "正常-仅参数名无值",
			query:    "flag&debug",
			expected: false,
			desc:     "无值的参数不应触发 XSS",
		},

		// --- 真实 XSS 场景 ---
		{
			name:     "真实XSS-script标签在值中",
			query:    "name=<script>alert(1)</script>",
			expected: true,
			desc:     "参数值包含 <script> 应触发 XSS",
		},
		{
			name:     "真实XSS-img onerror在值中",
			query:    `q="><img src=x onerror=alert(1)>`,
			expected: true,
			desc:     "参数值包含 img onerror 应触发 XSS",
		},
		{
			name:     "真实XSS-混合正常参数和恶意参数",
			query:    "page=1&input=<script>alert(1)</script>&size=10",
			expected: true,
			desc:     "混合参数中只要有一个恶意值就应触发",
		},
		{
			name:     "真实XSS-svg标签",
			query:    "data=<svg/onload=alert(1)>",
			expected: true,
			desc:     "参数值包含 svg onload 应触发 XSS",
		},

		// --- 边界情况 ---
		{
			name:     "边界-仅含特殊字符但不是XSS",
			query:    "path=a/b/c",
			expected: false,
			desc:     "含斜杠但不是XSS payload（libinjection不判定）",
		},
		{
			name:     "边界-URL编码后的script标签应被检测",
			query:    "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
			expected: true,
			desc:     "url.ParseQuery 会自动解码 %3C/%3E，解码后的 <script>alert(1)</script> 是真实 XSS 应被拦截",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsXSSInQueryValues(tt.query)
			if got != tt.expected {
				t.Errorf("[%s] IsXSSInQueryValues(%q) = %v, 期望 %v", tt.desc, tt.query, got, tt.expected)
			}
		})
	}
}
