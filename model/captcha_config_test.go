package model

import "testing"

// 存量 captcha_json 里的数值字段是字符串形式（前端提交如此）。
// 用普通 int 接收时 encoding/json 会跳过这些字段、悄悄回落默认值——
// 用户改了不生效且没有任何提示。这里用真实库里取到的整段配置守住。
func TestParseCaptchaConfig_NumericFieldsAsStrings(t *testing.T) {
	raw := `{"is_enable_captcha":0,"path_prefix":"/_waf_6lzsvyo8","exclude_urls":"/gettext",` +
		`"expire_time":"24","ip_mode":"proxy","engine_type":"traditional",` +
		`"cap_js_config":{"challengeCount":"60","challengeSize":"32","challengeDifficulty":"4",` +
		`"expiresMs":"600000","infoTitle":{"zh":"标题","en":"title"},` +
		`"infoText":{"zh":"正文","en":"text"}}}`

	c := ParseCaptchaConfig(raw)

	if c.ExcludeURLs != "/gettext" {
		t.Fatalf("exclude_urls 应被解析出来，实际 %q", c.ExcludeURLs)
	}
	if c.PathPrefix != "/_waf_6lzsvyo8" {
		t.Fatalf("path_prefix 解析错误：%q", c.PathPrefix)
	}
	// 关键：字符串形式的数字必须真的生效，而不是回落默认值
	if c.ExpireTime != 24 {
		t.Fatalf("expire_time 应为 24，实际 %d", c.ExpireTime)
	}
	if c.CapJsConfig.ChallengeCount != 60 {
		t.Fatalf("challengeCount 用户配的是 60，实际 %d（回落到默认值即为静默丢弃）",
			c.CapJsConfig.ChallengeCount)
	}
	if c.CapJsConfig.ChallengeSize != 32 || c.CapJsConfig.ChallengeDifficulty != 4 ||
		c.CapJsConfig.ExpiresMs != 600000 {
		t.Fatalf("capJs 其余数值字段解析错误：%+v", c.CapJsConfig)
	}
}

// 数字形式同样要能解析，不能为了兼容字符串把正常写法弄坏
func TestParseCaptchaConfig_NumericFieldsAsNumbers(t *testing.T) {
	c := ParseCaptchaConfig(`{"is_enable_captcha":1,"expire_time":6,"cap_js_config":{"challengeCount":10}}`)
	if c.IsEnableCaptcha != 1 || c.ExpireTime != 6 || c.CapJsConfig.ChallengeCount != 10 {
		t.Fatalf("数字形式解析错误：enable=%d expire=%d count=%d",
			c.IsEnableCaptcha, c.ExpireTime, c.CapJsConfig.ChallengeCount)
	}
}

// 空串与空 JSON 走默认值，不能因为兼容改动而 panic
func TestParseCaptchaConfig_Defaults(t *testing.T) {
	for _, raw := range []string{"", "{}", `{"expire_time":""}`, `{"expire_time":null}`} {
		c := ParseCaptchaConfig(raw)
		if c.ExpireTime != 24 || c.EngineType != "traditional" {
			t.Fatalf("输入 %q 应走默认值，实际 expire=%d engine=%q", raw, c.ExpireTime, c.EngineType)
		}
	}
}

// 存量 captcha_json 里的 exclude_urls 有字符串和数组两种写法（老版本前端写的是数组）。
// 用普通 string 接收数组时同样会被 encoding/json 跳过，整份豁免清单消失，
// 表现为「配了永不挑战的路径却照样被挑战」。
func TestParseCaptchaConfig_ExcludeURLsAsArray(t *testing.T) {
	c := ParseCaptchaConfig(`{"exclude_urls":["/api/ping"," /pay/callback ",""],"expire_time":"24"}`)
	if c.ExcludeURLs != "/api/ping\n/pay/callback" {
		t.Fatalf("数组形式的 exclude_urls 应拼成换行清单，实际 %q", c.ExcludeURLs)
	}
	// 同一份配置里的其它字段不能受影响
	if c.ExpireTime != 24 {
		t.Fatalf("expire_time 应为 24，实际 %d", c.ExpireTime)
	}
}

// 空数组与字符串写法都要正常，不能为了兼容数组把常规写法弄坏
func TestParseCaptchaConfig_ExcludeURLsPlain(t *testing.T) {
	if c := ParseCaptchaConfig(`{"exclude_urls":[]}`); c.ExcludeURLs != "" {
		t.Fatalf("空数组应解析为空，实际 %q", c.ExcludeURLs)
	}
	if c := ParseCaptchaConfig(`{"exclude_urls":"/a\n/b"}`); c.ExcludeURLs != "/a\n/b" {
		t.Fatalf("字符串写法应原样保留，实际 %q", c.ExcludeURLs)
	}
}
