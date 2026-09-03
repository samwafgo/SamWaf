package model

import "testing"

// 验证方式必须归一化到引擎认得的取值。
//
// 这条守的是一个静默失效：下游按 EngineType 分发挑战页时只认 traditional / capJs，
// 取到别的值就两个分支都不进、什么都不写，响应是空的、挑战永远发不出来，
// 而配置、界面、日志一切正常。用户库里就有 "default" 这种更早版本留下的取值。
func TestParseCaptchaConfig_NormalizesEngineType(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{"存量的 default", `{"engine_type":"default"}`, CaptchaEngineTraditional},
		{"空值", `{"engine_type":""}`, CaptchaEngineTraditional},
		{"没有这个字段", `{"is_enable_captcha":1}`, CaptchaEngineTraditional},
		{"大小写不符", `{"engine_type":"CapJs"}`, CaptchaEngineTraditional},
		{"随便一个值", `{"engine_type":"whatever"}`, CaptchaEngineTraditional},
		{"traditional 保持", `{"engine_type":"traditional"}`, CaptchaEngineTraditional},
		{"capJs 保持", `{"engine_type":"capJs"}`, CaptchaEngineCapJs},
	}
	for _, c := range cases {
		if got := ParseCaptchaConfig(c.json).EngineType; got != c.want {
			t.Fatalf("%s: 期望 %q，实际 %q", c.name, c.want, got)
		}
	}
}

// 用用户库里的真实一行做样本：engine_type=default，且数值字段是数字不是字符串。
// 归一化不能顺手把其余字段弄丢。
func TestParseCaptchaConfig_RealRowWithDefaultEngine(t *testing.T) {
	raw := `{"is_enable_captcha":0,"path_prefix":"","exclude_urls":"/gettext","expire_time":"24",` +
		`"ip_mode":"proxy","engine_type":"default","cap_js_config":{"challengeCount":50,` +
		`"challengeSize":32,"challengeDifficulty":4,"expiresMs":600000}}`
	cfg := ParseCaptchaConfig(raw)

	if cfg.EngineType != CaptchaEngineTraditional {
		t.Fatalf("engine_type=default 应归一化为 traditional，实际 %q", cfg.EngineType)
	}
	if string(cfg.ExcludeURLs) != "/gettext" {
		t.Fatalf("永不挑战的路径被弄丢了: %q", string(cfg.ExcludeURLs))
	}
	if cfg.IPMode != "proxy" {
		t.Fatalf("ip_mode 被弄丢了: %q", cfg.IPMode)
	}
	if int(cfg.ExpireTime) != 24 {
		t.Fatalf("expire_time 被弄丢了: %v", cfg.ExpireTime)
	}
	if int(cfg.CapJsConfig.ChallengeCount) != 50 {
		t.Fatalf("capJs 参数被弄丢了: %v", cfg.CapJsConfig.ChallengeCount)
	}
}
