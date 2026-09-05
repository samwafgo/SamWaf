package model

import "testing"

// TestDecodeHttpAuthConfigCompat 钉死向后兼容：所有存量站点的 http_auth_json 都是空串，
// 解析结果必须等价于加这套配置之前的硬编码行为——24 小时有效期、绑定登录 IP、不做空闲超时。
// 这条一旦破掉，就是升级当天全量站点的访问行为静默漂移。
func TestDecodeHttpAuthConfigCompat(t *testing.T) {
	for _, raw := range []string{"", "   ", "{}", "not a json", "[]"} {
		cfg := DecodeHttpAuthConfig(raw)
		if cfg.SessionTTL != DefaultHttpAuthSessionTTL {
			t.Errorf("raw=%q SessionTTL=%d, 期望 %d", raw, cfg.SessionTTL, DefaultHttpAuthSessionTTL)
		}
		if cfg.IdleTimeout != 0 {
			t.Errorf("raw=%q IdleTimeout=%d, 期望 0(不启用)", raw, cfg.IdleTimeout)
		}
		if cfg.BindIP != 1 {
			t.Errorf("raw=%q BindIP=%d, 期望 1(绑定)", raw, cfg.BindIP)
		}
	}
}

func TestDecodeHttpAuthConfig(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		ttl     FlexInt
		idle    FlexInt
		bindIP  FlexInt
	}{
		{"正常数值", `{"session_ttl":120,"idle_timeout":30,"bind_ip":1}`, 120, 30, 1},
		// 前端表单回传的是字符串，普通 int 会让字段悄悄回落默认值，这里必须被 FlexInt 接住
		{"字符串数值", `{"session_ttl":"120","idle_timeout":"30","bind_ip":"0"}`, 120, 30, 0},
		{"显式关闭绑IP", `{"session_ttl":60,"bind_ip":0}`, 60, 0, 0},
		// 老配置里没有 bind_ip 这个键 → 必须保持 1，不能当成「用户填了 0」
		{"缺 bind_ip 键", `{"session_ttl":60}`, 60, 0, 1},
		// 非法值不接受：0 或负数的有效期会让所有人一登录就掉线
		{"有效期为0回落默认", `{"session_ttl":0,"bind_ip":1}`, DefaultHttpAuthSessionTTL, 0, 1},
		{"有效期为负回落默认", `{"session_ttl":-5,"bind_ip":1}`, DefaultHttpAuthSessionTTL, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DecodeHttpAuthConfig(tt.raw)
			if cfg.SessionTTL != tt.ttl {
				t.Errorf("SessionTTL=%d, 期望 %d", cfg.SessionTTL, tt.ttl)
			}
			if cfg.IdleTimeout != tt.idle {
				t.Errorf("IdleTimeout=%d, 期望 %d", cfg.IdleTimeout, tt.idle)
			}
			if cfg.BindIP != tt.bindIP {
				t.Errorf("BindIP=%d, 期望 %d", cfg.BindIP, tt.bindIP)
			}
		})
	}
}
