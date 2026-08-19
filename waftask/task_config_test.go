package waftask

import "testing"

// TestNormalizeTokenExpireMinutes 锁定令牌有效期的归一化语义：
// 用户填 0/负数 = "不管控有效期"，落地为 1 年封顶；超过 1 年的值同样收敛，
// 保证全局变量恒为正数且不会让 time.Duration 溢出。
func TestNormalizeTokenExpireMinutes(t *testing.T) {
	cases := []struct {
		name string
		in   int64
		want int64
	}{
		{"零表示不限制", 0, tokenExpireUnlimitedMinutes},
		{"负数同样视为不限制", -1, tokenExpireUnlimitedMinutes},
		{"极小负数不会漏过", -999999, tokenExpireUnlimitedMinutes},
		{"正常值原样返回", 30, 30},
		{"最小有效值1分钟", 1, 1},
		{"恰好一年保持不变", tokenExpireUnlimitedMinutes, tokenExpireUnlimitedMinutes},
		{"超过一年收敛到一年", tokenExpireUnlimitedMinutes + 1, tokenExpireUnlimitedMinutes},
		{"极大值不会导致时长溢出", 1 << 62, tokenExpireUnlimitedMinutes},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := normalizeTokenExpireMinutes(c.in); got != c.want {
				t.Fatalf("normalizeTokenExpireMinutes(%d) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

// TestNormalizeTokenExpireMinutesAlwaysPositive 归一化结果必须恒为正数：
// 一旦返回 0 或负数，缓存写入的 TTL 就是非正值，令牌会当场失效、全员掉线。
func TestNormalizeTokenExpireMinutesAlwaysPositive(t *testing.T) {
	for _, v := range []int64{-1 << 62, -60, -1, 0, 1, 5, 30, 1440, 1 << 62} {
		if got := normalizeTokenExpireMinutes(v); got <= 0 {
			t.Fatalf("normalizeTokenExpireMinutes(%d) = %d，必须为正数", v, got)
		}
	}
}
