package wafupdate

import "testing"

// TestNormalizeExeBase 守护：运行中的程序被原地替换后，Linux 的 os.Executable 会返回
// ".SamWafLinux64.old.<时间戳>.<pid> (deleted)" 这类名字，备份前缀与回滚目标必须归一化回真实程序名，
// 否则升级失败后回滚会报"没有可用的备份版本"。
func TestNormalizeExeBase(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/home/www/SamWaf/SamWafLinux64", "SamWafLinux64"},
		{"/home/www/SamWaf/SamWafLinux64.exe", "SamWafLinux64.exe"},
		// 旧程序被 rename 成 .old 且已删除后，/proc/self/exe 的形态
		{"/home/www/SamWaf/.SamWafLinux64.old.20261116100733.230101 (deleted)", "SamWafLinux64"},
		{"/home/www/SamWaf/.SamWaf64.exe.old.20261116100733.230101 (deleted)", "SamWaf64.exe"},
		// 安装路径被人工覆盖（非 .old 改名），只剩 (deleted) 后缀
		{"/home/www/SamWaf/SamWafLinux64 (deleted)", "SamWafLinux64"},
	}
	for _, c := range cases {
		if got := normalizeExeBase(c.in); got != c.want {
			t.Errorf("normalizeExeBase(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
