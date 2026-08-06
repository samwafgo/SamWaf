package utils

import (
	"runtime"
	"testing"
)

// 探测失败也必须给出兜底值，不能 panic、不能整体为空
func TestGetOSDetail(t *testing.T) {
	detail := GetOSDetail()

	if detail.GOOS != runtime.GOOS || detail.GOARCH != runtime.GOARCH {
		t.Errorf("编译信息不正确: %+v", detail)
	}
	if detail.GoVersion == "" {
		t.Error("编译器版本不应为空")
	}
	if detail.OSName == "" {
		t.Error("操作系统名称至少要有兜底值")
	}
	if detail.IsWindows != (runtime.GOOS == "windows") {
		t.Errorf("IsWindows 判断不正确: %v", detail.IsWindows)
	}
	// 非 Windows 不可能是 Win7 内核
	if runtime.GOOS != "windows" && detail.IsWin7Kernel {
		t.Error("非 Windows 系统不应判定为 Win7 内核")
	}
	// 非 Linux 不做容器/WSL 判定
	if runtime.GOOS != "linux" && (detail.Container != "" || detail.IsWSL) {
		t.Errorf("非 Linux 不应识别出容器/WSL: container=%v wsl=%v", detail.Container, detail.IsWSL)
	}

	t.Logf("运行环境: %+v", detail)
	t.Logf("系统已运行: %v", FormatDurationCN(int64(GetSystemUptimeSeconds())))
}

func TestFormatDurationCN(t *testing.T) {
	cases := []struct {
		seconds int64
		want    string
	}{
		{0, "0 天 0 时 0 分 0 秒"},
		{-10, "0 天 0 时 0 分 0 秒"}, //负数按 0 处理，不能出现负值展示
		{59, "0 天 0 时 0 分 59 秒"},
		{3661, "0 天 1 时 1 分 1 秒"},
		{262145, "3 天 0 时 49 分 5 秒"},
	}
	for _, c := range cases {
		if got := FormatDurationCN(c.seconds); got != c.want {
			t.Errorf("FormatDurationCN(%v)=%v, 期望 %v", c.seconds, got, c.want)
		}
	}
}
