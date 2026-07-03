package utils

import (
	"os"
	"strings"
)

// IsChineseEnv 判断当前运行环境是否为中文环境（跨平台，默认英文）。
//
// 判定顺序：
//  1. 优先读取 POSIX 语言环境变量 LC_ALL/LC_MESSAGES/LANG/LANGUAGE（Linux/macOS 常见），含 "zh" 即视为中文；
//  2. 上述变量为空时（常见于 Windows 服务进程），回退到操作系统级语言检测（见各平台 isSystemChinese 实现）；
//  3. 均无法判定时返回 false（英文）。
func IsChineseEnv() bool {
	envLang := strings.ToLower(
		os.Getenv("LC_ALL") + os.Getenv("LC_MESSAGES") + os.Getenv("LANG") + os.Getenv("LANGUAGE"),
	)
	if envLang != "" {
		return strings.Contains(envLang, "zh")
	}
	// 环境变量为空时按操作系统语言判定（如 Windows 通过系统 API）
	return isSystemChinese()
}
