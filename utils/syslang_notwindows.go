//go:build !windows

package utils

// isSystemChinese 非 Windows 平台在语言环境变量缺失时不做额外系统级判定，默认英文。
// （Linux/macOS 上语言环境通常已由 LANG/LC_* 提供，见 IsChineseEnv。）
func isSystemChinese() bool {
	return false
}
