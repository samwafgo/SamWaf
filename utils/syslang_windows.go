//go:build windows

package utils

import "syscall"

// isSystemChinese 在语言环境变量缺失时，通过 Windows API 取用户默认 UI 语言判定是否为中文。
// GetUserDefaultUILanguage 返回 LANGID，主语言标识 LANG_CHINESE=0x04 即视为中文。
func isSystemChinese() bool {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage")
	ret, _, _ := proc.Call()
	langID := uint16(ret)
	const langChinese = 0x04 // LANG_CHINESE
	// PRIMARYLANGID(langID) = langID & 0x3ff
	return (langID & 0x3ff) == langChinese
}
