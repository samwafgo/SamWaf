//go:build !linux && !windows

package wafhostguard

// newSources 非 Linux/Windows 平台(主要是 macOS)的空实现。
//
// 这个文件的存在纯粹是为了让 macOS 能编译通过 —— build-releases-mac-amd.bat /
// -arm.bat 说明 darwin 是正式构建目标，漏掉它整个 mac 版本就构建不出来。
// 返回空源 + 中文原因，引擎会据此把自己标记为"当前环境不可用"并安静待命。
func newSources() ([]Source, string) {
	_, reason, _ := checkLogCapability()
	return nil, reason
}
