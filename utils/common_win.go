//go:build windows

package utils

import (
	"runtime"
	"syscall"
	"unsafe"
)

// 定义 RtlGetVersion 函数
var modNtDll = syscall.NewLazyDLL("ntdll.dll")
var procRtlGetVersion = modNtDll.NewProc("RtlGetVersion")

type OsVersionInfoEx struct {
	DwOSVersionInfoSize uint32
	DwMajorVersion      uint32
	DwMinorVersion      uint32
	DwBuildNumber       uint32
	DwPlatformId        uint32
	SzCSDVersion        [128]uint16
	WServicePackMajor   uint16
	WServicePackMinor   uint16
	WSuiteMask          uint16
	WProductType        byte
	WReserved           byte
}

// 使用 RtlGetVersion 函数获取版本信息
func getWindowsVersion() (uint32, uint32, uint32, error) {
	var info OsVersionInfoEx
	info.DwOSVersionInfoSize = uint32(unsafe.Sizeof(info))
	ret, _, _ := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&info)))
	if ret != 0 {
		return 0, 0, 0, syscall.Errno(ret)
	}
	return info.DwMajorVersion, info.DwMinorVersion, info.DwBuildNumber, nil
}

// 判断是否为 Windows 平台，并且是 Windows 7, Windows 8 或 Windows Server 2008 R2
func IsSupportedWindows7Version() bool {
	// 检查是否是 Windows 系统
	if runtime.GOOS != "windows" {
		return false
	}

	// 调用 RtlGetVersion 获取准确的操作系统版本信息
	major, minor, _, err := getWindowsVersion()
	if err != nil {
		return false
	}

	// 判断是否为 Windows 7 或 Windows Server 2008 R2 (版本 6.1)
	if major == 6 && minor == 1 {
		return true
	}

	// 判断是否为 Windows 8 (版本 6.2)
	if major == 6 && minor == 2 {
		return true
	}

	// 如果都不满足，返回 false
	return false
}
