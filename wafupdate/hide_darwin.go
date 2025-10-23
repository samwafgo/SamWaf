//go:build darwin
// +build darwin

package wafupdate

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	UF_HIDDEN = 0x8000 // macOS hidden file flag
)

// hideFile hides a file on macOS using chflags with UF_HIDDEN flag
func hideFile(path string) error {
	// Try to use chflags to set the hidden flag
	err := chflags(path, UF_HIDDEN)
	if err != nil {
		// Fallback: rename file with dot prefix (traditional Unix hidden file)
		return hideFileByRename(path)
	}
	return nil
}

// chflags sets file flags on macOS
func chflags(path string, flags int) error {
	pathBytes := []byte(path + "\x00") // null-terminated string
	_, _, errno := syscall.Syscall(syscall.SYS_CHFLAGS,
		uintptr(unsafe.Pointer(&pathBytes[0])),
		uintptr(flags),
		0)
	if errno != 0 {
		return errno
	}
	return nil
}

// hideFileByRename hides file by renaming it with a dot prefix
func hideFileByRename(path string) error {
	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	// Don't rename if already hidden (starts with dot)
	if strings.HasPrefix(filename, ".") {
		return nil
	}

	hiddenPath := filepath.Join(dir, "."+filename)
	return os.Rename(path, hiddenPath)
}
