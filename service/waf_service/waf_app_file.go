package waf_service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// writeAppFile 在同目录替换文件；首次上传在系统初始权限上增加所有者执行位。
func writeAppFile(destPath string, src io.Reader, mode *os.FileMode, expectedHash string) error {
	destPath = filepath.Clean(destPath)
	var f *os.File
	var err error
	if mode == nil {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return fmt.Errorf("生成临时文件名失败: %w", err)
		}
		tmpPath := filepath.Join(filepath.Dir(destPath), ".samwaf-upload-"+hex.EncodeToString(nonce[:]))
		f, err = os.OpenFile(tmpPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	} else {
		f, err = os.CreateTemp(filepath.Dir(destPath), ".samwaf-upload-*")
	}
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), src); err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}
	actualHash := hex.EncodeToString(h.Sum(nil))
	if expectedHash != "" && !strings.EqualFold(actualHash, expectedHash) {
		return fmt.Errorf("文件哈希校验失败，期望: %s，实际: %s", expectedHash, actualHash)
	}
	if mode == nil && runtime.GOOS != "windows" {
		info, err := f.Stat()
		if err != nil {
			return fmt.Errorf("读取临时文件权限失败: %w", err)
		}
		perm := info.Mode().Perm() | 0100
		mode = &perm
	}
	if mode != nil {
		if err := f.Chmod(mode.Perm()); err != nil {
			return fmt.Errorf("设置文件权限失败: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("关闭临时文件失败: %w", err)
	}
	if err := os.Rename(f.Name(), destPath); err != nil {
		return fmt.Errorf("保存文件失败: %w", err)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("源文件不是普通文件")
	}
	mode := info.Mode().Perm()
	return writeAppFile(dst, in, &mode, "")
}
