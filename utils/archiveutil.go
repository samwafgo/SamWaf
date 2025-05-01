package utils

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Unzip 解压缩zip文件到指定目录
// zipFile: zip文件路径
// destDir: 解压目标目录
func Unzip(zipFile, destDir string) error {
	// 打开zip文件
	reader, err := zip.OpenReader(zipFile)
	if err != nil {
		return fmt.Errorf("打开zip文件失败: %v", err)
	}
	defer reader.Close()

	// 确保目标目录存在
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("创建目标目录失败: %v", err)
	}

	// 遍历zip文件中的所有文件和目录
	for _, file := range reader.File {
		// 构建目标路径
		path := filepath.Join(destDir, file.Name)

		// 检查路径是否在目标目录内（防止zip slip漏洞）
		if !strings.HasPrefix(path, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("非法的文件路径: %s", file.Name)
		}

		// 如果是目录，创建它
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(path, file.Mode()); err != nil {
				return fmt.Errorf("创建目录失败: %v", err)
			}
			continue
		}

		// 确保父目录存在
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("创建父目录失败: %v", err)
		}

		// 创建目标文件
		destFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return fmt.Errorf("创建目标文件失败: %v", err)
		}

		// 打开源文件
		srcFile, err := file.Open()
		if err != nil {
			destFile.Close()
			return fmt.Errorf("打开源文件失败: %v", err)
		}

		// 复制内容
		_, err = io.Copy(destFile, srcFile)
		srcFile.Close()
		destFile.Close()
		if err != nil {
			return fmt.Errorf("复制文件内容失败: %v", err)
		}
	}

	return nil
}

// ExtractTarGz 解压缩tar.gz文件到指定目录
// tarGzFile: tar.gz文件路径
// destDir: 解压目标目录
func ExtractTarGz(tarGzFile, destDir string) error {
	// 打开tar.gz文件
	file, err := os.Open(tarGzFile)
	if err != nil {
		return fmt.Errorf("打开tar.gz文件失败: %v", err)
	}
	defer file.Close()

	// 创建gzip读取器
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("创建gzip读取器失败: %v", err)
	}
	defer gzipReader.Close()

	// 创建tar读取器
	tarReader := tar.NewReader(gzipReader)

	// 确保目标目录存在
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("创建目标目录失败: %v", err)
	}

	// 遍历tar文件中的所有文件和目录
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // 文件结束
		}
		if err != nil {
			return fmt.Errorf("读取tar文件失败: %v", err)
		}

		// 构建目标路径
		path := filepath.Join(destDir, header.Name)

		// 检查路径是否在目标目录内（防止zip slip漏洞）
		if !strings.HasPrefix(path, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("非法的文件路径: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir: // 目录
			if err := os.MkdirAll(path, 0755); err != nil {
				return fmt.Errorf("创建目录失败: %v", err)
			}
		case tar.TypeReg: // 普通文件
			// 确保父目录存在
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return fmt.Errorf("创建父目录失败: %v", err)
			}

			// 创建目标文件
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("创建目标文件失败: %v", err)
			}

			// 复制内容
			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				return fmt.Errorf("复制文件内容失败: %v", err)
			}
			file.Close()
		}
	}

	return nil
}
