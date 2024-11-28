package wafinit

import (
	"SamWaf/common/zlog"
	"embed"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// 版本文件路径在内嵌资源中
const versionFilePath = "exedata/owasp/version"

// CheckAndReleaseDataset 检查目标目录的版本，并根据条件决定是否释放数据集
func CheckAndReleaseDataset(owaspAssets embed.FS, targetDir string) error {
	innerLogName := "CheckOWASPRelease"
	zlog.Info(innerLogName, "检测OWASP数据集合")
	// 设置 lock.txt 文件路径
	lockFilePath := filepath.Join(targetDir, "lock.txt")

	// 检查目标目录是否已存在
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		// 目录不存在，创建目录
		err := os.MkdirAll(targetDir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
		zlog.Info(innerLogName, "OWASP Directory created:"+targetDir)
	}

	// 检查 lock.txt 是否存在
	if _, err := os.Stat(lockFilePath); !os.IsNotExist(err) {
		// lock.txt 存在，跳过释放
		zlog.Info(innerLogName, "Lock file exists, skipping release of the dataset")
		return nil
	}

	// 获取当前版本号，从内嵌的版本文件中读取
	currentVersion, err := getCurrentVersion(owaspAssets)
	if err != nil {
		return fmt.Errorf("error reading current version: %w", err)
	}

	// 检查版本号文件是否存在以及版本号
	var targetVersion string
	versionFilePath := filepath.Join(targetDir, "version")
	if _, err := os.Stat(versionFilePath); os.IsNotExist(err) {
		// version 文件不存在，认为是第一次运行，释放文件
		targetVersion = ""
	} else {
		// 读取版本号文件内容
		data, err := ioutil.ReadFile(versionFilePath)
		if err != nil {
			zlog.Info(innerLogName, "Error reading version file:", err.Error())
		}
		targetVersion = strings.TrimSpace(string(data))
	}

	// 如果版本号不存在，或者目标版本号较旧，则释放文件
	if targetVersion == "" || compareVersions(targetVersion, currentVersion) < 0 {
		// 释放文件
		err := ReleaseFiles(owaspAssets, "exedata/owasp", targetDir)
		if err != nil {
			return fmt.Errorf("error releasing files: %w", err)
		}

		// 释放后更新版本号
		err = ioutil.WriteFile(versionFilePath, []byte(currentVersion), 0644)
		if err != nil {
			return fmt.Errorf("error writing version file: %w", err)
		}
		zlog.Info(innerLogName, "数据集已更新.")
	} else {
		// 版本号是最新的，不需要释放
		zlog.Info(innerLogName, "版本号是最新的，不需要释放.")
	}

	return nil
}

// 获取当前版本号，从内嵌的版本文件中读取
func getCurrentVersion(owaspAssets embed.FS) (string, error) {
	data, err := owaspAssets.ReadFile(versionFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read version file from embedded assets: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// 比较版本号（假设版本号格式为 "X.Y.Z"）
func compareVersions(version1, version2 string) int {
	v1 := strings.Split(version1, ".")
	v2 := strings.Split(version2, ".")

	for i := 0; i < 3; i++ {
		if v1[i] < v2[i] {
			return -1
		} else if v1[i] > v2[i] {
			return 1
		}
	}
	return 0
}

// ReleaseFiles 释放嵌入的文件到目标目录
func ReleaseFiles(owaspAssets embed.FS, srcPath, destPath string) error {
	// 检查目标文件夹是否存在，不存在则创建
	innerLogName := "ReleaseFiles"
	if err := os.MkdirAll(destPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// 遍历嵌入的文件
	entries, err := owaspAssets.ReadDir(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read embedded directory: %w", err)
	}

	for _, entry := range entries {
		source := filepath.Join(srcPath, entry.Name())
		destination := filepath.Join(destPath, entry.Name())
		// 确保路径使用正斜杠
		source = strings.ReplaceAll(source, "\\", "/")
		destination = strings.ReplaceAll(destination, "\\", "/")

		// 如果是目录，递归提取
		if entry.IsDir() {
			if err := ReleaseFiles(owaspAssets, source, destination); err != nil {
				return err
			}
		} else {
			// 如果是文件，检查是否存在，如果不存在则写入
			data, err := owaspAssets.ReadFile(source)
			if err != nil {
				return fmt.Errorf("failed to read file from embed: %w", err)
			}

			// 写入文件
			if err := os.WriteFile(destination, data, 0644); err != nil {
				return fmt.Errorf("failed to write file: %w", err)
			}
			zlog.Info(innerLogName, "OWASP Extracted:"+destination)
		}
	}
	return nil
}
