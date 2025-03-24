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

// CheckAndReleaseDataset 检查目标目录的版本，并根据条件决定是否释放数据集
func CheckAndReleaseDataset(assets embed.FS, targetDir string, resourceType string) error {
	innerLogName := "CheckResourceRelease"
	zlog.Info(innerLogName, "检测"+resourceType+"数据集合")

	// 设置 lock.txt 文件路径
	lockFilePath := filepath.Join(targetDir, "lock.txt")

	// 检查目标目录是否已存在
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		// 目录不存在，创建目录
		err := os.MkdirAll(targetDir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
		zlog.Info(innerLogName, resourceType+" Directory created:"+targetDir)
	}

	// 检查 lock.txt 是否存在
	if _, err := os.Stat(lockFilePath); !os.IsNotExist(err) {
		// lock.txt 存在，跳过释放
		zlog.Info(innerLogName, "Lock file exists, skipping release of the dataset")
		return nil
	}

	// 构建版本文件路径
	versionFilePath := fmt.Sprintf("exedata/%s/version", strings.ToLower(resourceType))

	// 获取当前版本号，从内嵌的版本文件中读取
	currentVersion, err := getCurrentVersion(assets, versionFilePath)
	if err != nil {
		// 如果没有版本文件，则默认为初始版本
		currentVersion = "1.0.0"
		zlog.Info(innerLogName, "No version file found, using default version: "+currentVersion)
	}

	// 检查版本号文件是否存在以及版本号
	var targetVersion string
	localVersionFilePath := filepath.Join(targetDir, "version")
	if _, err := os.Stat(localVersionFilePath); os.IsNotExist(err) {
		// version 文件不存在，认为是第一次运行，释放文件
		targetVersion = ""
	} else {
		// 读取版本号文件内容
		data, err := ioutil.ReadFile(localVersionFilePath)
		if err != nil {
			zlog.Info(innerLogName, "Error reading version file:", err.Error())
		}
		targetVersion = strings.TrimSpace(string(data))
	}

	// 如果版本号不存在，或者目标版本号较旧，则释放文件
	if targetVersion == "" || compareVersions(targetVersion, currentVersion) < 0 {
		// 释放文件
		srcPath := fmt.Sprintf("exedata/%s", strings.ToLower(resourceType))
		err := ReleaseFiles(assets, srcPath, targetDir, resourceType)
		if err != nil {
			return fmt.Errorf("error releasing files: %w", err)
		}

		// 释放后更新版本号
		err = ioutil.WriteFile(localVersionFilePath, []byte(currentVersion), 0644)
		if err != nil {
			return fmt.Errorf("error writing version file: %w", err)
		}
		zlog.Info(innerLogName, resourceType+"数据集已更新.")
	} else {
		// 版本号是最新的，不需要释放
		zlog.Info(innerLogName, resourceType+"版本号是最新的，不需要释放.")
	}

	return nil
}

// 获取当前版本号，从内嵌的版本文件中读取
func getCurrentVersion(assets embed.FS, versionFilePath string) (string, error) {
	data, err := assets.ReadFile(versionFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read version file from embedded assets: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// 比较版本号（假设版本号格式为 "X.Y.Z"）
func compareVersions(version1, version2 string) int {
	v1 := strings.Split(version1, ".")
	v2 := strings.Split(version2, ".")

	// 确保两个版本号都有至少3个部分
	for len(v1) < 3 {
		v1 = append(v1, "0")
	}
	for len(v2) < 3 {
		v2 = append(v2, "0")
	}

	for i := 0; i < 3; i++ {
		// 转换为整数进行比较
		var num1, num2 int
		fmt.Sscanf(v1[i], "%d", &num1)
		fmt.Sscanf(v2[i], "%d", &num2)

		if num1 < num2 {
			return -1
		} else if num1 > num2 {
			return 1
		}
	}
	return 0
}

// ReleaseFiles 释放嵌入的文件到目标目录
func ReleaseFiles(assets embed.FS, srcPath, destPath, resourceType string) error {
	// 检查目标文件夹是否存在，不存在则创建
	innerLogName := "ReleaseFiles"
	if err := os.MkdirAll(destPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// 遍历嵌入的文件
	entries, err := assets.ReadDir(srcPath)
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
			if err := ReleaseFiles(assets, source, destination, resourceType); err != nil {
				return err
			}
		} else {
			// 如果是文件，检查是否存在，如果不存在则写入
			data, err := assets.ReadFile(source)
			if err != nil {
				return fmt.Errorf("failed to read file from embed: %w", err)
			}

			// 写入文件
			if err := os.WriteFile(destination, data, 0644); err != nil {
				return fmt.Errorf("failed to write file: %w", err)
			}
			zlog.Info(innerLogName, resourceType+" Extracted:"+destination)
		}
	}
	return nil
}
