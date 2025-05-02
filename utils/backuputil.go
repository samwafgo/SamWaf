package utils

import (
	"SamWaf/common/zlog"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BackupFile 备份文件到指定目录
// srcFilePath: 源文件路径
// backupDir: 备份目录
// backupFilePrefix: 备份文件名前缀
// keepCount: 保留的备份文件数量
func BackupFile(srcFilePath, backupDir, backupFilePrefix string, keepCount int) (string, error) {
	// 判断源文件是否存在
	if _, err := os.Stat(srcFilePath); os.IsNotExist(err) {
		return "", fmt.Errorf("源文件不存在: %s", srcFilePath)
	}

	// 判断备份目录是否存在，不存在则创建
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		if err := os.MkdirAll(backupDir, os.ModePerm); err != nil {
			zlog.Error("创建备份目录失败:", err)
			return "", err
		}
	}

	// 获取文件扩展名
	fileExt := filepath.Ext(srcFilePath)

	// 创建备份文件名
	backupFileName := fmt.Sprintf("%s_%s%s", backupFilePrefix, time.Now().Format("20060102150405"), fileExt)
	backupFilePath := filepath.Join(backupDir, backupFileName)

	// 创建备份文件
	backupFile, err := os.Create(backupFilePath)
	if err != nil {
		zlog.Error("创建备份文件失败:", err)
		return "", err
	}
	defer backupFile.Close()

	// 打开原始文件
	originalFile, err := os.Open(srcFilePath)
	if err != nil {
		zlog.Error("打开原始文件失败:", err)
		return "", err
	}
	defer originalFile.Close()

	// 复制文件内容到备份文件
	_, err = io.Copy(backupFile, originalFile)
	if err != nil {
		zlog.Error("文件复制失败:", err)
		return "", err
	}

	zlog.Info("文件备份成功，备份文件路径：", backupFilePath)

	// 清理旧的备份文件，只保留最新的keepCount个
	CleanupOldBackups(backupDir, backupFilePrefix, keepCount)

	return backupFilePath, nil
}

// CleanupOldBackups 清理旧的备份文件，只保留最新的n个
func CleanupOldBackups(backupDir, filePrefix string, keepCount int) {
	// 获取备份目录中的所有文件
	files, err := os.ReadDir(backupDir)
	if err != nil {
		zlog.Error("读取备份目录失败:", err)
		return
	}

	// 筛选出指定前缀的备份文件
	var backupFiles []os.DirEntry
	for _, file := range files {
		if !file.IsDir() && strings.HasPrefix(file.Name(), filePrefix) {
			backupFiles = append(backupFiles, file)
		}
	}

	// 如果备份文件数量不超过保留数量，则不需要删除
	if len(backupFiles) <= keepCount {
		return
	}

	// 按文件修改时间排序（从旧到新）
	sort.Slice(backupFiles, func(i, j int) bool {
		infoI, err := backupFiles[i].Info()
		if err != nil {
			return false
		}
		infoJ, err := backupFiles[j].Info()
		if err != nil {
			return false
		}
		return infoI.ModTime().Before(infoJ.ModTime())
	})

	// 删除多余的旧文件
	for i := 0; i < len(backupFiles)-keepCount; i++ {
		filePath := filepath.Join(backupDir, backupFiles[i].Name())
		err := os.Remove(filePath)
		if err != nil {
			zlog.Error("删除旧备份文件失败:", err, filePath)
		} else {
			zlog.Info("已删除旧备份文件:", filePath)
		}
	}
}
