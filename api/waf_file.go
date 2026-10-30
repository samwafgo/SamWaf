package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/common/response"
	"SamWaf/utils"
	"SamWaf/wafdb"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type WafFileApi struct {
}

// FileInfo 文件信息结构体
type FileInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	FullPath    string `json:"full_path"`
	Size        string `json:"size"`
	SizeBytes   int64  `json:"size_bytes"`
	Description string `json:"description"`
	CanDelete   bool   `json:"can_delete"`
	ModTime     string `json:"mod_time"`
	IsDir       bool   `json:"is_dir"`
}

// generateFileID 生成文件ID（基于文件全路径的SHA256）
func (w *WafFileApi) generateFileID(fullPath string) string {
	hash := sha256.Sum256([]byte(fullPath))
	return hex.EncodeToString(hash[:])
}

// dataFilesCache 文件列表的缓存值形态。结构体必须能 JSON 往返：
// JSON 类缓存后端(Redis)经 JSON 存取，读侧统一用 GetAs 还原，不做裸类型断言。
// 字段名与前端约定一致（files/total），改动需同步前端。
type dataFilesCache struct {
	Files []FileInfo `json:"files"`
	Total int        `json:"total"`
}

// loadDataFilesCache 读取文件列表缓存；未命中或读取失败返回 false
func loadDataFilesCache() (*dataFilesCache, bool) {
	var cached dataFilesCache
	if err := global.GCACHE_WAFCACHE.GetAs(enums.CACHE_FILE_INFO, &cached); err != nil {
		return nil, false
	}
	return &cached, true
}

// GetDataFilesApi 获取data目录下的文件列表
func (w *WafFileApi) GetDataFilesApi(c *gin.Context) {
	dataDir := utils.GetCurrentDir() + "/data"

	// 检查data目录是否存在
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		response.FailWithMessage("data目录不存在", c)
		return
	}

	// 检查是否强制刷新缓存
	isForce := c.Query("is_force") == "true" || c.Query("is_force") == "1"

	// 缓存键
	cacheKey := enums.CACHE_FILE_INFO

	// 如果不是强制刷新，先尝试从缓存获取
	if !isForce {
		if cached, ok := loadDataFilesCache(); ok {
			response.OkWithDetailed(cached, "获取成功(缓存)", c)
			return
		}
	}

	var fileInfos []FileInfo

	// 遍历data目录及其子目录
	err := filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过目录本身，只处理文件
		if info.IsDir() {
			return nil
		}

		// 获取相对路径
		relPath, _ := filepath.Rel(dataDir, path)
		relPath = strings.ReplaceAll(relPath, "\\", "/") // 统一使用正斜杠

		// 生成文件ID
		fileID := w.generateFileID(path)

		// 判断文件是否可以删除
		canDelete := w.canDeleteFile(info.Name(), relPath)

		// 获取文件描述
		description := w.getFileDescription(info.Name(), relPath)

		// 格式化文件大小
		fileSize := w.formatFileSize(info.Size())

		fileInfo := FileInfo{
			ID:          fileID,
			Name:        info.Name(),
			Path:        relPath,
			FullPath:    path,
			Size:        fileSize,
			SizeBytes:   info.Size(),
			Description: description,
			CanDelete:   canDelete,
			ModTime:     info.ModTime().Format("2006-01-02 15:04:05"),
			IsDir:       info.IsDir(),
		}

		fileInfos = append(fileInfos, fileInfo)
		return nil
	})

	if err != nil {
		response.FailWithMessage(fmt.Sprintf("读取目录失败: %v", err), c)
		return
	}

	// 构建返回结果
	result := dataFilesCache{
		Files: fileInfos,
		Total: len(fileInfos),
	}

	// 将文件列表结果缓存30分钟
	global.GCACHE_WAFCACHE.SetWithTTl(cacheKey, result, 30*time.Minute)

	response.OkWithDetailed(result, "获取成功", c)
}

// DeleteFileByIdApi 通过ID删除文件
func (w *WafFileApi) DeleteFileByIdApi(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	release, err := wafdb.AcquireLogWrite(ctx)
	if err != nil {
		response.FailWithMessage("日志来源繁忙，请稍后重试", c)
		return
	}
	defer release()
	fileID := c.Query("id")
	if fileID == "" {
		response.FailWithMessage("文件ID不能为空", c)
		return
	}

	// 从缓存中获取文件列表
	cached, ok := loadDataFilesCache()
	if !ok {
		response.FailWithMessage("文件信息不存在或已过期，请重新获取文件列表", c)
		return
	}
	fileInfos := cached.Files

	// 遍历文件列表找到对应ID的文件
	var targetFileInfo *FileInfo
	for _, fileInfo := range fileInfos {
		if fileInfo.ID == fileID {
			targetFileInfo = &fileInfo
			break
		}
	}

	// 检查是否找到文件
	if targetFileInfo == nil {
		response.FailWithMessage("未找到指定ID的文件", c)
		return
	}

	// 验证文件是否可以删除
	if !targetFileInfo.CanDelete {
		response.FailWithMessage("该文件不允许删除", c)
		return
	}

	// 检查文件是否仍然存在
	if _, err := os.Stat(targetFileInfo.FullPath); os.IsNotExist(err) {
		response.FailWithMessage("文件不存在", c)
		return
	}

	// 如果是主数据库文件，需要特殊处理
	if targetFileInfo.Name == "local_log.db" {
		err := w.deleteLogDatabase(targetFileInfo.FullPath)
		if err != nil {
			response.FailWithMessage(fmt.Sprintf("删除数据库文件失败: %v", err), c)
			return
		}
	} else {
		// 普通文件直接删除
		err := os.Remove(targetFileInfo.FullPath)
		if err != nil {
			response.FailWithMessage(fmt.Sprintf("删除文件失败: %v", err), c)
			return
		}
	}

	// 删除缓存
	global.GCACHE_WAFCACHE.Remove(enums.CACHE_FILE_INFO)

	response.OkWithMessage(fmt.Sprintf("文件 %s 删除成功", targetFileInfo.Name), c)
}

// deleteLogDatabase 删除日志数据库文件的专用方法
func (w *WafFileApi) deleteLogDatabase(filePath string) error {
	// 1. 设置数据库切换状态
	global.GDATA_CURRENT_CHANGE = true
	defer func() {
		// 确保在函数结束时重置状态
		global.GDATA_CURRENT_CHANGE = false
	}()

	// 2. 关闭数据库连接
	if global.GWAF_LOCAL_LOG_DB != nil {
		sqlDB, err := global.GWAF_LOCAL_LOG_DB.DB()
		if err != nil {
			return fmt.Errorf("获取数据库连接失败: %v", err)
		}

		// 关闭数据库连接
		if err := sqlDB.Close(); err != nil {
			return fmt.Errorf("关闭数据库连接失败: %v", err)
		}

		// 等待数据库完全关闭
		var testTotal int64
		for {
			testError := global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Count(&testTotal).Error
			if testError != nil {
				break
			}
			time.Sleep(1 * time.Second)
		}

		// 将全局变量设置为nil
		global.GWAF_LOCAL_LOG_DB = nil
	}

	// 3. 删除数据库文件及相关文件
	err := os.Remove(filePath)
	if err != nil {
		return fmt.Errorf("删除数据库文件失败: %v", err)
	}

	// 删除相关的 .db-shm 和 .db-wal 文件（如果存在）
	if _, err := os.Stat(filePath + "-shm"); err == nil {
		os.Remove(filePath + "-shm")
	}
	if _, err := os.Stat(filePath + "-wal"); err == nil {
		os.Remove(filePath + "-wal")
	}

	// 4. 重新初始化数据库
	_, err = wafdb.InitLogDb("")
	if err != nil {
		return fmt.Errorf("重新初始化数据库失败: %v", err)
	}

	return nil
}

// canDeleteFile 判断文件是否可以删除
func (w *WafFileApi) canDeleteFile(fileName, relPath string) bool {

	//哪些是不让删除得
	if strings.HasSuffix(fileName, "-wal") || strings.HasSuffix(fileName, "-shm") {
		return false
	}
	// local_log 相关文件可以删除
	if strings.Contains(fileName, "local_log") {
		return true
	}

	return false
}

// getFileDescription 获取文件描述
func (w *WafFileApi) getFileDescription(fileName, relPath string) string {
	switch {
	case fileName == "local.db":
		return "主数据库文件，存储WAF配置和规则"
	case fileName == "local_stats.db":
		return "统计数据库文件，存储访问统计信息"
	case fileName == "local_log.db":
		return "主日志数据库文件，存储访问日志和攻击记录删除后会情况重新创建一个新的日志文件"
	case strings.Contains(fileName, "local_log"):
		return "日志数据库文件，存储访问日志和攻击记录"
	case strings.Contains(relPath, "backup"):
		return "数据库备份文件"
	case strings.Contains(relPath, "owasp"):
		return "OWASP规则集文件"
	case strings.Contains(relPath, "captcha"):
		return "验证码相关文件"
	case strings.Contains(relPath, "ssl") || strings.HasSuffix(fileName, ".crt") || strings.HasSuffix(fileName, ".key"):
		return "SSL证书文件"
	case strings.Contains(relPath, "vhost"):
		return "虚拟主机配置文件"
	case strings.HasSuffix(fileName, ".log"):
		return "系统日志文件"
	case strings.HasSuffix(fileName, ".cache"):
		return "缓存文件"
	case strings.HasSuffix(fileName, ".tmp") || strings.HasSuffix(fileName, ".temp"):
		return "临时文件"
	case strings.HasSuffix(fileName, ".xdb"):
		return "IP地理位置数据库"
	case strings.HasSuffix(fileName, ".mmdb"):
		return "GeoIP数据库文件"
	default:
		return "数据文件"
	}
}

// formatFileSize 格式化文件大小
func (w *WafFileApi) formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
