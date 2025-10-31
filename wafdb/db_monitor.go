package wafdb

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/utils"
	"encoding/json"
	"fmt"
	"gorm.io/gorm"
	"os"
	"time"
)

// DatabaseMetrics 数据库性能指标结构体
type DatabaseMetrics struct {
	DatabaseName     string  `json:"database_name"`      // 数据库名称
	DatabasePath     string  `json:"database_path"`      // 数据库文件路径
	FileSize         int64   `json:"file_size"`          // 文件大小(字节)
	FileSizeMB       float64 `json:"file_size_mb"`       // 文件大小(MB)
	ConnectionCount  int     `json:"connection_count"`   // 连接数
	MaxConnections   int     `json:"max_connections"`    // 最大连接数
	IdleConnections  int     `json:"idle_connections"`   // 空闲连接数
	InUseConnections int     `json:"in_use_connections"` // 使用中连接数

	// SQLite特有的PRAGMA信息
	PageCount       int64  `json:"page_count"`       // 页面总数
	PageSize        int64  `json:"page_size"`        // 页面大小
	FreelistCount   int64  `json:"freelist_count"`   // 空闲页面数
	CacheSize       int64  `json:"cache_size"`       // 缓存大小
	JournalMode     string `json:"journal_mode"`     // 日志模式
	SynchronousMode string `json:"synchronous_mode"` // 同步模式
	TempStore       string `json:"temp_store"`       // 临时存储模式

	// 性能统计
	QueryCount    int64   `json:"query_count"`     // 查询次数(估算)
	WriteCount    int64   `json:"write_count"`     // 写入次数(估算)
	CacheHitRatio float64 `json:"cache_hit_ratio"` // 缓存命中率

	// 时间戳
	Timestamp time.Time `json:"timestamp"` // 采集时间
}

// GetDatabaseMetrics 获取指定数据库的性能指标
func GetDatabaseMetrics(db *gorm.DB, dbName string, dbPath string) (*DatabaseMetrics, error) {
	if db == nil {
		return nil, fmt.Errorf("数据库连接为空: %s", dbName)
	}

	metrics := &DatabaseMetrics{
		DatabaseName: dbName,
		DatabasePath: dbPath,
		Timestamp:    time.Now(),
	}

	// 获取底层sql.DB
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("获取sql.DB失败: %v", err)
	}

	// 获取连接池统计信息
	stats := sqlDB.Stats()
	metrics.ConnectionCount = stats.OpenConnections
	metrics.MaxConnections = stats.MaxOpenConnections
	metrics.IdleConnections = stats.Idle
	metrics.InUseConnections = stats.InUse

	// 获取文件大小
	if fileInfo, err := os.Stat(dbPath); err == nil {
		metrics.FileSize = fileInfo.Size()
		metrics.FileSizeMB = float64(fileInfo.Size()) / (1024 * 1024)
	}

	// 获取SQLite PRAGMA信息
	var pageCount, pageSize, freelistCount, cacheSize int64
	var journalMode, synchronousMode, tempStore string

	// 页面信息
	db.Raw("PRAGMA page_count").Scan(&pageCount)
	db.Raw("PRAGMA page_size").Scan(&pageSize)
	db.Raw("PRAGMA freelist_count").Scan(&freelistCount)
	db.Raw("PRAGMA cache_size").Scan(&cacheSize)

	// 模式信息
	db.Raw("PRAGMA journal_mode").Scan(&journalMode)
	db.Raw("PRAGMA synchronous").Scan(&synchronousMode)
	db.Raw("PRAGMA temp_store").Scan(&tempStore)

	metrics.PageCount = pageCount
	metrics.PageSize = pageSize
	metrics.FreelistCount = freelistCount
	metrics.CacheSize = cacheSize
	metrics.JournalMode = journalMode
	metrics.SynchronousMode = synchronousMode
	metrics.TempStore = tempStore

	// 获取缓存命中率等统计信息
	var cacheHit, cacheMiss int64
	db.Raw("PRAGMA cache_hit").Scan(&cacheHit)
	db.Raw("PRAGMA cache_miss").Scan(&cacheMiss)

	if cacheHit+cacheMiss > 0 {
		metrics.CacheHitRatio = float64(cacheHit) / float64(cacheHit+cacheMiss) * 100
	}

	return metrics, nil
}

// MonitorAllDatabases 监控所有数据库的性能指标
func MonitorAllDatabases() ([]*DatabaseMetrics, error) {
	var allMetrics []*DatabaseMetrics
	currentDir := utils.GetCurrentDir()

	// 监控主数据库
	if global.GWAF_LOCAL_DB != nil {
		mainDbPath := currentDir + "/data/local.db"
		if metrics, err := GetDatabaseMetrics(global.GWAF_LOCAL_DB, "主数据库(Core)", mainDbPath); err == nil {
			allMetrics = append(allMetrics, metrics)
		} else {
			zlog.Error("获取主数据库指标失败:", err)
		}
	}

	// 监控日志数据库
	if global.GWAF_LOCAL_LOG_DB != nil {
		logDbPath := currentDir + "/data/local_log.db"
		if metrics, err := GetDatabaseMetrics(global.GWAF_LOCAL_LOG_DB, "日志数据库(Log)", logDbPath); err == nil {
			allMetrics = append(allMetrics, metrics)
		} else {
			zlog.Error("获取日志数据库指标失败:", err)
		}
	}

	// 监控统计数据库
	if global.GWAF_LOCAL_STATS_DB != nil {
		statsDbPath := currentDir + "/data/local_stats.db"
		if metrics, err := GetDatabaseMetrics(global.GWAF_LOCAL_STATS_DB, "统计数据库(Stats)", statsDbPath); err == nil {
			allMetrics = append(allMetrics, metrics)
		} else {
			zlog.Error("获取统计数据库指标失败:", err)
		}
	}

	// 监控自定义日志数据库
	if global.GDATA_CURRENT_LOG_DB_MAP != nil {
		for fileName, db := range global.GDATA_CURRENT_LOG_DB_MAP {
			if db != nil {
				customDbPath := currentDir + "/data/" + fileName
				dbName := fmt.Sprintf("自定义日志数据库(%s)", fileName)
				if metrics, err := GetDatabaseMetrics(db, dbName, customDbPath); err == nil {
					allMetrics = append(allMetrics, metrics)
				} else {
					zlog.Error("获取自定义数据库指标失败:", fileName, err)
				}
			}
		}
	}

	return allMetrics, nil
}

// PrintDatabaseMetrics 打印数据库性能指标
func PrintDatabaseMetrics() {
	metrics, err := MonitorAllDatabases()
	if err != nil {
		zlog.Error("监控数据库失败:", err)
		return
	}

	zlog.Info("==================== 数据库性能监控报告 ====================")
	zlog.Info("采集时间:", time.Now().Format("2006-01-02 15:04:05"))
	zlog.Info("")

	for _, m := range metrics {
		// 构建缓存命中率信息
		cacheHitInfo := ""
		if m.CacheHitRatio > 0 {
			cacheHitInfo = fmt.Sprintf("\n    - 缓存命中率: %.2f%%", m.CacheHitRatio)
		}

		dbInfo := fmt.Sprintf(`【%s】
  数据库路径: %s
  文件大小: %.2f MB (%d 字节)
  连接池信息:
    - 当前连接数: %d
    - 最大连接数: %d
    - 空闲连接数: %d
    - 使用中连接数: %d
  SQLite配置:
    - 页面总数: %d
    - 页面大小: %d 字节
    - 空闲页面数: %d
    - 缓存大小: %d
    - 日志模式: %s
    - 同步模式: %s
    - 临时存储: %s%s`,
			m.DatabaseName,
			m.DatabasePath,
			m.FileSizeMB, m.FileSize,
			m.ConnectionCount,
			m.MaxConnections,
			m.IdleConnections,
			m.InUseConnections,
			m.PageCount,
			m.PageSize,
			m.FreelistCount,
			m.CacheSize,
			m.JournalMode,
			m.SynchronousMode,
			m.TempStore,
			cacheHitInfo)

		zlog.Info(dbInfo)
		zlog.Info("")
	}
	zlog.Info("========================================================")
}

// GetDatabaseMetricsJSON 获取数据库指标的JSON格式
func GetDatabaseMetricsJSON() (string, error) {
	metrics, err := MonitorAllDatabases()
	if err != nil {
		return "", err
	}

	jsonData, err := json.Marshal(metrics)
	if err != nil {
		return "", fmt.Errorf("序列化JSON失败: %v", err)
	}

	return string(jsonData), nil
}

// StartDatabaseMonitoring 启动定时数据库监控
func StartDatabaseMonitoring(intervalMinutes int) {
	if intervalMinutes <= 0 {
		intervalMinutes = 5 // 默认5分钟
	}

	ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
	go func() {
		for {
			select {
			case <-ticker.C:
				PrintDatabaseMetrics()
			}
		}
	}()

	zlog.Info("数据库性能监控已启动，监控间隔: %d 分钟", intervalMinutes)
}
