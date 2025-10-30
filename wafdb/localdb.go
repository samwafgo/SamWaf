package wafdb

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/utils"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"gorm.io/gorm/logger"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	//"github.com/kangarooxin/gorm-webplugin-crypto"
	//"github.com/kangarooxin/gorm-webplugin-crypto/strategy"
	gowxsqlite3 "github.com/samwafgo/go-wxsqlite3"
	"github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
)

func InitCoreDb(currentDir string) (bool, error) {
	if currentDir == "" {
		currentDir = utils.GetCurrentDir()
	}
	// 判断备份目录是否存在，不存在则创建
	if _, err := os.Stat(currentDir + "/data/"); os.IsNotExist(err) {
		if err := os.MkdirAll(currentDir+"/data/", os.ModePerm); err != nil {
			zlog.Error("创建data目录失败:", err)
			return false, err
		}
	}
	if global.GWAF_LOCAL_DB == nil {
		path := currentDir + "/data/local.db"
		// 检查数据库文件是否存在
		isNewDb := false
		if _, err := os.Stat(path); os.IsNotExist(err) {
			isNewDb = true
			zlog.Debug("本地主数据库文件不存在，将创建新数据库")
		}
		// 检查文件是否存在
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			// 文件存在的逻辑，使用工具函数进行备份
			backupDir := currentDir + "/data/backups"
			_, err := utils.BackupFile(path, backupDir, "local_backup", 10)
			if err != nil {
				zlog.Error("备份数据库文件失败:", err)
			}
		}

		key := url.QueryEscape(global.GWAF_PWD_COREDB)
		dns := fmt.Sprintf("%s?_db_key=%s", path, key)
		db, err := gorm.Open(sqlite.Open(dns), &gorm.Config{})
		if err != nil {
			panic("failed to connect database")
		}
		// 启用 WAL 模式
		_ = db.Exec("PRAGMA journal_mode=WAL;")

		// 创建自定义日志记录器
		gormLogger := NewGormZLogger()
		if global.GWAF_LOG_DEBUG_DB_ENABLE == true {
			gormLogger = gormLogger.LogMode(logger.Info).(*GormZLogger)
			// 启用调试模式
			db = db.Session(&gorm.Session{
				Logger: gormLogger,
			})
		}
		global.GWAF_LOCAL_DB = db
		s, err := db.DB()
		s.Ping()
		//db.Use(crypto.NewCryptoPlugin())
		// 注册默认的AES加解密策略
		//crypto.RegisterCryptoStrategy(strategy.NewAesCryptoStrategy("3Y)(27EtO^tK8Bj~"))
		// Migrate the schema
		db.AutoMigrate(&model.Hosts{})
		db.AutoMigrate(&model.Rules{})

		//隐私处理
		db.AutoMigrate(&model.LDPUrl{})

		//白名单处理
		db.AutoMigrate(&model.IPAllowList{})
		db.AutoMigrate(&model.URLAllowList{})

		//限制处理
		db.AutoMigrate(&model.IPBlockList{})
		db.AutoMigrate(&model.URLBlockList{})

		//抵抗CC
		db.AutoMigrate(&model.AntiCC{})

		//waf自身账号
		db.AutoMigrate(&model.TokenInfo{})
		db.AutoMigrate(&model.Account{})

		//系统参数
		db.AutoMigrate(&model.SystemConfig{})

		//延迟信息
		db.AutoMigrate(&model.DelayMsg{})

		//分库信息表
		db.AutoMigrate(&model.ShareDb{})

		//中心管控数据
		db.AutoMigrate(&model.Center{})

		//敏感词管理
		db.AutoMigrate(&model.Sensitive{})

		//负载均衡
		db.AutoMigrate(&model.LoadBalance{})

		//SSL证书
		db.AutoMigrate(&model.SslConfig{})

		//IPTag
		db.AutoMigrate(&model.IPTag{})

		//自动任务
		db.AutoMigrate(&model.BatchTask{})

		//SSL证书申请订单
		db.AutoMigrate(&model.SslOrder{})

		//SSL到期检测
		db.AutoMigrate(&model.SslExpire{})

		//HTTP AUTH
		db.AutoMigrate(&model.HttpAuthBase{})

		//任务
		db.AutoMigrate(&model.Task{})

		//自定义拦截界面
		db.AutoMigrate(&model.BlockingPage{})

		//OTP
		db.AutoMigrate(&model.Otp{})

		//密钥信息
		db.AutoMigrate(&model.PrivateInfo{})

		//密钥分组信息
		db.AutoMigrate(&model.PrivateGroup{})

		//缓存规则
		db.AutoMigrate(&model.CacheRule{})

		//隧道
		db.AutoMigrate(&model.Tunnel{})

		//CA服务器信息
		db.AutoMigrate(&model.CaServerInfo{})

		global.GWAF_LOCAL_DB.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)
		global.GWAF_LOCAL_DB.Callback().Query().Before("gorm:update").Register("tenant_plugin:before_update", before_update)

		//重启需要删除无效规则
		db.Where("user_code = ? and rule_status = 999", global.GWAF_USER_CODE).Delete(model.Rules{})

		pathCoreSql(db)
		return isNewDb, nil
	} else {
		return false, nil
	}
}

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

func InitLogDb(currentDir string) (bool, error) {
	if currentDir == "" {
		currentDir = utils.GetCurrentDir()
	}
	if global.GWAF_LOCAL_LOG_DB == nil {
		path := currentDir + "/data/local_log.db"

		// 检查数据库文件是否存在
		isNewDb := false
		if _, err := os.Stat(path); os.IsNotExist(err) {
			isNewDb = true
			zlog.Debug("本地日志数据库文件不存在，将创建新数据库")
		}

		key := url.QueryEscape(global.GWAF_PWD_LOGDB)
		dns := fmt.Sprintf("%s?_db_key=%s", path, key)
		db, err := gorm.Open(sqlite.Open(dns), &gorm.Config{})
		if err != nil {
			panic("failed to connect database")
		}
		// 启用 WAL 模式
		_ = db.Exec("PRAGMA journal_mode=WAL;")
		// 创建自定义日志记录器
		gormLogger := NewGormZLogger()
		if global.GWAF_LOG_DEBUG_DB_ENABLE == true {
			gormLogger = gormLogger.LogMode(logger.Info).(*GormZLogger)
			// 启用调试模式
			db = db.Session(&gorm.Session{
				Logger: logger.Default.LogMode(logger.Info), // 设置为Info表示启用调试模式
			})
		}
		global.GWAF_LOCAL_LOG_DB = db
		//logDB.Use(crypto.NewCryptoPlugin())
		// 注册默认的AES加解密策略
		//crypto.RegisterCryptoStrategy(strategy.NewAesCryptoStrategy("3Y)(27EtO^tK8Bj~"))
		// Migrate the schema
		//统计处理
		db.AutoMigrate(&innerbean.WebLog{})
		db.AutoMigrate(&model.AccountLog{})
		db.AutoMigrate(&model.WafSysLog{})
		db.AutoMigrate(&model.OneKeyMod{})
		global.GWAF_LOCAL_LOG_DB.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)
		global.GWAF_LOCAL_LOG_DB.Callback().Query().Before("gorm:update").Register("tenant_plugin:before_update", before_update)

		pathLogSql(db)
		var total int64 = 0
		global.GWAF_LOCAL_DB.Model(&model.ShareDb{}).Count(&total)
		if total == 0 {

			var logtotal int64 = 0
			global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Count(&logtotal)

			sharDbBean := model.ShareDb{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   global.GWAF_USER_CODE,
					Tenant_ID:   global.GWAF_TENANT_ID,
					CREATE_TIME: customtype.JsonTime(time.Now()),
					UPDATE_TIME: customtype.JsonTime(time.Now()),
				},
				DbLogicType: "log",
				StartTime:   customtype.JsonTime(time.Now()),
				EndTime:     customtype.JsonTime(time.Now()),
				FileName:    "local_log.db",
				Cnt:         logtotal,
			}
			global.GWAF_LOCAL_DB.Create(sharDbBean)
		}

		return isNewDb, nil
	} else {
		return false, nil
	}
}

// 手工切换日志数据源
func InitManaulLogDb(currentDir string, custFileName string) {
	if currentDir == "" {
		currentDir = utils.GetCurrentDir()
	}
	if global.GDATA_CURRENT_LOG_DB_MAP[custFileName] == nil {
		zlog.Debug("初始化自定义的库", custFileName)
		path := currentDir + "/data/" + custFileName
		key := url.QueryEscape(global.GWAF_PWD_LOGDB)
		dns := fmt.Sprintf("%s?_db_key=%s", path, key)
		db, err := gorm.Open(sqlite.Open(dns), &gorm.Config{})
		if err != nil {
			panic("failed to connect database")
		}
		// 启用 WAL 模式
		_ = db.Exec("PRAGMA journal_mode=WAL;")
		// 创建自定义日志记录器
		gormLogger := NewGormZLogger()
		if global.GWAF_LOG_DEBUG_DB_ENABLE == true {
			gormLogger = gormLogger.LogMode(logger.Info).(*GormZLogger)
			// 启用调试模式
			db = db.Session(&gorm.Session{
				Logger: logger.Default.LogMode(logger.Info), // 设置为Info表示启用调试模式
			})
		}
		global.GDATA_CURRENT_LOG_DB_MAP[custFileName] = db
		//logDB.Use(crypto.NewCryptoPlugin())
		// 注册默认的AES加解密策略
		//crypto.RegisterCryptoStrategy(strategy.NewAesCryptoStrategy("3Y)(27EtO^tK8Bj~"))
		// Migrate the schema
		//统计处理
		db.AutoMigrate(&innerbean.WebLog{})
		db.AutoMigrate(&model.AccountLog{})
		db.AutoMigrate(&model.WafSysLog{})
		db.AutoMigrate(&model.OneKeyMod{})

		global.GDATA_CURRENT_LOG_DB_MAP[custFileName].Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)
		global.GDATA_CURRENT_LOG_DB_MAP[custFileName].Callback().Query().Before("gorm:update").Register("tenant_plugin:before_update", before_update)

	} else {
		zlog.Debug("自定义的库已存在", custFileName)
	}
}

func InitStatsDb(currentDir string) (bool, error) {
	if currentDir == "" {
		currentDir = utils.GetCurrentDir()
	}
	if global.GWAF_LOCAL_STATS_DB == nil {
		path := currentDir + "/data/local_stats.db"
		// 检查数据库文件是否存在
		isNewDb := false
		if _, err := os.Stat(path); os.IsNotExist(err) {
			isNewDb = true
			zlog.Debug("本地统计数据库文件不存在，将创建新数据库")
		}
		key := url.QueryEscape(global.GWAF_PWD_STATDB)
		dns := fmt.Sprintf("%s?_db_key=%s", path, key)
		db, err := gorm.Open(sqlite.Open(dns), &gorm.Config{})
		if err != nil {
			panic("failed to connect database")
		}
		// 启用 WAL 模式
		_ = db.Exec("PRAGMA journal_mode=WAL;")
		// 创建自定义日志记录器
		gormLogger := NewGormZLogger()
		if global.GWAF_LOG_DEBUG_DB_ENABLE == true {
			gormLogger = gormLogger.LogMode(logger.Info).(*GormZLogger)
			// 启用调试模式
			db = db.Session(&gorm.Session{
				Logger: logger.Default.LogMode(logger.Info), // 设置为Info表示启用调试模式
			})
		}
		global.GWAF_LOCAL_STATS_DB = db
		//db.Use(crypto.NewCryptoPlugin())
		// 注册默认的AES加解密策略
		//crypto.RegisterCryptoStrategy(strategy.NewAesCryptoStrategy("3Y)(27EtO^tK8Bj~"))
		// Migrate the schema
		//统计处理
		db.AutoMigrate(&model.StatsTotal{})
		db.AutoMigrate(&model.StatsDay{})
		db.AutoMigrate(&model.StatsIPDay{})
		db.AutoMigrate(&model.StatsIPCityDay{})
		global.GWAF_LOCAL_STATS_DB.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)
		global.GWAF_LOCAL_STATS_DB.Callback().Query().Before("gorm:update").Register("tenant_plugin:before_update", before_update)

		pathStatsSql(db)

		return isNewDb, nil
	} else {
		return false, nil
	}
}

func before_query(db *gorm.DB) {
	db.Where("tenant_id = ? and user_code=? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
}
func before_update(db *gorm.DB) {
}

// 在线备份
func BackupDatabase(db *gorm.DB, backupFile string) error {
	// 获取底层的 sql.DB 对象
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}

	// 获取源数据库的连接
	srcConn, err := sqlDB.Conn(context.Background())
	if err != nil {
		return err
	}
	defer srcConn.Close()

	// 获取底层的 SQLiteConn 对象
	var srcSQLiteConn *gowxsqlite3.SQLiteConn
	err = srcConn.Raw(func(driverConn interface{}) error {
		// 将 driverConn 转换为 *wxsqlite3.SQLiteConn
		sqliteConn, ok := driverConn.(*gowxsqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("not a SQLite connection")
		}
		srcSQLiteConn = sqliteConn
		return nil
	})
	if err != nil {
		return err
	}

	// 打开目标数据库连接
	destConn, err := sql.Open("sqlite3", backupFile)
	if err != nil {
		return err
	}
	defer destConn.Close()

	// 获取目标数据库的连接
	destSqlConn, err := destConn.Conn(context.Background())
	if err != nil {
		return err
	}
	defer destSqlConn.Close()

	// 获取目标数据库的 SQLiteConn 对象
	var destSQLiteConn *gowxsqlite3.SQLiteConn
	err = destSqlConn.Raw(func(driverConn interface{}) error {
		// 将 driverConn 转换为 *wxsqlite3.SQLiteConn
		sqliteConn, ok := driverConn.(*gowxsqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("not a SQLite connection")
		}
		destSQLiteConn = sqliteConn
		return nil
	})
	if err != nil {
		return err
	}

	// 执行备份
	backup, err := destSQLiteConn.Backup("main", srcSQLiteConn, "main")
	if err != nil {
		return err
	}
	defer backup.Finish()

	// 执行备份步骤 (-1 代表全部备份)
	for {
		b, stepErr := backup.Step(-1) // 备份指定多个页面 -1 是所有
		if b == false {
			zlog.Debug("backup fail", stepErr)
			if stepErr != nil {
				return stepErr
			}
		} else {
			break
		}

	}

	fmt.Println("Backup completed successfully")
	return nil
}

// cleanupOldBackups 清理旧的备份文件，只保留最新的n个
func cleanupOldBackups(backupDir string, keepCount int) {
	// 获取备份目录中的所有文件
	files, err := os.ReadDir(backupDir)
	if err != nil {
		zlog.Error("读取备份目录失败:", err)
		return
	}

	// 筛选出数据库备份文件
	var backupFiles []os.DirEntry
	for _, file := range files {
		if !file.IsDir() && strings.HasPrefix(file.Name(), "local_backup_") && filepath.Ext(file.Name()) == ".db" {
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
