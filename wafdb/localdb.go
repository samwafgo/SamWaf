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
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm/logger"

	//"github.com/kangarooxin/gorm-webplugin-crypto"
	//"github.com/kangarooxin/gorm-webplugin-crypto/strategy"
	"SamWaf/wafdb/dialect"
	gowxsqlite3 "github.com/samwafgo/go-wxsqlite3"
	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
)

func InitCoreDb(currentDir string) (bool, error) {
	if dialect.Get().Name() == "mysql" {
		return InitCoreDbMySQL()
	}
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
		// 升级接管(takeover)启动时旧 Worker 仍在写该库，跳过整库文件备份，避免拷贝到不一致的 WAL 状态
		if _, err := os.Stat(path); !os.IsNotExist(err) && !global.GWAF_RUNTIME_IS_TAKEOVER {
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
		// 升级重叠期可能新旧 Worker 并存写库，busy_timeout 让写操作在锁竞争时重试等待，避免立即报 database is locked
		_ = db.Exec("PRAGMA busy_timeout=5000;")

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

		// ============ 使用 gormigrate 替代 AutoMigrate（完全向后兼容） ============
		zlog.Info("开始执行core数据库迁移...")
		if err := RunCoreDBMigrations(db); err != nil {
			// 记录详细的错误信息
			errStr := fmt.Sprintf("%v", err)
			zlog.Error("core数据库迁移失败", "error_string", errStr, "error_type", fmt.Sprintf("%T", err))
			zlog.Error("core数据库迁移失败详细信息: " + errStr)
			panic("core database migration failed: " + errStr)
		}

		// ============ 执行任务初始化迁移 ============
		zlog.Info("开始执行任务初始化迁移...")
		if err := RunTaskInitMigrations(db); err != nil {
			// 记录详细的错误信息
			errStr := fmt.Sprintf("%v", err)
			zlog.Error("任务初始化迁移失败", "error_string", errStr, "error_type", fmt.Sprintf("%T", err))
			zlog.Error("任务初始化迁移失败详细信息: " + errStr)
			panic("task initialization migration failed: " + errStr)
		}
		// ============ 迁移代码结束 ============

		global.GWAF_LOCAL_DB.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)
		global.GWAF_LOCAL_DB.Callback().Query().Before("gorm:update").Register("tenant_plugin:before_update", before_update)

		//重启需要删除无效规则
		db.Where("user_code = ? and rule_status = 999", global.GWAF_USER_CODE).Delete(model.Rules{})

		// 执行数据补丁和默认值初始化（幂等操作，每次启动都执行）
		pathCoreSql(db)
		return isNewDb, nil
	} else {
		return false, nil
	}
}

func InitLogDb(currentDir string) (bool, error) {
	if dialect.Get().Name() == "mysql" {
		return InitLogDbMySQL()
	}
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
		// 升级重叠期可能新旧 Worker 并存写库，busy_timeout 让写操作在锁竞争时重试等待，避免立即报 database is locked
		_ = db.Exec("PRAGMA busy_timeout=5000;")
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

		// ============ 使用 gormigrate 替代 AutoMigrate（完全向后兼容） ============
		zlog.Info("开始执行log数据库迁移...")
		if err := RunLogDBMigrations(db); err != nil {
			errStr := fmt.Sprintf("%v", err)
			zlog.Error("log数据库迁移失败", "error_string", errStr, "error_type", fmt.Sprintf("%T", err))
			zlog.Error("log数据库迁移失败详细信息: " + errStr)
			panic("log database migration failed: " + errStr)
		}
		// ============ 迁移代码结束 ============

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
	if dialect.Get().Name() != "sqlite" {
		// MySQL 模式下所有日志写入同一个库，无需手动切换分库
		return
	}
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
		// 升级重叠期可能新旧 Worker 并存写库，busy_timeout 让写操作在锁竞争时重试等待，避免立即报 database is locked
		_ = db.Exec("PRAGMA busy_timeout=5000;")
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

		// ============ 使用 gormigrate 替代 AutoMigrate（完全向后兼容） ============
		zlog.Info("开始执行手动log数据库迁移...", "file", custFileName)
		if err := RunLogDBMigrations(db); err != nil {
			errStr := fmt.Sprintf("%v", err)
			zlog.Error("手动log数据库迁移失败", "file", custFileName, "error_string", errStr, "error_type", fmt.Sprintf("%T", err))
			zlog.Error("手动log数据库迁移失败详细信息: " + errStr)
			panic("manual log database migration failed: " + errStr)
		}
		// ============ 迁移代码结束 ============

		global.GDATA_CURRENT_LOG_DB_MAP[custFileName].Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)
		global.GDATA_CURRENT_LOG_DB_MAP[custFileName].Callback().Query().Before("gorm:update").Register("tenant_plugin:before_update", before_update)

	} else {
		zlog.Debug("自定义的库已存在", custFileName)
	}
}

func InitStatsDb(currentDir string) (bool, error) {
	if dialect.Get().Name() == "mysql" {
		return InitStatsDbMySQL()
	}
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
		// 升级重叠期可能新旧 Worker 并存写库，busy_timeout 让写操作在锁竞争时重试等待，避免立即报 database is locked
		_ = db.Exec("PRAGMA busy_timeout=5000;")
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

		// ============ 使用 gormigrate 替代 AutoMigrate（完全向后兼容） ============
		zlog.Info("开始执行stats数据库迁移...")
		if err := RunStatsDBMigrations(db); err != nil {
			errStr := fmt.Sprintf("%v", err)
			zlog.Error("stats数据库迁移失败", "error_string", errStr, "error_type", fmt.Sprintf("%T", err))
			zlog.Error("stats数据库迁移失败详细信息: " + errStr)
			panic("stats database migration failed: " + errStr)
		}
		// ============ 迁移代码结束 ============

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
	if !dialect.Get().SupportsBackup() {
		return fmt.Errorf("BackupDatabase 仅在 SQLite 模式下可用，当前驱动: %s", dialect.Get().Name())
	}
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

// RepairDatabase 修复损坏的SQLite数据库
// dbPath: 数据库文件路径
// password: 数据库密码（如果有加密）
func RepairDatabase(dbPath string, password string) error {
	if !dialect.Get().SupportsRepair() {
		return fmt.Errorf("RepairDatabase 仅在 SQLite 模式下可用，当前驱动: %s", dialect.Get().Name())
	}
	zlog.Info("========================================")
	zlog.Info("开始修复数据库:", dbPath)
	zlog.Info("========================================")

	// 检查数据库文件是否存在
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("数据库文件不存在: %s", dbPath)
	}

	// 创建备份文件名
	backupPath := dbPath + ".backup_before_repair_" + time.Now().Format("20060102150405")

	// 1. 先备份原数据库
	zlog.Info("步骤1: 备份原数据库...")
	input, err := os.ReadFile(dbPath)
	if err != nil {
		return fmt.Errorf("读取数据库文件失败: %w", err)
	}
	if err := os.WriteFile(backupPath, input, 0644); err != nil {
		return fmt.Errorf("创建备份失败: %w", err)
	}
	zlog.Info("✓ 备份成功:", backupPath)

	// 2. 打开数据库进行检查
	zlog.Info("步骤2: 检查数据库完整性...")
	key := url.QueryEscape(password)
	dns := fmt.Sprintf("%s?_db_key=%s", dbPath, key)
	db, err := gorm.Open(sqlite.Open(dns), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		zlog.Error("✗ 无法打开数据库，尝试使用 dump 方式修复...")
		return repairDatabaseByDump(dbPath, password, backupPath)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("获取数据库连接失败: %w", err)
	}
	defer sqlDB.Close()

	// 3. 运行完整性检查
	var result string
	err = db.Raw("PRAGMA integrity_check;").Scan(&result).Error
	if err != nil {
		zlog.Error("✗ 完整性检查失败:", err)
		return repairDatabaseByDump(dbPath, password, backupPath)
	}

	zlog.Info("完整性检查结果:", result)

	if result == "ok" {
		zlog.Info("✓ 数据库完整性良好，尝试优化...")

		// 4. 尝试 VACUUM 重建数据库
		zlog.Info("步骤3: 执行 VACUUM 优化...")
		if err := db.Exec("VACUUM;").Error; err != nil {
			zlog.Warn("✗ VACUUM 失败:", err)
		} else {
			zlog.Info("✓ VACUUM 成功")
		}

		// 5. 重新索引
		zlog.Info("步骤4: 重建索引...")
		if err := db.Exec("REINDEX;").Error; err != nil {
			zlog.Warn("✗ REINDEX 失败:", err)
		} else {
			zlog.Info("✓ REINDEX 成功")
		}

		zlog.Info("========================================")
		zlog.Info("✓ 数据库修复完成!")
		zlog.Info("========================================")
		return nil
	} else {
		zlog.Error("✗ 数据库存在完整性问题，尝试使用 dump 方式修复...")
		return repairDatabaseByDump(dbPath, password, backupPath)
	}
}

// repairDatabaseByDump 使用 dump 和重建的方式修复数据库
func repairDatabaseByDump(dbPath string, password string, backupPath string) error {
	zlog.Info("使用导出重建方式修复数据库...")

	// 创建临时修复文件
	repairedPath := dbPath + ".repaired_" + time.Now().Format("20060102150405")

	key := url.QueryEscape(password)

	// 1. 尝试打开源数据库（忽略错误继续）
	zlog.Info("步骤1: 读取源数据库数据...")
	srcDns := fmt.Sprintf("%s?_db_key=%s", dbPath, key)
	srcDB, err := gorm.Open(sqlite.Open(srcDns), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("无法打开源数据库进行修复: %w", err)
	}

	srcSqlDB, err := srcDB.DB()
	if err != nil {
		return fmt.Errorf("获取源数据库连接失败: %w", err)
	}
	defer srcSqlDB.Close()

	// 2. 创建新的数据库
	zlog.Info("步骤2: 创建新数据库...")
	dstDns := fmt.Sprintf("%s?_db_key=%s", repairedPath, key)
	dstDB, err := gorm.Open(sqlite.Open(dstDns), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("创建新数据库失败: %w", err)
	}

	dstSqlDB, err := dstDB.DB()
	if err != nil {
		return fmt.Errorf("获取新数据库连接失败: %w", err)
	}
	defer dstSqlDB.Close()

	// 3. 获取所有表名
	zlog.Info("步骤3: 读取表结构...")
	var tables []string
	err = srcDB.Raw("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;").Scan(&tables).Error
	if err != nil {
		return fmt.Errorf("获取表列表失败: %w", err)
	}

	zlog.Info(fmt.Sprintf("找到 %d 个表", len(tables)))

	// 4. 逐表复制数据
	successCount := 0
	errorCount := 0
	for _, tableName := range tables {
		zlog.Info("正在处理表:", tableName)

		// 获取建表语句
		var createSQL string
		err := srcDB.Raw("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", tableName).Scan(&createSQL).Error
		if err != nil {
			zlog.Error(fmt.Sprintf("✗ 获取表 %s 的建表语句失败: %v", tableName, err))
			errorCount++
			continue
		}

		// 在新数据库中创建表
		if err := dstDB.Exec(createSQL).Error; err != nil {
			zlog.Error(fmt.Sprintf("✗ 创建表 %s 失败: %v", tableName, err))
			errorCount++
			continue
		}

		// 复制数据
		var count int64
		if err := srcDB.Table(tableName).Count(&count).Error; err != nil {
			zlog.Warn(fmt.Sprintf("✗ 获取表 %s 记录数失败: %v", tableName, err))
		} else {
			zlog.Info(fmt.Sprintf("  - 表 %s 有 %d 条记录", tableName, count))
		}

		// 附加源数据库并复制
		attachSQL := fmt.Sprintf("ATTACH DATABASE '%s' AS source", dbPath)
		if err := dstDB.Exec(attachSQL).Error; err != nil {
			zlog.Error(fmt.Sprintf("✗ 附加源数据库失败: %v", err))
			errorCount++
			continue
		}

		copyDataSQL := fmt.Sprintf("INSERT INTO main.%s SELECT * FROM source.%s", tableName, tableName)
		if err := dstDB.Exec(copyDataSQL).Error; err != nil {
			zlog.Warn(fmt.Sprintf("✗ 复制表 %s 数据失败: %v", tableName, err))
			errorCount++
		} else {
			zlog.Info(fmt.Sprintf("✓ 表 %s 复制成功", tableName))
			successCount++
		}

		// 分离数据库
		dstDB.Exec("DETACH DATABASE source")
	}

	// 5. 复制索引和其他对象
	zlog.Info("步骤4: 复制索引...")
	var indexes []string
	err = srcDB.Raw("SELECT sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL ORDER BY name;").Scan(&indexes).Error
	if err == nil {
		for _, indexSQL := range indexes {
			if err := dstDB.Exec(indexSQL).Error; err != nil {
				zlog.Warn("创建索引失败:", err)
			}
		}
	}

	// 6. 关闭数据库连接
	srcSqlDB.Close()
	dstSqlDB.Close()

	// 7. 替换原数据库
	if successCount > 0 {
		zlog.Info("步骤5: 替换原数据库...")

		// 删除原数据库
		if err := os.Remove(dbPath); err != nil {
			return fmt.Errorf("删除原数据库失败: %w", err)
		}

		// 重命名修复后的数据库
		if err := os.Rename(repairedPath, dbPath); err != nil {
			return fmt.Errorf("重命名修复后数据库失败: %w", err)
		}

		zlog.Info("========================================")
		zlog.Info(fmt.Sprintf("✓ 数据库修复完成! 成功: %d 个表, 失败: %d 个表", successCount, errorCount))
		zlog.Info("原数据库备份在:", backupPath)
		zlog.Info("========================================")
		return nil
	} else {
		// 清理修复文件
		os.Remove(repairedPath)
		return fmt.Errorf("修复失败: 没有成功复制任何表")
	}
}

// ExecuteSQLCommand 执行SQL命令工具
func ExecuteSQLCommand(currentDir string) {
	if currentDir == "" {
		currentDir = utils.GetCurrentDir()
	}

	// 初始化审计日志
	auditLogger, auditLogPath := initSQLAuditLogger(currentDir)
	if auditLogger != nil {
		defer auditLogger.Close()
		writeAuditLog(auditLogger, "INFO", "SQL执行工具启动", "")
		fmt.Printf("📝 审计日志: %s\n", auditLogPath)
	}

	fmt.Println("================================================")
	fmt.Println("         SamWaf SQL 执行工具")
	fmt.Println("================================================")
	fmt.Println("\n可以在以下数据库上执行 SQL 语句：")
	fmt.Println("1. 核心数据库 (local.db) - 存储配置、规则等")
	fmt.Println("2. 日志数据库 (local_log.db) - 存储访问日志")
	fmt.Println("3. 统计数据库 (local_stats.db) - 存储统计数据")
	fmt.Println("\n⚠️  警告：")
	fmt.Println("- 执行前请确保已备份数据库")
	fmt.Println("- UPDATE/DELETE 操作会直接修改数据，请谨慎使用")
	fmt.Println("- 不当的 SQL 可能导致数据丢失或系统异常")
	fmt.Println("- 所有操作将被记录到审计日志")

	fmt.Print("\n请选择数据库 (1-3)，或输入 'q' 退出: ")
	var input string
	fmt.Scanln(&input)

	if input == "q" || input == "Q" {
		fmt.Println("已退出 SQL 执行工具")
		writeAuditLog(auditLogger, "INFO", "用户退出SQL执行工具", "")
		return
	}

	var db *gorm.DB
	var dbName string
	var dbPath string
	var password string

	switch input {
	case "1":
		dbPath = currentDir + "/data/local.db"
		dbName = "核心数据库 (local.db)"
		password = global.GWAF_PWD_COREDB
	case "2":
		dbPath = currentDir + "/data/local_log.db"
		dbName = "日志数据库 (local_log.db)"
		password = global.GWAF_PWD_LOGDB
	case "3":
		dbPath = currentDir + "/data/local_stats.db"
		dbName = "统计数据库 (local_stats.db)"
		password = global.GWAF_PWD_STATDB
	default:
		fmt.Println("✗ 无效的选择")
		writeAuditLog(auditLogger, "ERROR", "无效的数据库选择", fmt.Sprintf("输入: %s", input))
		return
	}

	// 检查文件是否存在
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		fmt.Printf("✗ 数据库文件不存在: %s\n", dbPath)
		writeAuditLog(auditLogger, "ERROR", "数据库文件不存在", dbPath)
		return
	}

	// 记录连接数据库
	writeAuditLog(auditLogger, "INFO", fmt.Sprintf("连接数据库: %s", dbName), dbPath)

	// 打开数据库
	fmt.Printf("\n正在连接到 %s...\n", dbName)
	key := url.QueryEscape(password)
	dns := fmt.Sprintf("%s?_db_key=%s", dbPath, key)
	var err error
	db, err = gorm.Open(sqlite.Open(dns), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		fmt.Printf("✗ 连接数据库失败: %v\n", err)
		writeAuditLog(auditLogger, "ERROR", "连接数据库失败", fmt.Sprintf("数据库: %s, 错误: %v", dbName, err))
		return
	}

	sqlDB, err := db.DB()
	if err != nil {
		fmt.Printf("✗ 获取数据库连接失败: %v\n", err)
		writeAuditLog(auditLogger, "ERROR", "获取数据库连接失败", fmt.Sprintf("错误: %v", err))
		return
	}
	defer sqlDB.Close()

	fmt.Printf("✓ 已连接到 %s\n", dbName)
	writeAuditLog(auditLogger, "INFO", "成功连接数据库", dbName)

	fmt.Println("\n================================================")
	fmt.Println("SQL 执行模式")
	fmt.Println("================================================")
	fmt.Println("提示:")
	fmt.Println("- 输入 SQL 语句并按回车执行")
	fmt.Println("- 输入 'tables' 查看所有表")
	fmt.Println("- 输入 'quit' 或 'exit' 退出")
	fmt.Println("- 示例: SELECT * FROM account LIMIT 10")
	fmt.Println("================================================")

	// 创建输入扫描器
	scanner := bufio.NewScanner(os.Stdin)

	// 交互式执行 SQL
	for {
		fmt.Print("SQL> ")

		if !scanner.Scan() {
			break
		}

		sqlInput := scanner.Text()
		sqlInput = strings.TrimSpace(sqlInput)

		// 跳过空行
		if sqlInput == "" {
			continue
		}

		// 特殊命令处理
		switch strings.ToLower(sqlInput) {
		case "quit", "exit", "q":
			fmt.Println("\n已退出 SQL 执行工具")
			writeAuditLog(auditLogger, "INFO", "用户退出SQL执行工具", "")
			return
		case "tables":
			writeAuditLog(auditLogger, "INFO", "查看表列表", dbName)
			listTables(db)
			continue
		case "help", "?":
			fmt.Println("\n可用命令:")
			fmt.Println("  tables       - 显示所有表")
			fmt.Println("  help/?       - 显示此帮助")
			fmt.Println("  quit/exit/q  - 退出")
			fmt.Println("\nSQL 语句示例:")
			fmt.Println("  SELECT * FROM account LIMIT 10;")
			fmt.Println("  UPDATE hosts SET status=1 WHERE code='xxx';")
			fmt.Println("  DELETE FROM web_logs WHERE unix_add_time < 1234567890;")
			fmt.Println("")
			continue
		}

		// 执行 SQL（带审计日志）
		executeSingleSQLWithAudit(db, sqlInput, dbName, auditLogger)
		fmt.Println("")
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("✗ 读取输入错误: %v\n", err)
		writeAuditLog(auditLogger, "ERROR", "读取输入错误", fmt.Sprintf("错误: %v", err))
	}
}

// initSQLAuditLogger 初始化SQL审计日志
func initSQLAuditLogger(currentDir string) (*os.File, string) {
	// 确保logs目录存在
	logsDir := filepath.Join(currentDir, "logs")
	if err := os.MkdirAll(logsDir, os.ModePerm); err != nil {
		fmt.Printf("⚠️  警告: 无法创建logs目录: %v\n", err)
		return nil, ""
	}

	// 创建审计日志文件
	logPath := filepath.Join(logsDir, "db.log")
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("⚠️  警告: 无法创建审计日志文件: %v\n", err)
		return nil, ""
	}

	return file, logPath
}

// writeAuditLog 写入审计日志
func writeAuditLog(logger *os.File, level, action, detail string) {
	if logger == nil {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	logLine := fmt.Sprintf("[%s] [%s] %s", timestamp, level, action)
	if detail != "" {
		logLine += fmt.Sprintf(" | %s", detail)
	}
	logLine += "\n"

	if _, err := logger.WriteString(logLine); err != nil {
		fmt.Printf("⚠️  警告: 写入审计日志失败: %v\n", err)
	}
}

// executeSingleSQLWithAudit 执行单条 SQL 语句（带审计日志）
func executeSingleSQLWithAudit(db *gorm.DB, sqlStr string, dbName string, auditLogger *os.File) {
	sqlStr = strings.TrimSpace(sqlStr)
	if sqlStr == "" {
		return
	}

	// 记录SQL执行
	writeAuditLog(auditLogger, "INFO", fmt.Sprintf("执行SQL [数据库: %s]", dbName), sqlStr)

	// 判断 SQL 类型
	sqlUpper := strings.ToUpper(sqlStr)
	isQuery := strings.HasPrefix(sqlUpper, "SELECT") ||
		strings.HasPrefix(sqlUpper, "PRAGMA") ||
		strings.HasPrefix(sqlUpper, "SHOW")

	if isQuery {
		// 查询语句
		executeQuerySQLWithAudit(db, sqlStr, dbName, auditLogger)
	} else {
		// 修改语句（UPDATE/DELETE/INSERT等）
		executeModifySQLWithAudit(db, sqlStr, dbName, auditLogger)
	}
}

// listTables 列出所有表
func listTables(db *gorm.DB) {
	var tables []string
	err := db.Raw("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").Scan(&tables).Error
	if err != nil {
		fmt.Printf("✗ 查询表列表失败: %v\n", err)
		return
	}

	fmt.Println("\n数据库中的表:")
	fmt.Println("----------------------------------------")
	for i, table := range tables {
		// 获取表的记录数
		var count int64
		db.Table(table).Count(&count)
		fmt.Printf("%2d. %-30s (记录数: %d)\n", i+1, table, count)
	}
	fmt.Println("----------------------------------------")
}

// executeQuerySQLWithAudit 执行查询语句（带审计）
func executeQuerySQLWithAudit(db *gorm.DB, sqlStr string, dbName string, auditLogger *os.File) {
	rows, err := db.Raw(sqlStr).Rows()
	if err != nil {
		fmt.Printf("✗ 执行查询失败: %v\n", err)
		writeAuditLog(auditLogger, "ERROR", fmt.Sprintf("查询执行失败 [数据库: %s]", dbName), fmt.Sprintf("错误: %v", err))
		return
	}
	defer rows.Close()

	// 获取列名
	columns, err := rows.Columns()
	if err != nil {
		fmt.Printf("✗ 获取列信息失败: %v\n", err)
		writeAuditLog(auditLogger, "ERROR", fmt.Sprintf("获取列信息失败 [数据库: %s]", dbName), fmt.Sprintf("错误: %v", err))
		return
	}

	fmt.Println("\n查询结果:")
	fmt.Println("----------------------------------------")

	// 打印列名
	for i, col := range columns {
		if i > 0 {
			fmt.Print(" | ")
		}
		fmt.Printf("%-20s", col)
	}
	fmt.Println()
	fmt.Println(strings.Repeat("-", len(columns)*23))

	// 打印数据行
	rowCount := 0
	for rows.Next() {
		// 创建接收数据的切片
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			fmt.Printf("✗ 读取数据失败: %v\n", err)
			writeAuditLog(auditLogger, "ERROR", fmt.Sprintf("读取数据失败 [数据库: %s]", dbName), fmt.Sprintf("错误: %v", err))
			return
		}

		// 打印每一列的值
		for i, val := range values {
			if i > 0 {
				fmt.Print(" | ")
			}
			// 处理 nil 值
			if val == nil {
				fmt.Printf("%-20s", "NULL")
			} else {
				// 将值转换为字符串
				strVal := fmt.Sprintf("%v", val)
				if len(strVal) > 20 {
					strVal = strVal[:17] + "..."
				}
				fmt.Printf("%-20s", strVal)
			}
		}
		fmt.Println()
		rowCount++

		// 限制显示行数，避免输出过多
		if rowCount >= 100 {
			fmt.Println("... (仅显示前100行)")
			break
		}
	}

	fmt.Println("----------------------------------------")
	fmt.Printf("✓ 查询完成，共 %d 行\n", rowCount)

	// 记录审计日志
	writeAuditLog(auditLogger, "SUCCESS", fmt.Sprintf("查询执行成功 [数据库: %s]", dbName), fmt.Sprintf("返回 %d 行", rowCount))
}

// executeModifySQLWithAudit 执行修改语句（带审计）
func executeModifySQLWithAudit(db *gorm.DB, sqlStr string, dbName string, auditLogger *os.File) {
	// 二次确认
	fmt.Print("\n⚠️  您即将执行修改操作，是否继续？(yes/no): ")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Println("✗ 操作已取消")
		writeAuditLog(auditLogger, "CANCEL", fmt.Sprintf("用户取消修改操作 [数据库: %s]", dbName), "读取确认失败")
		return
	}

	confirm := strings.TrimSpace(strings.ToLower(scanner.Text()))

	if confirm != "yes" && confirm != "y" {
		fmt.Println("✗ 操作已取消")
		writeAuditLog(auditLogger, "CANCEL", fmt.Sprintf("用户取消修改操作 [数据库: %s]", dbName), fmt.Sprintf("用户输入: %s", confirm))
		return
	}

	// 记录用户确认执行
	writeAuditLog(auditLogger, "CONFIRM", fmt.Sprintf("用户确认执行修改 [数据库: %s]", dbName), "")

	result := db.Exec(sqlStr)
	if result.Error != nil {
		fmt.Printf("✗ 执行失败: %v\n", result.Error)
		writeAuditLog(auditLogger, "ERROR", fmt.Sprintf("修改执行失败 [数据库: %s]", dbName), fmt.Sprintf("错误: %v", result.Error))
		return
	}

	fmt.Printf("✓ 执行成功，影响 %d 行\n", result.RowsAffected)
	writeAuditLog(auditLogger, "SUCCESS", fmt.Sprintf("修改执行成功 [数据库: %s]", dbName), fmt.Sprintf("影响 %d 行", result.RowsAffected))
}

// RepairAllDatabases 修复所有数据库
func RepairAllDatabases(currentDir string) {
	if currentDir == "" {
		currentDir = utils.GetCurrentDir()
	}

	databases := []struct {
		Path     string
		Name     string
		Password string
	}{
		{
			Path:     currentDir + "/data/local.db",
			Name:     "核心数据库 (local.db)",
			Password: global.GWAF_PWD_COREDB,
		},
		{
			Path:     currentDir + "/data/local_log.db",
			Name:     "日志数据库 (local_log.db)",
			Password: global.GWAF_PWD_LOGDB,
		},
		{
			Path:     currentDir + "/data/local_stats.db",
			Name:     "统计数据库 (local_stats.db)",
			Password: global.GWAF_PWD_STATDB,
		},
	}

	fmt.Println("\n================================================")
	fmt.Println("         SamWaf 数据库修复工具")
	fmt.Println("================================================")
	fmt.Println("\n将检查并修复以下数据库：")
	for i, db := range databases {
		fmt.Printf("%d. %s\n", i+1, db.Name)
		fmt.Printf("   路径: %s\n", db.Path)
	}
	fmt.Println("\n⚠️  警告：修复前会自动备份数据库")
	fmt.Print("\n是否继续？请输入数据库编号 (1-3)，或输入 'all' 修复全部，输入 'q' 退出: ")

	var input string
	fmt.Scanln(&input)

	if input == "q" || input == "Q" {
		fmt.Println("已取消修复操作")
		return
	}

	var selectedDBs []int
	if input == "all" || input == "ALL" {
		selectedDBs = []int{0, 1, 2}
	} else {
		// 解析用户输入的数字
		var dbIndex int
		_, err := fmt.Sscanf(input, "%d", &dbIndex)
		if err != nil || dbIndex < 1 || dbIndex > 3 {
			fmt.Println("✗ 无效的输入")
			return
		}
		selectedDBs = []int{dbIndex - 1}
	}

	// 执行修复
	successCount := 0
	errorCount := 0

	for _, idx := range selectedDBs {
		db := databases[idx]
		fmt.Printf("\n正在修复: %s\n", db.Name)

		// 检查文件是否存在
		if _, err := os.Stat(db.Path); os.IsNotExist(err) {
			fmt.Printf("✗ 数据库文件不存在，跳过: %s\n", db.Path)
			continue
		}

		err := RepairDatabase(db.Path, db.Password)
		if err != nil {
			fmt.Printf("✗ 修复失败: %v\n", err)
			errorCount++
		} else {
			fmt.Printf("✓ 修复成功\n")
			successCount++
		}
	}

	fmt.Println("\n================================================")
	fmt.Printf("修复完成! 成功: %d, 失败: %d\n", successCount, errorCount)
	fmt.Println("================================================")

	if errorCount > 0 {
		fmt.Println("\n⚠️  部分数据库修复失败，请检查日志")
	}
}
