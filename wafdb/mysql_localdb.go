package wafdb

// MySQL-specific database initialisation.
// This file is compiled for all platforms; the build tag for MySQL driver
// activation is handled via the go.mod dependency on gorm.io/driver/mysql.

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/wafdb/dialect"
	"fmt"
	"strconv"
	"strings"
	"time"

	mysqldriver "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// mysqlServerInfo holds a parsed MySQL / MariaDB version string.
type mysqlServerInfo struct {
	Major     int
	Minor     int
	Patch     int
	IsMariaDB bool
	Raw       string
}

// detectServerInfo queries @@VERSION from an open GORM connection.
func detectServerInfo(db *gorm.DB) mysqlServerInfo {
	var raw string
	db.Raw("SELECT @@VERSION").Scan(&raw)
	return parseMySQLVersion(raw)
}

// parseMySQLVersion parses strings like:
//
//	"8.0.32"          → MySQL 8.0
//	"5.7.44-log"      → MySQL 5.7
//	"10.6.12-MariaDB" → MariaDB 10.6
func parseMySQLVersion(version string) mysqlServerInfo {
	info := mysqlServerInfo{Raw: version}
	info.IsMariaDB = strings.Contains(strings.ToLower(version), "mariadb")
	parts := strings.SplitN(version, ".", 3)
	if len(parts) >= 1 {
		info.Major, _ = strconv.Atoi(leadingDigits(parts[0]))
	}
	if len(parts) >= 2 {
		info.Minor, _ = strconv.Atoi(leadingDigits(parts[1]))
	}
	if len(parts) >= 3 {
		info.Patch, _ = strconv.Atoi(leadingDigits(parts[2]))
	}
	return info
}

// leadingDigits returns the leading ASCII digit sequence in s.
func leadingDigits(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return s[:i]
		}
	}
	return s
}

// bestCollation returns the most appropriate utf8mb4 collation for this server:
//
//	MySQL 8.0+          → utf8mb4_0900_ai_ci  (default; best Unicode support)
//	MySQL 5.x / MariaDB → utf8mb4_general_ci  (universally available)
func (v mysqlServerInfo) bestCollation() string {
	if !v.IsMariaDB && v.Major >= 8 {
		return "utf8mb4_0900_ai_ci"
	}
	return "utf8mb4_general_ci"
}

// label returns a human-readable flavour string for log messages.
func (v mysqlServerInfo) label() string {
	if v.IsMariaDB {
		return fmt.Sprintf("MariaDB %d.%d.%d", v.Major, v.Minor, v.Patch)
	}
	return fmt.Sprintf("MySQL %d.%d.%d", v.Major, v.Minor, v.Patch)
}

// ensureMySQLDatabase makes sure dbName exists before we open a GORM connection to it.
//
// Strategy:
//  1. Connect to the server without selecting a database, detect the server
//     version, pick the best collation for that version, then issue
//     CREATE DATABASE IF NOT EXISTS.  Succeeds when the user has CREATE privilege.
//  2. If step 1 fails (permission denied, or server refuses the collation for any
//     reason), try connecting directly to the target database.
//     • Direct connection OK  → database already exists; user just lacks CREATE
//       privilege — proceed normally.
//     • Direct connection fails → database does not exist and cannot be created;
//       log a clear hint with the exact SQL the user must run manually.
func ensureMySQLDatabase(dbName string) error {
	rootDSN := dialect.BuildMySQLRootDSN(
		global.GWAF_MYSQL_HOST, global.GWAF_MYSQL_PORT,
		global.GWAF_MYSQL_USER, global.GWAF_MYSQL_PASSWORD,
		global.GWAF_MYSQL_CHARSET,
	)

	// Step 1: connect without a database, detect version, auto-create.
	rootDB, connErr := gorm.Open(mysqldriver.Open(rootDSN), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if connErr == nil {
		sqlDB, _ := rootDB.DB()
		defer sqlDB.Close()

		info := detectServerInfo(rootDB)
		collation := info.bestCollation()
		createSQL := fmt.Sprintf(
			"CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE %s",
			dbName, collation,
		)
		zlog.Info("mysql: 服务器信息", "version", info.label(), "collation", collation)

		if createErr := rootDB.Exec(createSQL).Error; createErr == nil {
			zlog.Info("mysql: 数据库已就绪（新建或已存在）", "db", dbName)
			return nil
		} else {
			zlog.Warn("mysql: 自动建库失败，尝试直连确认库是否已存在",
				"db", dbName, "error", createErr)
		}
	} else {
		zlog.Warn("mysql: 无 database 根连接失败，尝试直连目标库",
			"db", dbName, "error", connErr)
	}

	// Step 2: fall back — try connecting directly to the target database.
	directDSN := dialect.BuildMySQLDSN(
		global.GWAF_MYSQL_HOST, global.GWAF_MYSQL_PORT,
		global.GWAF_MYSQL_USER, global.GWAF_MYSQL_PASSWORD,
		dbName, global.GWAF_MYSQL_CHARSET,
	)
	directDB, directErr := gorm.Open(mysqldriver.Open(directDSN), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if directErr == nil {
		directSQLDB, _ := directDB.DB()
		directSQLDB.Close()
		zlog.Info("mysql: 数据库已存在，跳过自动建库", "db", dbName)
		return nil
	}

	// Step 3: nothing worked — emit actionable guidance and abort.
	// Use utf8mb4_general_ci in the hint: it works on all MySQL/MariaDB versions.
	hintSQL := fmt.Sprintf(
		"CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci",
		dbName,
	)
	hint := fmt.Sprintf(
		"\n========================================================\n"+
			"  数据库 `%s` 不存在，且当前账户无权自动创建。\n"+
			"  请用 MySQL root 账户执行以下 SQL，然后重启 SamWaf：\n\n"+
			"    %s;\n"+
			"    GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'%%';\n"+
			"    FLUSH PRIVILEGES;\n"+
			"========================================================",
		dbName, hintSQL, dbName, global.GWAF_MYSQL_USER,
	)
	fmt.Println(hint) // also print to stdout so it's visible even without log viewer
	zlog.Error("mysql: 无法连接或创建数据库", "db", dbName, "hint", hint)
	return fmt.Errorf("mysql: 数据库 `%s` 不存在且权限不足，请手动建库后重启（详见日志）", dbName)
}

// openMySQLDB opens a GORM connection to the named MySQL database,
// applying connection pool settings from global config.
func openMySQLDB(dbName string) (*gorm.DB, error) {
	if err := ensureMySQLDatabase(dbName); err != nil {
		return nil, err
	}
	dsn := dialect.BuildMySQLDSN(
		global.GWAF_MYSQL_HOST, global.GWAF_MYSQL_PORT,
		global.GWAF_MYSQL_USER, global.GWAF_MYSQL_PASSWORD,
		dbName, global.GWAF_MYSQL_CHARSET,
	)
	db, err := gorm.Open(mysqldriver.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("mysql: 打开数据库 %s 失败: %w", dbName, err)
	}

	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(global.GWAF_MYSQL_MAX_OPEN_CONNS)
	sqlDB.SetMaxIdleConns(global.GWAF_MYSQL_MAX_IDLE_CONNS)
	sqlDB.SetConnMaxLifetime(time.Duration(global.GWAF_MYSQL_CONN_MAX_LIFETIME_MINUTES) * time.Minute)
	// 空闲连接最多存活 3 分钟，远小于 MySQL 默认 wait_timeout(8h)，
	// 避免 MySQL 主动关闭后 Go 连接池仍持有死连接，导致 "bad connection"
	sqlDB.SetConnMaxIdleTime(3 * time.Minute)

	return db, nil
}

// applyGormLogger attaches the custom GormZLogger (and debug mode) to db.
func applyGormLogger(db *gorm.DB) *gorm.DB {
	gormLogger := NewGormZLogger()
	if global.GWAF_LOG_DEBUG_DB_ENABLE {
		gormLogger = gormLogger.LogMode(logger.Info).(*GormZLogger)
		db = db.Session(&gorm.Session{Logger: gormLogger})
	}
	return db
}

// InitCoreDbMySQL initialises the MySQL core database.
func InitCoreDbMySQL() (bool, error) {
	if global.GWAF_LOCAL_DB != nil {
		return false, nil
	}

	dbName := global.GWAF_MYSQL_CORE_DB
	zlog.Info("mysql: 初始化核心数据库", "db", dbName)

	db, err := openMySQLDB(dbName)
	if err != nil {
		return false, err
	}
	db = applyGormLogger(db)
	global.GWAF_LOCAL_DB = db

	zlog.Info("开始执行core数据库迁移...")
	if err := RunCoreDBMigrations(db); err != nil {
		panic("core database migration failed: " + err.Error())
	}
	zlog.Info("开始执行任务初始化迁移...")
	if err := RunTaskInitMigrations(db); err != nil {
		panic("task initialization migration failed: " + err.Error())
	}

	global.GWAF_LOCAL_DB.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)
	global.GWAF_LOCAL_DB.Callback().Query().Before("gorm:update").Register("tenant_plugin:before_update", before_update)

	db.Where("user_code = ? and rule_status = 999", global.GWAF_USER_CODE).Delete(model.Rules{})
	pathCoreSql(db)
	return false, nil
}

// InitLogDbMySQL initialises the MySQL log database.
func InitLogDbMySQL() (bool, error) {
	if global.GWAF_LOCAL_LOG_DB != nil {
		return false, nil
	}

	dbName := global.GWAF_MYSQL_LOG_DB
	zlog.Info("mysql: 初始化日志数据库", "db", dbName)

	db, err := openMySQLDB(dbName)
	if err != nil {
		return false, err
	}
	db = applyGormLogger(db)
	global.GWAF_LOCAL_LOG_DB = db

	zlog.Info("开始执行log数据库迁移...")
	if err := RunLogDBMigrations(db); err != nil {
		panic("log database migration failed: " + err.Error())
	}

	global.GWAF_LOCAL_LOG_DB.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)
	global.GWAF_LOCAL_LOG_DB.Callback().Query().Before("gorm:update").Register("tenant_plugin:before_update", before_update)

	pathLogSql(db)

	// 确保存在一条 live 分片记录(web_logs)。幂等：仅当该记录不存在时创建。
	// 不能用 share_dbs 总数判断——从 SQLite 迁移过来时表里已有 .db 历史分片，总数!=0 会导致 live 记录缺失。
	var liveCount int64
	global.GWAF_LOCAL_DB.Model(&model.ShareDb{}).Where("file_name = ?", "web_logs").Count(&liveCount)
	if liveCount == 0 {
		var logTotal int64
		global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Count(&logTotal)

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
			// live 分片标识用 web_logs 表名（与 ResolveLogDB 的 live 判定一致）；
			// 历史分片由分表任务写入 web_logs_<ts> 表名。不能用库名，否则读取会误入历史分支。
			FileName: "web_logs",
			Cnt:      logTotal,
		}
		global.GWAF_LOCAL_DB.Create(sharDbBean)
	}

	return false, nil
}

// InitStatsDbMySQL initialises the MySQL statistics database.
func InitStatsDbMySQL() (bool, error) {
	if global.GWAF_LOCAL_STATS_DB != nil {
		return false, nil
	}

	dbName := global.GWAF_MYSQL_STATS_DB
	zlog.Info("mysql: 初始化统计数据库", "db", dbName)

	db, err := openMySQLDB(dbName)
	if err != nil {
		return false, err
	}
	db = applyGormLogger(db)
	global.GWAF_LOCAL_STATS_DB = db

	zlog.Info("开始执行stats数据库迁移...")
	if err := RunStatsDBMigrations(db); err != nil {
		panic("stats database migration failed: " + err.Error())
	}

	global.GWAF_LOCAL_STATS_DB.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)
	global.GWAF_LOCAL_STATS_DB.Callback().Query().Before("gorm:update").Register("tenant_plugin:before_update", before_update)

	pathStatsSql(db)
	return false, nil
}
