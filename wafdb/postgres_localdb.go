package wafdb

// PostgreSQL-specific database initialisation.
// Mirrors mysql_localdb.go; see that file for the shape this follows.

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
	"time"

	pgdriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ensurePostgresDatabase makes sure dbName exists before we open a GORM connection to it.
//
// PostgreSQL has no "CREATE DATABASE IF NOT EXISTS", and CREATE DATABASE cannot run
// inside a transaction or from a connection to the database being created. So:
//
//  1. Connect to the maintenance database (default "postgres"), check pg_database, and
//     CREATE DATABASE if absent. Succeeds when the user has the CREATEDB privilege.
//  2. If step 1 fails (no CREATEDB privilege, maintenance DB unreachable), try connecting
//     directly to the target database.
//     • Direct connection OK  → database already exists; the user just lacks CREATEDB —
//     proceed normally.
//     • Direct connection fails → cannot create and cannot reach it; print the exact SQL
//     the user must run manually and abort.
func ensurePostgresDatabase(dbName string) error {
	maintDSN := dialect.BuildPostgresMaintenanceDSN(
		global.GWAF_PG_HOST, global.GWAF_PG_PORT,
		global.GWAF_PG_USER, global.GWAF_PG_PASSWORD,
		global.GWAF_PG_MAINTENANCE_DB, global.GWAF_PG_SSLMODE,
	)

	// Step 1: connect to the maintenance DB and auto-create.
	maintDB, connErr := gorm.Open(pgdriver.Open(maintDSN), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if connErr == nil {
		sqlDB, _ := maintDB.DB()
		defer sqlDB.Close()

		var version string
		maintDB.Raw("SELECT version()").Scan(&version)
		zlog.Info("postgres: 服务器信息", "version", version)

		var exists int64
		maintDB.Raw("SELECT 1 FROM pg_database WHERE datname = ?", dbName).Scan(&exists)
		if exists == 1 {
			zlog.Info("postgres: 数据库已存在", "db", dbName)
			return nil
		}

		// A bare Exec autocommits — do NOT wrap this in a transaction, CREATE DATABASE
		// is not allowed inside one.
		createSQL := fmt.Sprintf(`CREATE DATABASE %s ENCODING 'UTF8'`, pgIdent(dbName))
		if createErr := maintDB.Exec(createSQL).Error; createErr == nil {
			zlog.Info("postgres: 数据库创建成功", "db", dbName)
			return nil
		} else {
			zlog.Warn("postgres: 自动建库失败，尝试直连确认库是否已存在",
				"db", dbName, "error", createErr)
		}
	} else {
		zlog.Warn("postgres: 维护库连接失败，尝试直连目标库",
			"maintenance_db", global.GWAF_PG_MAINTENANCE_DB, "db", dbName, "error", connErr)
	}

	// Step 2: fall back — try connecting directly to the target database.
	directDB, directErr := gorm.Open(pgdriver.Open(buildPGDSN(dbName)), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if directErr == nil {
		directSQLDB, _ := directDB.DB()
		directSQLDB.Close()
		zlog.Info("postgres: 数据库已存在，跳过自动建库", "db", dbName)
		return nil
	}

	// Step 3: nothing worked — emit actionable guidance and abort.
	hint := fmt.Sprintf(
		"\n========================================================\n"+
			"  数据库 %s 不存在，且当前账户无权自动创建。\n"+
			"  请用 PostgreSQL 超级用户执行以下 SQL，然后重启 SamWaf：\n\n"+
			"    CREATE DATABASE %s ENCODING 'UTF8';\n"+
			"    GRANT ALL PRIVILEGES ON DATABASE %s TO %s;\n"+
			"========================================================",
		dbName, dbName, dbName, global.GWAF_PG_USER,
	)
	fmt.Println(hint) // also to stdout so it's visible without a log viewer
	zlog.Error("postgres: 无法连接或创建数据库", "db", dbName, "hint", hint)
	return fmt.Errorf("postgres: 数据库 %s 不存在且权限不足，请手动建库后重启（详见日志）", dbName)
}

// buildPGDSN builds the DSN for one of the SamWaf databases from global config.
func buildPGDSN(dbName string) string {
	return dialect.BuildPostgresDSN(
		global.GWAF_PG_HOST, global.GWAF_PG_PORT,
		global.GWAF_PG_USER, global.GWAF_PG_PASSWORD,
		dbName, global.GWAF_PG_SSLMODE, global.GWAF_PG_TIMEZONE,
	)
}

// pgIdent quotes an identifier for DDL built here (database names).
func pgIdent(name string) string {
	return `"` + name + `"`
}

// openPostgresDB opens a GORM connection to the named PostgreSQL database,
// applying connection pool settings from global config.
func openPostgresDB(dbName string) (*gorm.DB, error) {
	if err := ensurePostgresDatabase(dbName); err != nil {
		return nil, err
	}
	return openPostgresDBRaw(dbName)
}

// openPostgresDBRaw opens the database without trying to create it.
func openPostgresDBRaw(dbName string) (*gorm.DB, error) {
	db, err := gorm.Open(pgdriver.Open(buildPGDSN(dbName)), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("postgres: 打开数据库 %s 失败: %w", dbName, err)
	}

	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(global.GWAF_PG_MAX_OPEN_CONNS)
	sqlDB.SetMaxIdleConns(global.GWAF_PG_MAX_IDLE_CONNS)
	sqlDB.SetConnMaxLifetime(time.Duration(global.GWAF_PG_CONN_MAX_LIFETIME_MINUTES) * time.Minute)
	// 与 MySQL 侧同理：空闲连接最多存活 3 分钟，避免服务端先行断开后连接池仍持有死连接
	sqlDB.SetConnMaxIdleTime(3 * time.Minute)

	return db, nil
}

// InitCoreDbPostgres initialises the PostgreSQL core database.
func InitCoreDbPostgres() (bool, error) {
	if global.GWAF_LOCAL_DB != nil {
		return false, nil
	}

	dbName := global.GWAF_PG_CORE_DB
	zlog.Info("postgres: 初始化核心数据库", "db", dbName)

	db, err := openPostgresDB(dbName)
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

// InitLogDbPostgres initialises the PostgreSQL log database.
func InitLogDbPostgres() (bool, error) {
	if global.GWAF_LOCAL_LOG_DB != nil {
		return false, nil
	}

	dbName := global.GWAF_PG_LOG_DB
	zlog.Info("postgres: 初始化日志数据库", "db", dbName)

	db, err := openPostgresDB(dbName)
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

// InitStatsDbPostgres initialises the PostgreSQL statistics database.
func InitStatsDbPostgres() (bool, error) {
	if global.GWAF_LOCAL_STATS_DB != nil {
		return false, nil
	}

	dbName := global.GWAF_PG_STATS_DB
	zlog.Info("postgres: 初始化统计数据库", "db", dbName)

	db, err := openPostgresDB(dbName)
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
