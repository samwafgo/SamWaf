package wafdb

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/utils"
	"SamWaf/utils/zlog"
	"fmt"
	uuid "github.com/satori/go.uuid"
	"gorm.io/gorm/logger"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	//"github.com/kangarooxin/gorm-plugin-crypto"
	//"github.com/kangarooxin/gorm-plugin-crypto/strategy"
	"github.com/pengge/sqlitedriver"
	"gorm.io/gorm"
)

func InitCoreDb(currentDir string) {
	if currentDir == "" {
		currentDir = utils.GetCurrentDir()
	}
	// 判断备份目录是否存在，不存在则创建
	if _, err := os.Stat(currentDir + "/data/"); os.IsNotExist(err) {
		if err := os.MkdirAll(currentDir+"/data/", os.ModePerm); err != nil {
			zlog.Error("创建data目录失败:", err)
			return
		}
	}
	if global.GWAF_LOCAL_DB == nil {
		path := currentDir + "/data/local.db"
		// 检查文件是否存在
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			// 文件存在的逻辑
			backupDir := currentDir + "/data/backups"
			// 判断备份目录是否存在，不存在则创建
			if _, err := os.Stat(backupDir); os.IsNotExist(err) {
				if err := os.MkdirAll(backupDir, os.ModePerm); err != nil {
					zlog.Error("创建备份目录失败:", err)
					return
				}
			}
			// 创建备份文件
			backupFilePath := filepath.Join(backupDir, fmt.Sprintf("local_backup_%s.db", time.Now().Format("20060102150405")))
			backupFile, err := os.Create(backupFilePath)
			if err != nil {
				zlog.Error("创建备份文件失败:", err)
				return
			}
			defer backupFile.Close()

			// 打开原始文件
			originalFile, err := os.Open(path)
			if err != nil {
				zlog.Error("打开原始文件失败:", err)
				return
			}
			defer originalFile.Close()

			// 复制文件内容到备份文件
			_, err = io.Copy(backupFile, originalFile)
			if err != nil {
				zlog.Error("文件复制失败:", err)
				return
			}

			zlog.Info("文件备份成功，备份文件路径：", backupFilePath)
		}
		key := url.QueryEscape(global.GWAF_PWD_COREDB)
		dns := fmt.Sprintf("%s?_db_key=%s", path, key)
		db, err := gorm.Open(sqlite.Open(dns), &gorm.Config{})
		if err != nil {
			panic("failed to connect database")
		}
		// 启用 WAL 模式
		_ = db.Exec("PRAGMA journal_mode=WAL;")

		if global.GWAF_RELEASE == "false" {
			// 启用调试模式
			db = db.Session(&gorm.Session{
				Logger: logger.Default.LogMode(logger.Info), // 设置为Info表示启用调试模式
			})
		}
		global.GWAF_LOCAL_DB = db

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
		global.GWAF_LOCAL_DB.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)
		global.GWAF_LOCAL_DB.Callback().Query().Before("gorm:update").Register("tenant_plugin:before_update", before_update)

		//重启需要删除无效规则
		db.Where("user_code = ? and rule_status = 999", global.GWAF_USER_CODE).Delete(model.Rules{})

	}
}

func InitLogDb(currentDir string) {
	if currentDir == "" {
		currentDir = utils.GetCurrentDir()
	}
	if global.GWAF_LOCAL_LOG_DB == nil {
		path := currentDir + "/data/local_log.db"
		key := url.QueryEscape(global.GWAF_PWD_LOGDB)
		dns := fmt.Sprintf("%s?_db_key=%s", path, key)
		db, err := gorm.Open(sqlite.Open(dns), &gorm.Config{})
		if err != nil {
			panic("failed to connect database")
		}
		// 启用 WAL 模式
		_ = db.Exec("PRAGMA journal_mode=WAL;")
		if global.GWAF_RELEASE == "false" {
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

		var total int64 = 0
		global.GWAF_LOCAL_DB.Model(&model.ShareDb{}).Count(&total)
		if total == 0 {

			var logtotal int64 = 0
			global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Count(&logtotal)

			sharDbBean := model.ShareDb{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.NewV4().String(),
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
		if global.GWAF_RELEASE == "false" {
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

func InitStatsDb(currentDir string) {
	if currentDir == "" {
		currentDir = utils.GetCurrentDir()
	}
	if global.GWAF_LOCAL_STATS_DB == nil {
		path := currentDir + "/data/local_stats.db"
		key := url.QueryEscape(global.GWAF_PWD_STATDB)
		dns := fmt.Sprintf("%s?_db_key=%s", path, key)
		db, err := gorm.Open(sqlite.Open(dns), &gorm.Config{})
		if err != nil {
			panic("failed to connect database")
		}
		// 启用 WAL 模式
		_ = db.Exec("PRAGMA journal_mode=WAL;")
		if global.GWAF_RELEASE == "false" {
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

	}
}

func before_query(db *gorm.DB) {
	db.Where("tenant_id = ? and user_code=? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
}
func before_update(db *gorm.DB) {
}
