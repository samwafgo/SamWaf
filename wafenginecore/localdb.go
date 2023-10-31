package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils"
	"SamWaf/utils/zlog"
	//"github.com/kangarooxin/gorm-plugin-crypto"
	//"github.com/kangarooxin/gorm-plugin-crypto/strategy"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func InitDb(currentDir string) {
	if currentDir == "" {
		currentDir = utils.GetCurrentDir()
	}
	if global.GWAF_LOCAL_DB == nil {
		path := currentDir + "/data/local.db"
		db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
		if err != nil {
			panic("failed to connect database")
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
		db.AutoMigrate(&model.IPWhiteList{})
		db.AutoMigrate(&model.URLWhiteList{})

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

		global.GWAF_LOCAL_DB.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)
		global.GWAF_LOCAL_DB.Callback().Query().Before("gorm:update").Register("tenant_plugin:before_update", before_update)

		//重启需要删除无效规则
		db.Where("user_code = ? and rule_status = 999", global.GWAF_USER_CODE).Delete(model.Rules{})

	}
	if global.GWAF_LOCAL_LOG_DB == nil {
		logDB, err := gorm.Open(sqlite.Open(currentDir+"/data/local_log.db"), &gorm.Config{})
		if err != nil {
			panic("failed to connect database")
		}
		global.GWAF_LOCAL_LOG_DB = logDB
		//logDB.Use(crypto.NewCryptoPlugin())
		// 注册默认的AES加解密策略
		//crypto.RegisterCryptoStrategy(strategy.NewAesCryptoStrategy("3Y)(27EtO^tK8Bj~"))
		// Migrate the schema
		//统计处理
		logDB.AutoMigrate(&model.StatsTotal{})
		logDB.AutoMigrate(&model.StatsDay{})
		logDB.AutoMigrate(&model.StatsIPDay{})
		logDB.AutoMigrate(&model.StatsIPCityDay{})
		logDB.AutoMigrate(&innerbean.WebLog{})
		logDB.AutoMigrate(&model.AccountLog{})
		logDB.AutoMigrate(&model.WafSysLog{})
		global.GWAF_LOCAL_LOG_DB.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)
		global.GWAF_LOCAL_LOG_DB.Callback().Query().Before("gorm:update").Register("tenant_plugin:before_update", before_update)

	}
}
func before_query(db *gorm.DB) {
	if global.GWAF_RELEASE == "false" {
		db.Debug()
	}
	db.Where("tenant_id = ? and user_code=? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
	zlog.Debug("before_query")
}
func before_update(db *gorm.DB) {
	if global.GWAF_RELEASE == "false" {
		db.Debug()
	}
}
