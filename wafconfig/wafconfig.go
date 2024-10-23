package wafconfig

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/utils"
	"github.com/denisbrodbeck/machineid"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"os"
)

// 加载配置并初始化
func LoadAndInitConfig() {
	zlog.Info("load config")
	/**
	1.如果user_code存在就使用本地的user_code
	2.
	*/
	// 判断备份目录是否存在，不存在则创建
	configDir := utils.GetCurrentDir() + "/conf/"
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, os.ModePerm); err != nil {
			zlog.Error("创建config目录失败:", err)
			return
		}
	}
	config := viper.New()
	config.AddConfigPath(configDir) // 文件所在目录
	config.SetConfigName("config")  // 文件名
	config.SetConfigType("yml")     // 文件类型

	if err := config.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			zlog.Error("找不到配置文件..")
			config.Set("local_port", global.GWAF_LOCAL_SERVER_PORT)
			err = config.SafeWriteConfig()
		} else {
			zlog.Error("配置文件出错..")
		}
	}
	if config.IsSet("user_code") == false {
		id, err := machineid.ID()
		if err != nil {
			newcode := "RAD" + uuid.NewV4().String()
			config.Set("user_code", newcode)
			global.GWAF_USER_CODE = newcode
		} else {
			config.Set("user_code", id)
			global.GWAF_USER_CODE = id
		}
	} else {
		global.GWAF_USER_CODE = config.GetString("user_code")
	}
	if config.IsSet("soft_id") == false {
		config.Set("soft_id", global.GWAF_TENANT_ID)
	} else {
		global.GWAF_TENANT_ID = config.GetString("soft_id")
	}
	if config.IsSet("local_port") {
		global.GWAF_LOCAL_SERVER_PORT = config.GetInt("local_port") //读取本地端口
	}
	if config.IsSet("custom_server_name") {
		global.GWAF_CUSTOM_SERVER_NAME = config.GetString("custom_server_name") //本地服务器其定义名称
	} else {
		hostname, err := os.Hostname()
		if err != nil {
			global.GWAF_CUSTOM_SERVER_NAME = "未定义服务器名称"
		} else {
			config.Set("custom_server_name", hostname)
			global.GWAF_CUSTOM_SERVER_NAME = hostname
		}

	}
	if config.IsSet("notice.isenable") {
		global.GWAF_NOTICE_ENABLE = config.GetBool("notice.isenable")
	} else {
		config.Set("notice.isenable", false)
	}

	err := config.WriteConfig()
	if err != nil {
		zlog.Error("write config failed: ", err)
	}
	zlog.Info("user_code:", global.GWAF_USER_CODE)
	zlog.Info("sof_id:", global.GWAF_TENANT_ID)
}
