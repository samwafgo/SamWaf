package waftask

import (
	"SamWaf/global"
	"SamWaf/utils/zlog"
	"SamWaf/wafenginecore"
	"github.com/spf13/viper"
	"testing"
)

func TestTaskDeleteHistoryInfo(t *testing.T) {
	currentPath := "../"
	config := viper.New()
	config.AddConfigPath(currentPath + "/conf/") // 文件所在目录
	config.SetConfigName("config")               // 文件名
	config.SetConfigType("yml")                  // 文件类型
	if err := config.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			zlog.Error("找不到配置文件..")
		} else {
			zlog.Error("配置文件出错..")
		}
	}

	global.GWAF_USER_CODE = config.GetString("user_code") // 读取配置
	global.GWAF_TENANT_ID = global.GWAF_USER_CODE
	global.GWAF_LOCAL_SERVER_PORT = config.GetInt("local_port")             //读取本地端口
	global.GWAF_CUSTOM_SERVER_NAME = config.GetString("custom_server_name") //本地服务器其定义名称
	zlog.Debug(" load ini: ", global.GWAF_USER_CODE)
	wafenginecore.InitDb(currentPath)
	TaskDeleteHistoryInfo()
}
