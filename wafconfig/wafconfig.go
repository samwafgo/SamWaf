package wafconfig

import (
	"SamWaf/global"
	"SamWaf/utils"
	"fmt"
	"github.com/denisbrodbeck/machineid"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"os"
	"time"
)

// 加载配置并初始化
func LoadAndInitConfig() {
	// 格式化当前时间为指定格式
	currentTime := time.Now().Format("2006-01-02 15:04:05.000")
	fmt.Printf("%s\tINFO\tload config\n", currentTime)
	/**
	1.如果user_code存在就使用本地的user_code
	2.
	*/
	// 判断备份目录是否存在，不存在则创建
	configDir := utils.GetCurrentDir() + "/conf/"
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		if err := os.MkdirAll(configDir, os.ModePerm); err != nil {
			fmt.Printf("%s\tERROR\t创建config目录失败:%v\n", currentTime, err)
			return
		}
	}
	config := viper.New()
	config.AddConfigPath(configDir) // 文件所在目录
	config.SetConfigName("config")  // 文件名
	config.SetConfigType("yml")     // 文件类型

	if err := config.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			fmt.Printf("%s\tWARN\t找不到配置文件..\n", currentTime)
			config.Set("local_port", global.GWAF_LOCAL_SERVER_PORT)
			err = config.SafeWriteConfig()
		} else {
			fmt.Printf("%s\tERROR\t配置文件出错..\n", currentTime)
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

	if config.IsSet("export_download") == false {
		config.Set("export_download", global.GWAF_CAN_EXPORT_DOWNLOAD_LOG)
	} else {
		global.GWAF_CAN_EXPORT_DOWNLOAD_LOG = config.GetBool("export_download")
	}

	if config.IsSet("zlog.outputformat") {
		global.GWAF_LOG_OUTPUT_FORMAT = config.GetString("zlog.outputformat")
	} else {
		config.Set("zlog.outputformat", global.GWAF_LOG_OUTPUT_FORMAT)
	}

	err := config.WriteConfig()
	if err != nil {
		fmt.Printf("%s\tERROR\twrite config failed:%v\n", currentTime, err)
		return
	}

	fmt.Printf("%s\tINFO\tuser_code:%s ,soft_id:%s\n",
		currentTime, global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
}
