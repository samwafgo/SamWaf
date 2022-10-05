package global

import "gorm.io/gorm"

const (
	Version_name = "v1.0.1"
	Version_num  = 1
)

var (
	GWAF_LOCAL_DB          *gorm.DB     //通用本地数据库，尊重用户隐私
	GWAF_REMOTE_DB         *gorm.DB     //仅当用户使用云数据库
	GWAF_LOCAL_SERVER_PORT int      = 0 // 本地local端口
)
