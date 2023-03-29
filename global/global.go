package global

import (
	"SamWaf/model"
	"SamWaf/model/spec"
	"github.com/bytedance/godlp/dlpheader"
	"gorm.io/gorm"
	"time"
)

const (
	Version_name = "v1.0.1"
	Version_num  = 1
)

var (
	GWAF_LOCAL_DB             *gorm.DB                      //通用本地数据库，尊重用户隐私
	GWAF_LOCAL_LOG_DB         *gorm.DB                      //通用本地数据库存日志数据，尊重用户隐私
	GWAF_REMOTE_DB            *gorm.DB                      //仅当用户使用云数据库
	GWAF_LOCAL_SERVER_PORT    int                 = 26666   // 本地local端口
	GWAF_USER_CODE            string                        // 当前识别号
	GWAF_CUSTOM_SERVER_NAME   string                        // 当前服务器自定义名称
	GWAF_TENANT_ID            string                        // 当前租户ID
	GWAF_RELEASE              string              = "false" // 当前是否为发行版
	GWAF_RELEASE_VERSION_NAME string              = "1.0"   // 发行版的版本号名称
	GWAF_RELEASE_VERSION      string              = "1"     // 发行版的版本号
	GWAF_LAST_UPDATE_TIME     time.Time                     // 上次时间
	GWAF_DLP                  dlpheader.EngineAPI           // 脱敏引擎
	/**链聚合**/
	GWAF_CHAN_HOST   = make(chan model.Hosts, 10) //主机链
	GWAF_CHAN_ENGINE = make(chan int, 10)         //引擎链

	GWAF_CHAN_MSG = make(chan spec.ChanCommonHost, 10) //全局通讯包

	GCACHE_WECHAT_ACCESS string = "" //微信访问密钥
	GCACHE_IP_CBUFF      []byte      // IP相关缓存

	GDATA_DELETE_INTERVAL = 100 // 删除100天前的数据
)
