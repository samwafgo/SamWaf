package enums

const (
	TASK_RUNTIME_QPS_CLEAN            = "task_runtime_qps_clean"            //清空运行QPS
	TASK_HOST_QPS_CLEAN               = "task_host_qps_clean"               //清空主机QPS
	TASK_SHARE_DB                     = "task_share_db"                     //分库检测
	TASK_COUNTER                      = "task_counter"                      //统计
	TASK_DELAY_INFO                   = "task_delay_info"                   //延迟统计信息
	TASK_LOAD_CONFIG                  = "task_load_config"                  //获取配置信息
	TASK_REFLUSH_WECHAT_ACCESS_TOKEN  = "task_reflush_wechat_access_token"  //刷新微信端accesstoken
	TASK_DELETE_HISTORY_INFO          = "task_delete_history_info"          //删除历史信息
	TASK_DELETE_HISTORY_DOWNLOAD_FILE = "task_delete_history_download_file" //删除历史文件信息
	TASK_SSL_ORDER_RENEW              = "task_ssl_order_renew"              //SSL 证书自动续期
	TASK_SSL_PATH_LOAD                = "task_ssl_path_load"                //SSL证书可自动加载路径下的证书
	TASK_BATCH                        = "task_batch"                        //批量任务
	TASK_SSL_EXPIRE_CHECK             = "task_ssl_expire_check"             //SSL证书到期检测
	TASK_NOTICE                       = "task_notice"                       //通知信息
)
