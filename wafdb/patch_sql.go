package wafdb

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"gorm.io/gorm"
	"time"
)

/*
*
一些后续补丁
*/
func pathLogSql(db *gorm.DB) {

}
func pathCoreSql(db *gorm.DB) {
	startTime := time.Now()

	zlog.Info("ready create core default value maybe use a few minutes ")
	// 20241018 创建联合索引 weblog
	err := db.Exec("UPDATE system_configs SET item_class = 'system' WHERE item_class IS NULL or item_class='' ").Error
	if err != nil {
		panic("failed to system_config :item_class " + err.Error())
	} else {
		zlog.Info("db", "system_config :item_class init successfully")
	}
	// 20241026 是否自动跳转https站点
	err = db.Exec("UPDATE hosts SET auto_jump_http_s=0 WHERE auto_jump_http_s IS NULL ").Error
	if err != nil {
		panic("failed to hosts :auto_jump_https " + err.Error())
	} else {
		zlog.Info("db", "hosts :auto_jump_https init successfully")
	}
	//20241030 初始化一次状态信息
	err = db.Exec("UPDATE hosts SET start_status=0 WHERE start_status IS NULL ").Error
	if err != nil {
		panic("failed to hosts :start_status " + err.Error())
	} else {
		zlog.Info("db", "hosts :start_status init successfully")
	}
	//20241209 是否传递后端域名到后端服务器侧
	err = db.Exec("UPDATE hosts SET is_trans_back_domain=0 WHERE is_trans_back_domain IS NULL ").Error
	if err != nil {
		panic("failed to hosts :is_trans_back_domain " + err.Error())
	} else {
		zlog.Info("db", "hosts :is_trans_back_domain init successfully")
	}
	//20250103 初始化一次HTTP Auth Base 状态信息
	err = db.Exec("UPDATE hosts SET is_enable_http_auth_base=0 WHERE is_enable_http_auth_base IS NULL ").Error
	if err != nil {
		panic("failed to hosts :is_enable_http_auth_base " + err.Error())
	} else {
		zlog.Info("db", "hosts :is_enable_http_auth_base init successfully")
	}
	//20250106 初始化一次站点超时状态信息
	err = db.Exec("UPDATE hosts SET response_time_out=60 WHERE response_time_out IS NULL ").Error
	if err != nil {
		panic("failed to hosts :response_time_out " + err.Error())
	} else {
		zlog.Info("db", "hosts :response_time_out init successfully")
	}
	//20250219 初始化敏感词拦截方式和拦截动作
	err = db.Exec("UPDATE sensitives SET check_direction='in',action='deny' WHERE check_direction IS NULL ").Error
	if err != nil {
		panic("failed to sensitives :response_time_out " + err.Error())
	} else {
		zlog.Info("db", "sensitives :response_time_out init successfully")
	}

	//20250307 是否跳过后端https有效性验证
	err = db.Exec("UPDATE hosts SET insecure_skip_verify=0 WHERE insecure_skip_verify IS NULL ").Error
	if err != nil {
		panic("failed to hosts :insecure_skip_verify " + err.Error())
	} else {
		zlog.Info("db", "hosts :insecure_skip_verify init successfully")
	}
	//20250328 cc模式 默认还是现有的
	err = db.Exec("UPDATE anti_ccs SET limit_mode='window' WHERE limit_mode IS NULL ").Error
	if err != nil {
		panic("failed to anti_ccs :limit_mode " + err.Error())
	} else {
		zlog.Info("db", "anti_ccs :limit_mode init successfully")
	}

	//20250401 CC防护IP提取模式，默认为网卡模式
	err = db.Exec("UPDATE anti_ccs SET ip_mode='nic' WHERE ip_mode IS NULL ").Error
	if err != nil {
		panic("failed to anti_ccs :ip_mode " + err.Error())
	} else {
		zlog.Info("db", "anti_ccs :ip_mode init successfully")
	}
	//20250519 默认编码设置
	err = db.Exec("UPDATE hosts SET default_encoding='auto' WHERE default_encoding IS NULL").Error
	if err != nil {
		panic("failed to hosts: default_encoding " + err.Error())
	} else {
		zlog.Info("db", "hosts: default_encoding init successfully")
	}
	//20250527 初始化分组信息  model.PrivateGroup
	// 初始化四个云服务提供商的默认分组
	cloudProviders := []string{"alidns", "huaweicloud", "tencentcloud", "cloudflare"}
	for _, cloudProvider := range cloudProviders {
		// 检查该云服务提供商是否已有分组记录
		var count int64
		db.Model(&model.PrivateGroup{}).Where("private_group_belong_cloud = ?", cloudProvider).Count(&count)

		// 如果不存在记录，则插入默认分组
		if count == 0 {
			privateGroup := model.PrivateGroup{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   global.GWAF_USER_CODE,
					Tenant_ID:   global.GWAF_TENANT_ID,
					CREATE_TIME: customtype.JsonTime(time.Now()),
					UPDATE_TIME: customtype.JsonTime(time.Now()),
				},
				PrivateGroupName:        "default",
				PrivateGroupBelongCloud: cloudProvider,
			}

			err := db.Create(&privateGroup).Error
			if err != nil {
				zlog.Error("db", "init cloud group fail", "cloud", cloudProvider, "error", err.Error())
			} else {
				zlog.Info("db", "init cloud group success", "cloud", cloudProvider)
			}
		}
	}
	//如果申请记录里面没有分组信息，那么就默认放到default分组
	err = db.Exec("UPDATE ssl_orders SET private_group_name='default' WHERE private_group_name IS NULL").Error
	if err != nil {
		panic("failed to ssl_orders: private_group_name " + err.Error())
	} else {
		zlog.Info("db", "ssl_orders: private_group_name init successfully")
	}
	// 更新private_infos表中空分组信息
	err = db.Exec("UPDATE private_infos SET private_group_name='default' WHERE private_group_name IS NULL OR private_group_name=''").Error
	if err != nil {
		panic("failed to update private_infos: private_group_name " + err.Error())
	} else {
		zlog.Info("db", "private_infos: private_group_name updated successfully")
	}

	// 根据环境变量名称更新所属云信息
	envCloudMap := map[string]string{
		"ALICLOUD_ACCESS_KEY":           "alidns",
		"ALICLOUD_SECRET_KEY":           "alidns",
		"ALICLOUD_SECURITY_TOKEN":       "alidns",
		"HUAWEICLOUD_ACCESS_KEY_ID":     "huaweicloud",
		"HUAWEICLOUD_SECRET_ACCESS_KEY": "huaweicloud",
		"HUAWEICLOUD_REGION":            "huaweicloud",
		"TENCENTCLOUD_SECRET_ID":        "tencentcloud",
		"TENCENTCLOUD_SECRET_KEY":       "tencentcloud",
		"CF_DNS_API_TOKEN":              "cloudflare",
	}

	// 遍历环境变量映射，更新对应的所属云信息
	for envKey, cloudName := range envCloudMap {
		err = db.Exec("UPDATE private_infos SET private_group_belong_cloud=? WHERE private_key=? AND (private_group_belong_cloud IS NULL OR private_group_belong_cloud='')", cloudName, envKey).Error
		if err != nil {
			zlog.Error("db", "update dns key fail", "env", envKey, "cloud", cloudName, "error", err.Error())
		} else {
			zlog.Info("db", "update dns key successfully", "env", envKey, "cloud", cloudName)
		}
	}

	//20250603 批量任务执行策略
	err = db.Exec("UPDATE batch_tasks SET batch_trigger_type='cron' WHERE batch_trigger_type IS NULL").Error
	if err != nil {
		panic("failed to batch_tasks: batch_trigger_type " + err.Error())
	} else {
		zlog.Info("db", "batch_tasks: batch_trigger_type init successfully")
	}

	//20250603 批量任务额外配置初始化
	err = db.Exec("UPDATE batch_tasks SET batch_extra_config='{}' WHERE batch_extra_config IS NULL").Error
	if err != nil {
		panic("failed to batch_tasks: batch_extra_config " + err.Error())
	} else {
		zlog.Info("db", "batch_tasks: batch_extra_config init successfully")
	}

	// 记录结束时间并计算耗时
	duration := time.Since(startTime)
	zlog.Info("create core default value completely", "duration", duration.String())
}

// 处理统计部分代码
func pathStatsSql(db *gorm.DB) {

}
