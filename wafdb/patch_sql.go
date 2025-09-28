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
	// 初始化五个云服务提供商的默认分组
	cloudProviders := []string{"alidns", "huaweicloud", "tencentcloud", "cloudflare", "baiducloud"}
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
		"BAIDUCLOUD_ACCESS_KEY_ID":      "baiducloud",
		"BAIDUCLOUD_SECRET_ACCESS_KEY":  "baiducloud",
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

	//20250604 静态网站配置初始化
	defaultStaticSiteConfig := `{"is_enable_static_site":0,"static_site_path":"","static_site_prefix":"/","sensitive_paths":"/etc/passwd,/etc/shadow,/etc/group,/etc/gshadow,/etc/hosts,/etc/hostname,/etc/resolv.conf,/etc/ssh/,/var/log/,/.ssh/,/.bash_history,/.profile,/.bashrc,/etc/crontab,/var/spool/cron/,/etc/apache2/,/etc/nginx/,/etc/httpd/,/var/www/,/usr/share/,/var/tmp/,/var/run/,c:\\windows\\,c:\\program files\\,c:\\program files (x86)\\,c:\\users\\,c:\\documents and settings\\,c:\\windows\\system32\\,c:\\windows\\syswow64\\,c:\\boot.ini,c:\\autoexec.bat,c:\\config.sys,\\windows\\,\\program files\\,\\program files (x86)\\,\\users\\,\\documents and settings\\,\\windows\\system32\\,\\windows\\syswow64\\,boot.ini,autoexec.bat,config.sys,ntuser.dat,pagefile.sys,hiberfil.sys,swapfile.sys","sensitive_extensions":".key,.pem,.crt,.p12,.pfx,.jks,.bak,.backup,.old,.orig,.save,.sql,.db,.sqlite,.mdb,.env,.htaccess,.htpasswd,.git,.svn,.hg,.bzr,.DS_Store,Thumbs.db,desktop.ini,.tmp,.temp,.lock,.pid","allowed_extensions":".html,.htm,.css,.js,.json,.png,.jpg,.jpeg,.gif,.svg,.ico,.webp,.pdf,.txt,.md,.xml,.woff,.woff2,.ttf,.eot,.mp4,.webm,.ogg,.mp3,.wav,.zip,.tar,.gz,.rar","sensitive_patterns":"(?i)\\.git(/|\\\\),(?i)\\.svn(/|\\\\),(?i)\\.env,(?i)database\\.(php|xml|json|yaml|yml),(?i)(backup|dump|export)\\.(sql|db|tar|zip|gz),(?i)(id_rsa|id_dsa|id_ecdsa|id_ed25519),(?i)\\.ssh(/|\\\\).*,(?i)(access|error|debug)\\.log,(?i)web\\.config,(?i)phpinfo\\.php"}`

	// 处理static_site_json为null的情况
	err = db.Exec("UPDATE hosts SET static_site_json=? WHERE static_site_json IS NULL", defaultStaticSiteConfig).Error
	if err != nil {
		panic("failed to hosts :static_site_json " + err.Error())
	} else {
		zlog.Info("db", "hosts :static_site_json init successfully")
	}

	// 处理static_site_json不包含sensitive_paths字段的情况
	err = db.Exec("UPDATE hosts SET static_site_json=? WHERE static_site_json IS NOT NULL AND static_site_json NOT LIKE '%sensitive_paths%'", defaultStaticSiteConfig).Error
	if err != nil {
		panic("failed to hosts :static_site_json sensitive_paths update " + err.Error())
	} else {
		zlog.Info("db", "hosts :static_site_json sensitive_paths update successfully")
	}
	//20250827 初始化 letsencrypt CA 服务器记录
	var letsencryptCount int64
	db.Model(&model.CaServerInfo{}).Where("ca_server_name = ?", "letsencrypt").Count(&letsencryptCount)

	// 如果不存在 letsencrypt 记录，则创建
	if letsencryptCount == 0 {
		letsencryptCA := model.CaServerInfo{
			BaseOrm: baseorm.BaseOrm{
				Id:          uuid.GenUUID(),
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(time.Now()),
				UPDATE_TIME: customtype.JsonTime(time.Now()),
			},
			CaServerName:    "letsencrypt",
			CaServerAddress: "https://acme-v02.api.letsencrypt.org/directory",
			Remarks:         "Let's Encrypt",
		}

		err := db.Create(&letsencryptCA).Error
		if err != nil {
			zlog.Error("db", "init letsencrypt CA server fail", "error", err.Error())
		} else {
			zlog.Info("db", "init letsencrypt CA server success")
		}
	}
	// 2025-09-10 host的log_only_mode 初始化 默认是0 不启用
	err = db.Exec("UPDATE hosts SET log_only_mode=? WHERE log_only_mode IS NULL", 0).Error
	if err != nil {
		panic("failed to hosts :log_only_mode " + err.Error())
	} else {
		zlog.Info("db", "hosts :log_only_mode init successfully")
	}
	// 记录结束时间并计算耗时
	duration := time.Since(startTime)
	zlog.Info("create core default value completely", "duration", duration.String())
}

// 处理统计部分代码
func pathStatsSql(db *gorm.DB) {

}
