package wafdb

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"fmt"
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// RunCoreDBMigrations 执行主数据库迁移（完全兼容老用户）
func RunCoreDBMigrations(db *gorm.DB) error {
	zlog.Info("开始执行core数据库迁移检查...")

	// 检测表和索引的存在情况
	tablesExist := checkCoreTablesExist(db)
	indexesExist := checkCoreIndexesExist(db)

	zlog.Info("数据库状态检测",
		"表是否存在", tablesExist,
		"索引是否完整", indexesExist)

	m := gormigrate.New(db, gormigrate.DefaultOptions, []*gormigrate.Migration{
		// 迁移1: 创建表（如果不存在）
		{
			ID: "202511140001_initial_core_tables",
			Migrate: func(tx *gorm.DB) error {
				if tablesExist {
					zlog.Info("迁移 202511140001: 表已存在，执行结构同步")
					// 表已存在，只做结构同步（安全操作，不会删除字段/数据）
					if err := tx.AutoMigrate(
						&model.Hosts{},
						&model.Rules{},
						&model.LDPUrl{},
						&model.IPAllowList{},
						&model.URLAllowList{},
						&model.IPBlockList{},
						&model.URLBlockList{},
						&model.AntiCC{},
						&model.TokenInfo{},
						&model.Account{},
						&model.SystemConfig{},
						&model.DelayMsg{},
						&model.ShareDb{},
						&model.Center{},
						&model.Sensitive{},
						&model.LoadBalance{},
						&model.SslConfig{},
						&model.IPTag{},
						&model.BatchTask{},
						&model.SslOrder{},
						&model.SslExpire{},
						&model.HttpAuthBase{},
						&model.Task{},
						&model.BlockingPage{},
						&model.Otp{},
						&model.PrivateInfo{},
						&model.PrivateGroup{},
						&model.CacheRule{},
						&model.Tunnel{},
						&model.CaServerInfo{},
					); err != nil {
						return fmt.Errorf("同步表结构失败: %w", err)
					}
					zlog.Info("表结构同步成功（数据完整保留）")
				} else {
					zlog.Info("迁移 202511140001: 创建新表")
					// 表不存在，创建所有表
					if err := tx.AutoMigrate(
						&model.Hosts{},
						&model.Rules{},
						&model.LDPUrl{},
						&model.IPAllowList{},
						&model.URLAllowList{},
						&model.IPBlockList{},
						&model.URLBlockList{},
						&model.AntiCC{},
						&model.TokenInfo{},
						&model.Account{},
						&model.SystemConfig{},
						&model.DelayMsg{},
						&model.ShareDb{},
						&model.Center{},
						&model.Sensitive{},
						&model.LoadBalance{},
						&model.SslConfig{},
						&model.IPTag{},
						&model.BatchTask{},
						&model.SslOrder{},
						&model.SslExpire{},
						&model.HttpAuthBase{},
						&model.Task{},
						&model.BlockingPage{},
						&model.Otp{},
						&model.PrivateInfo{},
						&model.PrivateGroup{},
						&model.CacheRule{},
						&model.Tunnel{},
						&model.CaServerInfo{},
					); err != nil {
						return fmt.Errorf("创建core表失败: %w", err)
					}
					zlog.Info("core表创建成功")
				}
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				if tablesExist {
					// 如果是老数据库，不执行删除操作（保护数据）
					zlog.Info("回滚 202511140001: 检测到已存在数据，跳过表删除（保护用户数据）")
					return nil
				}
				// 新数据库可以安全删除
				zlog.Info("回滚 202511140001: 删除表")
				return tx.Migrator().DropTable(
					&model.Hosts{},
					&model.Rules{},
					&model.LDPUrl{},
					&model.IPAllowList{},
					&model.URLAllowList{},
					&model.IPBlockList{},
					&model.URLBlockList{},
					&model.AntiCC{},
					&model.TokenInfo{},
					&model.Account{},
					&model.SystemConfig{},
					&model.DelayMsg{},
					&model.ShareDb{},
					&model.Center{},
					&model.Sensitive{},
					&model.LoadBalance{},
					&model.SslConfig{},
					&model.IPTag{},
					&model.BatchTask{},
					&model.SslOrder{},
					&model.SslExpire{},
					&model.HttpAuthBase{},
					&model.Task{},
					&model.BlockingPage{},
					&model.Otp{},
					&model.PrivateInfo{},
					&model.PrivateGroup{},
					&model.CacheRule{},
					&model.Tunnel{},
					&model.CaServerInfo{},
				)
			},
		},
		// 迁移2: 创建索引（幂等操作）
		{
			ID: "202511140002_create_core_indexes",
			Migrate: func(tx *gorm.DB) error {
				if indexesExist {
					zlog.Info("迁移 202511140002: 索引已完整，跳过创建")
					return nil
				}
				zlog.Info("迁移 202511140002: 开始创建索引")
				return createCoreIndexes(tx)
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202511140002: 删除索引")
				return dropCoreIndexes(tx)
			},
		},
		// 迁移3: 创建通知管理相关表
		{
			ID: "202511240001_add_notify_tables",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202511240001: 创建通知管理表")
				// 创建通知渠道和订阅表
				if err := tx.AutoMigrate(
					&model.NotifyChannel{},
					&model.NotifySubscription{},
				); err != nil {
					return fmt.Errorf("创建通知管理表失败: %w", err)
				}
				zlog.Info("通知管理表创建成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202511240001: 删除通知管理表")
				return tx.Migrator().DropTable(
					&model.NotifyChannel{},
					&model.NotifySubscription{},
				)
			},
		},
		// 迁移4: 创建防火墙IP封禁表
		{
			ID: "202511280001_add_firewall_ip_block_table",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202511280001: 创建防火墙IP封禁表")
				// 创建防火墙IP封禁表
				if err := tx.AutoMigrate(
					&model.FirewallIPBlock{},
				); err != nil {
					return fmt.Errorf("创建防火墙IP封禁表失败: %w", err)
				}

				// 创建索引
				if err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_firewall_ip_block_ip ON firewall_ip_block(ip)").Error; err != nil {
					zlog.Warn("创建索引 idx_firewall_ip_block_ip 失败", "error", err.Error())
				}
				if err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_firewall_ip_block_status ON firewall_ip_block(status)").Error; err != nil {
					zlog.Warn("创建索引 idx_firewall_ip_block_status 失败", "error", err.Error())
				}
				if err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_firewall_ip_block_expire_time ON firewall_ip_block(expire_time)").Error; err != nil {
					zlog.Warn("创建索引 idx_firewall_ip_block_expire_time 失败", "error", err.Error())
				}

				zlog.Info("防火墙IP封禁表创建成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202511280001: 删除防火墙IP封禁表")
				return tx.Migrator().DropTable(&model.FirewallIPBlock{})
			},
		},
		// 迁移5: 为 tunnel 表添加 allowed_time_ranges 字段
		{
			ID: "202512100001_add_tunnel_allowed_time_ranges",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202512100001: 为 tunnel 表添加 allowed_time_ranges 字段")

				// 检查字段是否已存在
				if tx.Migrator().HasColumn(&model.Tunnel{}, "allowed_time_ranges") {
					zlog.Info("allowed_time_ranges 字段已存在，跳过添加")
					return nil
				}

				// 添加字段，默认值为空字符串（表示不限制）
				if err := tx.Migrator().AddColumn(&model.Tunnel{}, "allowed_time_ranges"); err != nil {
					return fmt.Errorf("添加 allowed_time_ranges 字段失败: %w", err)
				}

				zlog.Info("allowed_time_ranges 字段添加成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202512100001: 删除 tunnel 表的 allowed_time_ranges 字段")
				if tx.Migrator().HasColumn(&model.Tunnel{}, "allowed_time_ranges") {
					return tx.Migrator().DropColumn(&model.Tunnel{}, "allowed_time_ranges")
				}
				return nil
			},
		},
		// 迁移6: 为 hosts 表添加 http_auth_base_type 字段
		{
			ID: "202512250001_add_hosts_http_auth_base_type",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202512250001: 为 hosts 表添加 http_auth_base_type 字段")

				// 检查字段是否已存在
				if tx.Migrator().HasColumn(&model.Hosts{}, "http_auth_base_type") {
					zlog.Info("http_auth_base_type 字段已存在，跳过添加")
					return nil
				}

				// 添加字段，默认值为 authorization（Basic Auth方式）
				if err := tx.Migrator().AddColumn(&model.Hosts{}, "http_auth_base_type"); err != nil {
					return fmt.Errorf("添加 http_auth_base_type 字段失败: %w", err)
				}

				// 将所有已存在的记录设置默认值为 authorization
				if err := tx.Exec("UPDATE hosts SET http_auth_base_type = 'authorization' WHERE http_auth_base_type IS NULL OR http_auth_base_type = ''").Error; err != nil {
					zlog.Warn("设置 http_auth_base_type 默认值失败", "error", err.Error())
				}

				zlog.Info("http_auth_base_type 字段添加成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202512250001: 删除 hosts 表的 http_auth_base_type 字段")
				if tx.Migrator().HasColumn(&model.Hosts{}, "http_auth_base_type") {
					return tx.Migrator().DropColumn(&model.Hosts{}, "http_auth_base_type")
				}
				return nil
			},
		},
		// 迁移7: 为 hosts 表添加 http_auth_path_prefix 字段（防路径泄漏功能）
		{
			ID: "202601050001_add_hosts_http_auth_path_prefix",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202601050001: 为 hosts 表添加 http_auth_path_prefix 字段")

				// 检查字段是否已存在
				if tx.Migrator().HasColumn(&model.Hosts{}, "http_auth_path_prefix") {
					zlog.Info("http_auth_path_prefix 字段已存在，跳过添加")
					return nil
				}

				// 添加字段，默认值为空字符串（空值时使用默认路径 /samwaf_httpauth）
				if err := tx.Migrator().AddColumn(&model.Hosts{}, "http_auth_path_prefix"); err != nil {
					return fmt.Errorf("添加 http_auth_path_prefix 字段失败: %w", err)
				}

				zlog.Info("http_auth_path_prefix 字段添加成功（空值将使用默认路径保持兼容）")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202601050001: 删除 hosts 表的 http_auth_path_prefix 字段")
				if tx.Migrator().HasColumn(&model.Hosts{}, "http_auth_path_prefix") {
					return tx.Migrator().DropColumn(&model.Hosts{}, "http_auth_path_prefix")
				}
				return nil
			},
		},
		// 迁移8: 为 hosts 表添加 custom_headers_json 字段（自定义头信息功能）
		{
			ID: "202601060001_add_hosts_custom_headers_json",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202601060001: 为 hosts 表添加 custom_headers_json 字段")

				// 检查字段是否已存在
				if tx.Migrator().HasColumn(&model.Hosts{}, "custom_headers_json") {
					zlog.Info("custom_headers_json 字段已存在，跳过添加")
					return nil
				}

				// 添加字段
				if err := tx.Migrator().AddColumn(&model.Hosts{}, "custom_headers_json"); err != nil {
					return fmt.Errorf("添加 custom_headers_json 字段失败: %w", err)
				}

				// 设置默认值
				defaultCustomHeadersConfig := `{"is_enable_custom_headers":0,"headers":[]}`
				if err := tx.Exec("UPDATE hosts SET custom_headers_json = ? WHERE custom_headers_json IS NULL OR custom_headers_json = ''", defaultCustomHeadersConfig).Error; err != nil {
					zlog.Warn("设置 custom_headers_json 默认值失败", "error", err.Error())
				}

				zlog.Info("custom_headers_json 字段添加成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202601060001: 删除 hosts 表的 custom_headers_json 字段")
				if tx.Migrator().HasColumn(&model.Hosts{}, "custom_headers_json") {
					return tx.Migrator().DropColumn(&model.Hosts{}, "custom_headers_json")
				}
				return nil
			},
		},
		// 迁移9: 为 blocking_page 表添加 attack_type 字段（攻击类型）
		{
			ID: "202601090001_add_blocking_page_attack_type",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202601090001: 为 blocking_page 表添加 attack_type 字段")

				// 检查字段是否已存在
				if tx.Migrator().HasColumn(&model.BlockingPage{}, "attack_type") {
					zlog.Info("attack_type 字段已存在，跳过添加")
					return nil
				}

				// 添加字段，默认值为空字符串（表示通用拦截页面）
				if err := tx.Migrator().AddColumn(&model.BlockingPage{}, "attack_type"); err != nil {
					return fmt.Errorf("添加 attack_type 字段失败: %w", err)
				}

				zlog.Info("attack_type 字段添加成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202601090001: 删除 blocking_page 表的 attack_type 字段")
				if tx.Migrator().HasColumn(&model.BlockingPage{}, "attack_type") {
					return tx.Migrator().DropColumn(&model.BlockingPage{}, "attack_type")
				}
				return nil
			},
		},
		// 迁移10: 为 otp 表添加 issuer 字段（发行者标识）
		{
			ID: "202601090002_add_otp_issuer",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202601090002: 为 otp 表添加 issuer 字段")

				// 检查字段是否已存在
				if tx.Migrator().HasColumn(&model.Otp{}, "issuer") {
					zlog.Info("issuer 字段已存在，跳过添加")
					return nil
				}

				// 添加字段
				if err := tx.Migrator().AddColumn(&model.Otp{}, "issuer"); err != nil {
					return fmt.Errorf("添加 issuer 字段失败: %w", err)
				}

				// 为已存在的记录设置默认值为 "SamWaf-{服务器名称}"
				defaultIssuer := "SamWaf-" + global.GWAF_CUSTOM_SERVER_NAME
				if err := tx.Exec("UPDATE otp SET issuer = ? WHERE issuer IS NULL OR issuer = ''", defaultIssuer).Error; err != nil {
					zlog.Warn("设置 issuer 默认值失败", "error", err.Error())
				}

				zlog.Info("issuer 字段添加成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202601090002: 删除 otp 表的 issuer 字段")
				if tx.Migrator().HasColumn(&model.Otp{}, "issuer") {
					return tx.Migrator().DropColumn(&model.Otp{}, "issuer")
				}
				return nil
			},
		},
		// 迁移11: 初始化 ZeroSSL CA 服务器记录
		{
			ID: "202601100001_init_zerossl_ca_server",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202601100001: 初始化 ZeroSSL CA 服务器记录")

				// 检查是否已存在 ZeroSSL 记录（通过名称或地址检查）
				var zerosslCount int64
				tx.Model(&model.CaServerInfo{}).Where("ca_server_name = ? OR ca_server_address = ?", "ZeroSSL", "https://acme.zerossl.com/v2/DV90").Count(&zerosslCount)

				// 如果已存在，跳过创建
				if zerosslCount > 0 {
					zlog.Info("ZeroSSL CA 服务器记录已存在，跳过创建")
					return nil
				}

				// 创建 ZeroSSL CA 服务器记录
				zerosslCA := model.CaServerInfo{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.GenUUID(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: customtype.JsonTime(time.Now()),
						UPDATE_TIME: customtype.JsonTime(time.Now()),
					},
					CaServerName:    "zerossl",
					CaServerAddress: "https://acme.zerossl.com/v2/DV90",
					Remarks:         "ZeroSSL",
				}

				if err := tx.Create(&zerosslCA).Error; err != nil {
					return fmt.Errorf("创建 ZeroSSL CA 服务器记录失败: %w", err)
				}

				zlog.Info("ZeroSSL CA 服务器记录创建成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202601100001: 删除 ZeroSSL CA 服务器记录")
				// 只删除我们创建的记录（通过名称和地址匹配）
				return tx.Where("ca_server_name = ? AND ca_server_address = ?", "ZeroSSL", "https://acme.zerossl.com/v2/DV90").Delete(&model.CaServerInfo{}).Error
			},
		},
		// 迁移12: 为 tunnel 表添加 ip_version 字段（IP版本支持）
		{
			ID: "202601110001_add_tunnel_ip_version",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202601110001: 为 tunnel 表添加 ip_version 字段")

				// 检查字段是否已存在
				if tx.Migrator().HasColumn(&model.Tunnel{}, "ip_version") {
					zlog.Info("ip_version 字段已存在，跳过添加")
					return nil
				}

				// 添加字段
				if err := tx.Migrator().AddColumn(&model.Tunnel{}, "ip_version"); err != nil {
					return fmt.Errorf("添加 ip_version 字段失败: %w", err)
				}

				// 为已存在的记录设置默认值为 "both"（同时支持IPv4和IPv6）
				if err := tx.Exec("UPDATE tunnels SET ip_version = 'both' WHERE ip_version IS NULL OR ip_version = ''").Error; err != nil {
					zlog.Warn("设置 ip_version 默认值失败", "error", err.Error())
				}

				zlog.Info("ip_version 字段添加成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202601110001: 删除 tunnel 表的 ip_version 字段")
				if tx.Migrator().HasColumn(&model.Tunnel{}, "ip_version") {
					return tx.Migrator().DropColumn(&model.Tunnel{}, "ip_version")
				}
				return nil
			},
		},
		// 迁移13: 为 notify_subscription 表添加 recipients 字段（订阅级收件人）
		{
			ID: "202601300001_add_notify_subscription_recipients",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202601300001: 为 notify_subscription 表添加 recipients 字段")

				// 检查字段是否已存在
				if tx.Migrator().HasColumn(&model.NotifySubscription{}, "recipients") {
					zlog.Info("recipients 字段已存在，跳过添加")
					return nil
				}

				// 添加字段，默认值为空字符串（表示使用渠道默认收件人）
				if err := tx.Migrator().AddColumn(&model.NotifySubscription{}, "recipients"); err != nil {
					return fmt.Errorf("添加 recipients 字段失败: %w", err)
				}

				zlog.Info("recipients 字段添加成功（空值时将使用渠道配置的默认收件人，保持向后兼容）")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202601300001: 删除 notify_subscription 表的 recipients 字段")
				if tx.Migrator().HasColumn(&model.NotifySubscription{}, "recipients") {
					return tx.Migrator().DropColumn(&model.NotifySubscription{}, "recipients")
				}
				return nil
			},
		},
		// 迁移14: 为 hosts 表添加 ip_mode 字段（IP提取模式统一管理）
		{
			ID: "202602090001_add_hosts_ip_mode",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202602090001: 为 hosts 表添加 ip_mode 字段")

				// 检查字段是否已存在
				if tx.Migrator().HasColumn(&model.Hosts{}, "ip_mode") {
					zlog.Info("ip_mode 字段已存在，跳过添加")
					return nil
				}

				// 添加字段
				if err := tx.Migrator().AddColumn(&model.Hosts{}, "ip_mode"); err != nil {
					return fmt.Errorf("添加 ip_mode 字段失败: %w", err)
				}

				zlog.Info("ip_mode 字段添加成功，开始迁移老数据...")

				// 迁移老数据：从 anti_ccs 和 captcha_json 中读取 ip_mode
				var hosts []model.Hosts
				if err := tx.Find(&hosts).Error; err != nil {
					zlog.Warn("查询 hosts 记录失败", "error", err.Error())
					return nil // 非致命错误，继续执行
				}

				for _, host := range hosts {
					ipMode := "nic" // 默认值

					// 1. 优先从 anti_ccs 表读取
					var antiCC model.AntiCC
					if err := tx.Where("host_code = ?", host.Code).First(&antiCC).Error; err == nil {
						if antiCC.IPMode == "proxy" {
							ipMode = "proxy"
						}
					}

					// 2. 如果还是 nic，尝试从 captcha_json 读取
					if ipMode == "nic" && host.CaptchaJSON != "" {
						captchaConfig := model.ParseCaptchaConfig(host.CaptchaJSON)
						if captchaConfig.IPMode == "proxy" {
							ipMode = "proxy"
						}
					}

					// 3. 更新 host 的 ip_mode
					if err := tx.Model(&model.Hosts{}).Where("code = ?", host.Code).Update("ip_mode", ipMode).Error; err != nil {
						zlog.Warn("更新 host ip_mode 失败", "host_code", host.Code, "error", err.Error())
					}
				}

				zlog.Info("老数据迁移完成，所有 hosts 记录已设置 ip_mode")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202602090001: 删除 hosts 表的 ip_mode 字段")
				if tx.Migrator().HasColumn(&model.Hosts{}, "ip_mode") {
					return tx.Migrator().DropColumn(&model.Hosts{}, "ip_mode")
				}
				return nil
			},
		},
		// 迁移15: 为 hosts 表添加 custom_response_headers_json 字段（自定义响应头信息功能）
		{
			ID: "202602110001_add_hosts_custom_response_headers_json",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202602110001: 为 hosts 表添加 custom_response_headers_json 字段")

				// 检查字段是否已存在
				if tx.Migrator().HasColumn(&model.Hosts{}, "custom_response_headers_json") {
					zlog.Info("custom_response_headers_json 字段已存在，跳过添加")
					return nil
				}

				// 添加字段
				if err := tx.Migrator().AddColumn(&model.Hosts{}, "custom_response_headers_json"); err != nil {
					return fmt.Errorf("添加 custom_response_headers_json 字段失败: %w", err)
				}

				// 设置默认值
				defaultCustomResponseHeadersConfig := `{"is_enable_custom_headers":0,"headers":[]}`
				if err := tx.Exec("UPDATE hosts SET custom_response_headers_json = ? WHERE custom_response_headers_json IS NULL OR custom_response_headers_json = ''", defaultCustomResponseHeadersConfig).Error; err != nil {
					zlog.Warn("设置 custom_response_headers_json 默认值失败", "error", err.Error())
				}

				zlog.Info("custom_response_headers_json 字段添加成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202602110001: 删除 hosts 表的 custom_response_headers_json 字段")
				if tx.Migrator().HasColumn(&model.Hosts{}, "custom_response_headers_json") {
					return tx.Migrator().DropColumn(&model.Hosts{}, "custom_response_headers_json")
				}
				return nil
			},
		},
		// 迁移16: 创建开放平台 API Key 表（不含 api_secret）
		{
			ID: "202603060001_add_oplatform_key_table",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202603060001: 创建开放平台 API Key 表")

				if tx.Migrator().HasTable(&model.OPlatformKey{}) {
					zlog.Info("o_platform_keys 表已存在，执行结构同步")
					if err := tx.AutoMigrate(&model.OPlatformKey{}); err != nil {
						return fmt.Errorf("同步 o_platform_keys 表结构失败: %w", err)
					}
					return nil
				}

				if err := tx.AutoMigrate(&model.OPlatformKey{}); err != nil {
					return fmt.Errorf("创建 o_platform_keys 表失败: %w", err)
				}

				zlog.Info("o_platform_keys 表创建成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202603060001: 删除开放平台 API Key 表")
				return tx.Migrator().DropTable(&model.OPlatformKey{})
			},
		},
		// 迁移17: 移除开放平台 API Key 表中冗余的 api_secret 列
		{
			ID: "202603060002_drop_api_secret_from_oplatform_key",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202603060002: 移除 o_platform_keys.api_secret 列")
				if tx.Migrator().HasColumn(&model.OPlatformKey{}, "api_secret") {
					if err := tx.Migrator().DropColumn(&model.OPlatformKey{}, "api_secret"); err != nil {
						return fmt.Errorf("删除 api_secret 列失败: %w", err)
					}
					zlog.Info("api_secret 列已删除")
				} else {
					zlog.Info("api_secret 列不存在，跳过")
				}
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				return nil
			},
		},
		// 迁移18: 为 tunnel 表添加 SSL 相关字段
		{
			ID: "202603170001_add_tunnel_ssl_fields",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202603170001: 为 tunnel 表添加 SSL 相关字段")

				sslFields := []string{"ssl_status", "ssl_certificate", "ssl_certificate_key", "ssl_protocols"}
				for _, field := range sslFields {
					if tx.Migrator().HasColumn(&model.Tunnel{}, field) {
						zlog.Info(field + " 字段已存在，跳过添加")
						continue
					}
					if err := tx.Migrator().AddColumn(&model.Tunnel{}, field); err != nil {
						return fmt.Errorf("添加 %s 字段失败: %w", field, err)
					}
					zlog.Info(field + " 字段添加成功")
				}

				// ssl_status 默认值为 0（关闭）
				if err := tx.Exec("UPDATE tunnels SET ssl_status = 0 WHERE ssl_status IS NULL").Error; err != nil {
					zlog.Warn("设置 ssl_status 默认值失败", "error", err.Error())
				}

				zlog.Info("tunnel 表 SSL 相关字段添加成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202603170001: 删除 tunnel 表的 SSL 相关字段")
				sslFields := []string{"ssl_status", "ssl_certificate", "ssl_certificate_key", "ssl_protocols"}
				for _, field := range sslFields {
					if tx.Migrator().HasColumn(&model.Tunnel{}, field) {
						if err := tx.Migrator().DropColumn(&model.Tunnel{}, field); err != nil {
							zlog.Warn("删除字段失败", "field", field, "error", err.Error())
						}
					}
				}
				return nil
			},
		},
		// 迁移19: 为 hosts 表添加 response_compress_json（站点级响应压缩）
		{
			ID: "202603200001_add_hosts_response_compress_json",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202603200001: 为 hosts 表添加 response_compress_json 字段")
				if tx.Migrator().HasColumn(&model.Hosts{}, "response_compress_json") {
					zlog.Info("response_compress_json 字段已存在，跳过添加")
					return nil
				}
				if err := tx.Migrator().AddColumn(&model.Hosts{}, "response_compress_json"); err != nil {
					return fmt.Errorf("添加 response_compress_json 字段失败: %w", err)
				}
				defaultJSON := `{"is_enable":0,"prefer":"br_first","min_length":256,"include_types":"","include_extensions":"","exclude_extensions":"","exclude_paths":"","compress_when_static_assist":0}`
				if err := tx.Exec("UPDATE hosts SET response_compress_json = ? WHERE response_compress_json IS NULL OR response_compress_json = ''", defaultJSON).Error; err != nil {
					zlog.Warn("设置 response_compress_json 默认值失败", "error", err.Error())
				}
				zlog.Info("response_compress_json 字段添加成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202603200001: 删除 hosts 表的 response_compress_json 字段")
				if tx.Migrator().HasColumn(&model.Hosts{}, "response_compress_json") {
					return tx.Migrator().DropColumn(&model.Hosts{}, "response_compress_json")
				}
				return nil
			},
		},
		// 迁移20: 为 ssl_orders 表添加 skip_dns_verify 字段（DNS校验跳过开关）
		{
			ID: "202603250001_add_ssl_orders_skip_dns_verify",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202603250001: 为 ssl_orders 表添加 skip_dns_verify 字段")

				// 检查字段是否已存在
				if tx.Migrator().HasColumn(&model.SslOrder{}, "skip_dns_verify") {
					zlog.Info("skip_dns_verify 字段已存在，执行默认值回填")
					if err := tx.Exec("UPDATE ssl_orders SET skip_dns_verify = 0 WHERE skip_dns_verify IS NULL").Error; err != nil {
						zlog.Warn("回填 skip_dns_verify 默认值失败", "error", err.Error())
					}
					return nil
				}

				// 添加字段
				if err := tx.Migrator().AddColumn(&model.SslOrder{}, "skip_dns_verify"); err != nil {
					return fmt.Errorf("添加 skip_dns_verify 字段失败: %w", err)
				}

				// 为历史数据回填默认值 0（不跳过DNS校验）
				if err := tx.Exec("UPDATE ssl_orders SET skip_dns_verify = 0 WHERE skip_dns_verify IS NULL").Error; err != nil {
					zlog.Warn("设置 skip_dns_verify 默认值失败", "error", err.Error())
				}

				zlog.Info("skip_dns_verify 字段添加成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202603250001: 删除 ssl_orders 表的 skip_dns_verify 字段")
				if tx.Migrator().HasColumn(&model.SslOrder{}, "skip_dns_verify") {
					return tx.Migrator().DropColumn(&model.SslOrder{}, "skip_dns_verify")
				}
				return nil
			},
		},
		// 迁移: 创建数据保留策略表并初始化默认策略
		{
			ID: "202604100002_add_data_retention_policies",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202604100002: 创建 data_retention_policies 表")
				if err := tx.AutoMigrate(&model.DataRetentionPolicy{}); err != nil {
					return fmt.Errorf("创建 data_retention_policies 表失败: %w", err)
				}

				// 初始化默认策略（幂等：按 table_name 检查）
				defaultPolicies := []model.DataRetentionPolicy{
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TableName:     "stats_ip_days",
						DbType:        "stats",
						RetainDays:    90,
						RetainRows:    100000,
						DayField:      "day",
						DayFieldType:  "int_day",
						RowOrderField: "day",
						RowOrderDir:   "DESC",
						CleanEnabled:  0,
						Remarks:       "IP日统计-按day字段判断天数,保留day值最大(最新)的行",
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TableName:     "stats_ip_city_days",
						DbType:        "stats",
						RetainDays:    90,
						RetainRows:    100000,
						DayField:      "day",
						DayFieldType:  "int_day",
						RowOrderField: "day",
						RowOrderDir:   "DESC",
						CleanEnabled:  0,
						Remarks:       "IP城市日统计-按day字段判断天数,保留day值最大(最新)的行",
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TableName:     "ip_tags",
						DbType:        "stats",
						RetainDays:    90,
						RetainRows:    50000,
						DayField:      "create_time",
						DayFieldType:  "datetime",
						RowOrderField: "update_time",
						RowOrderDir:   "DESC",
						CleanEnabled:  0,
						Remarks:       "IP标签-按create_time判断天数,按update_time排序保留最近活跃的行",
					},
				}

				for _, policy := range defaultPolicies {
					var count int64
					tx.Model(&model.DataRetentionPolicy{}).Where("table_name = ?", policy.TableName).Count(&count)
					if count == 0 {
						if err := tx.Create(&policy).Error; err != nil {
							return fmt.Errorf("初始化策略 %s 失败: %w", policy.TableName, err)
						}
						zlog.Info("默认保留策略已创建", "table", policy.TableName)
					} else {
						zlog.Debug("默认保留策略已存在，跳过", "table", policy.TableName)
					}
				}

				zlog.Info("迁移 202604100002: data_retention_policies 初始化完成")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202604100002: 删除 data_retention_policies 表")
				return tx.Migrator().DropTable(&model.DataRetentionPolicy{})
			},
		},
		// 迁移21: 为 anti_ccs 表添加 skip_global_cc 字段（局部CC命中后跳过全局CC检测）
		{
			ID: "202604170001_add_anticc_skip_global_cc",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202604170001: 为 anti_ccs 表添加 skip_global_cc 字段")

				if tx.Migrator().HasColumn(&model.AntiCC{}, "skip_global_cc") {
					zlog.Info("skip_global_cc 字段已存在，跳过添加")
					return nil
				}

				if err := tx.Migrator().AddColumn(&model.AntiCC{}, "skip_global_cc"); err != nil {
					return fmt.Errorf("添加 skip_global_cc 字段失败: %w", err)
				}

				// 历史数据默认值为 false（保持原有行为：继续检测全局CC）
				if err := tx.Exec("UPDATE anti_ccs SET skip_global_cc = 0 WHERE skip_global_cc IS NULL").Error; err != nil {
					zlog.Warn("设置 skip_global_cc 默认值失败", "error", err.Error())
				}

				zlog.Info("skip_global_cc 字段添加成功")
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202604170001: 删除 anti_ccs 表的 skip_global_cc 字段")
				if tx.Migrator().HasColumn(&model.AntiCC{}, "skip_global_cc") {
					return tx.Migrator().DropColumn(&model.AntiCC{}, "skip_global_cc")
				}
				return nil
			},
		},
	})

	// 执行迁移
	if err := m.Migrate(); err != nil {
		errMsg := fmt.Sprintf("core数据库迁移失败: %v", err)
		zlog.Error("迁移执行错误", "error", err.Error())
		return fmt.Errorf("%s", errMsg)
	}

	zlog.Info("core数据库迁移成功完成")
	return nil
}

// checkCoreTablesExist 检查核心表是否存在（检查几个关键表）
func checkCoreTablesExist(db *gorm.DB) bool {
	// 检查几个关键表，如果都存在则认为是老数据库
	keyTables := []interface{}{
		&model.Hosts{},
		&model.Rules{},
		&model.Account{},
		&model.SystemConfig{},
	}

	for _, table := range keyTables {
		if !db.Migrator().HasTable(table) {
			return false
		}
	}
	return true
}

// checkCoreIndexesExist 检查所有core索引是否存在
func checkCoreIndexesExist(db *gorm.DB) bool {
	// 需要检查的索引列表（表名, 索引名）
	indexes := []struct {
		TableName string
		IndexName string
	}{
		{"ip_tags", "uni_iptags_full"},
		{"ip_tags", "idx_iptag_ip"},
	}

	for _, idx := range indexes {
		if !checkIndexExists(db, idx.TableName, idx.IndexName) {
			zlog.Info("索引不存在", "table", idx.TableName, "index", idx.IndexName)
			return false
		}
	}
	return true
}

// createCoreIndexes 创建所有core索引（幂等操作）
func createCoreIndexes(tx *gorm.DB) error {
	zlog.Info("开始创建core索引...")
	startTime := time.Now()

	// 先检查并清理 ip_tags 表中的重复数据（针对唯一索引）
	if err := cleanupDuplicateIPTags(tx); err != nil {
		zlog.Warn("清理重复数据时出现问题（非致命）", "error", err.Error())
	}

	indexes := []struct {
		Name string
		SQL  string
	}{
		{
			Name: "uni_iptags_full",
			SQL:  "CREATE UNIQUE INDEX IF NOT EXISTS uni_iptags_full ON ip_tags (user_code, tenant_id, ip, ip_tag)",
		},
		{
			Name: "idx_iptag_ip",
			SQL:  "CREATE INDEX IF NOT EXISTS idx_iptag_ip ON ip_tags (user_code, tenant_id, ip)",
		},
	}

	for _, idx := range indexes {
		zlog.Info("开始创建索引", "index", idx.Name, "sql", idx.SQL)
		indexStartTime := time.Now()

		if err := tx.Exec(idx.SQL).Error; err != nil {
			// 记录详细的错误信息
			errMsg := fmt.Sprintf("创建索引失败 %s: %v (错误类型: %T)", idx.Name, err, err)
			zlog.Error("索引创建失败详情", "index", idx.Name, "error", err.Error(), "sql", idx.SQL)
			return fmt.Errorf("%s", errMsg)
		}

		indexDuration := time.Since(indexStartTime)
		zlog.Info("索引创建成功", "index", idx.Name, "耗时", indexDuration.String())
	}

	duration := time.Since(startTime)
	zlog.Info("所有core索引创建完成", "耗时", duration.String())
	return nil
}

// cleanupDuplicateIPTags 清理 ip_tags 表中的重复数据
func cleanupDuplicateIPTags(tx *gorm.DB) error {
	zlog.Info("检查 ip_tags 表中的重复数据...")

	// 检查是否存在重复数据
	var duplicateCount int64
	err := tx.Raw(`
		SELECT COUNT(*) FROM (
			SELECT user_code, tenant_id, ip, ip_tag, COUNT(*) as cnt
			FROM ip_tags
			GROUP BY user_code, tenant_id, ip, ip_tag
			HAVING cnt > 1
		)
	`).Scan(&duplicateCount).Error

	if err != nil {
		return fmt.Errorf("检查重复数据失败: %w", err)
	}

	if duplicateCount == 0 {
		zlog.Info("ip_tags 表无重复数据，可以安全创建唯一索引")
		return nil
	}

	zlog.Warn("发现重复数据，开始清理", "重复组数", duplicateCount)

	// 删除重复数据，保留 id 最小的记录
	result := tx.Exec(`
		DELETE FROM ip_tags
		WHERE id NOT IN (
			SELECT MIN(id)
			FROM ip_tags
			GROUP BY user_code, tenant_id, ip, ip_tag
		)
	`)

	if result.Error != nil {
		return fmt.Errorf("清理重复数据失败: %w", result.Error)
	}

	zlog.Info("重复数据清理完成", "删除记录数", result.RowsAffected)
	return nil
}

// dropCoreIndexes 删除所有core索引
func dropCoreIndexes(tx *gorm.DB) error {
	zlog.Info("开始删除core索引")

	indexes := []string{
		"uni_iptags_full",
		"idx_iptag_ip",
	}

	for _, indexName := range indexes {
		if err := tx.Exec(fmt.Sprintf("DROP INDEX IF EXISTS %s", indexName)).Error; err != nil {
			zlog.Warn("删除索引失败（可能不存在）", "index", indexName, "error", err)
		} else {
			zlog.Info("索引删除成功", "index", indexName)
		}
	}

	zlog.Info("所有core索引删除完成")
	return nil
}

// RollbackCoreDBMigration 回滚到指定版本
func RollbackCoreDBMigration(db *gorm.DB, migrationID string) error {
	zlog.Info("准备回滚core迁移", "target_version", migrationID)

	m := gormigrate.New(db, gormigrate.DefaultOptions, []*gormigrate.Migration{})
	if err := m.RollbackTo(migrationID); err != nil {
		return fmt.Errorf("回滚失败: %w", err)
	}

	zlog.Info("回滚成功完成", "version", migrationID)
	return nil
}
