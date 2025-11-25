package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/spec"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"fmt"
	"time"
)

var (
	wafHostService      = waf_service.WafHostServiceApp
	wafSslConfigService = waf_service.WafSslConfigServiceApp
	wafSslOrderService  = waf_service.WafSSLOrderServiceApp
	wafSslExpireService = waf_service.WafSslExpireServiceApp
)

/*
*
SSL路径自动加载—_证书自动续期
*/
func SSLReload() {
	innerLogName := "TaskSSL"
	zlog.Info(innerLogName, "准备进行ssl证书文件路径自动加载")
	if global.GCONFIG_RECORD_AUTO_LOAD_SSL == 1 {
		zlog.Info(innerLogName, "自动加载ssl开关:开启")
		//1.遍历所有证书夹得内容
		//2.如果对应得位置有内容
		//3.就开始判断数据是否是正常的，如果正常则备份现有，然后现有的证书替换掉
		//4.重新查询让关联的主机信息重新加载
		sslConfigReps, err := wafSslConfigService.GetAllListInner()
		if err != nil {
			zlog.Error(innerLogName, "ssl config:", err)
			return
		}

		if len(sslConfigReps) <= 0 {
			zlog.Info(innerLogName, "没有ssl证书")
			return
		}
		for _, rep := range sslConfigReps {
			err, updateSslConfig, backSslConfig := rep.CheckKeyAndCertFileLoad()
			if err != nil {
				zlog.Error(innerLogName, "ssl config:", err.Error())
				continue
			}
			wafSslConfigService.CreateNewIdInner(backSslConfig)
			err = wafSslConfigService.ModifyInner(updateSslConfig)
			if err != nil {
				zlog.Error(innerLogName, "ssl modify inner config:", err.Error())
			}
			for _, hosts := range wafHostService.GetHostBySSLConfigId(updateSslConfig.Id) {
				//1.更新主机信息 2.发送主机通知
				err = wafHostService.UpdateSSLInfo(updateSslConfig.CertContent, updateSslConfig.KeyContent, hosts.Code)
				if err != nil {
					zlog.Error(innerLogName, "ssl host update:", err.Error())
					continue
				}
				hosts.Keyfile = updateSslConfig.KeyContent
				hosts.Certfile = updateSslConfig.CertContent
				var chanInfo = spec.ChanCommonHost{
					HostCode:   hosts.Code,
					Type:       enums.ChanTypeSSL,
					Content:    hosts,
					OldContent: hosts,
				}
				global.GWAF_CHAN_MSG <- chanInfo
			}
			zlog.Info(innerLogName, "ssl证书已处理完", rep.CertPath, rep.KeyPath)

		}
	} else {
		zlog.Info(innerLogName, "自动加载ssl开关:关闭")
	}
}

// SSLOrderReload SSL证书自动续期 远程申请
func SSLOrderReload() {
	innerLogName := "TaskSSLOrder"
	zlog.Info(innerLogName, "准备进行ssl证书自动续期检测")
	//1.找出来所有得SSL得主机 2.查询是否存在自动SSL订单得最新得数据 3.查询没有到期得最后一条信息来申请延期
	allSSLHost, _, err := wafHostService.GetAllSSLBindHost()
	if err == nil {
		for _, hostBean := range allSSLHost {
			zlog.Info(innerLogName, fmt.Sprintf("正在检测域名: %s:%d", hostBean.Host, hostBean.Port))
			lastSslOrderInfo, err := wafSslOrderService.GetLastedInfo(hostBean.Code)
			if err != nil {
				zlog.Error(innerLogName, "ssl order get lasted info:", err.Error())
			} else {
				if lastSslOrderInfo.Id == "" {
					//未找到关联信息
					continue
				}
				isExpire, availDay, msg, err := lastSslOrderInfo.ExpirationMessage()
				if err != nil {
					zlog.Error(innerLogName, "ssl order get lasted info:", err.Error())
				} else {
					zlog.Info(fmt.Sprintf("%s 域名%s 是否过期 %v 天数：%v 信息 %v ，系统检测超期天数 %v 天",
						innerLogName, hostBean.Host, isExpire, availDay, msg, global.GCONFIG_RECORD_SSLOrder_EXPIRE_DAY))
					if isExpire == false && availDay <= int(global.GCONFIG_RECORD_SSLOrder_EXPIRE_DAY) {
						//没过期 且是知单天数 就才处理
						var chanInfo = spec.ChanSslOrder{
							Type:    enums.ChanSslOrderrenew,
							Content: lastSslOrderInfo,
						}
						global.GWAF_CHAN_SSLOrder <- chanInfo
					}
				}
			}
		}
	}
}

/*
*
SSL证书过期检测
*/
func SSLExpireCheck() {
	innerLogName := "SSLExpireCheck"
	zlog.Info(innerLogName, "准备进行SSL证书过期检测")
	sslExpires, cnt, err := wafSslExpireService.GetAllList()
	if err != nil {
		zlog.Error(innerLogName, "ssl expire list:", err.Error())
		return
	}
	if cnt == 0 {
		zlog.Error(innerLogName, "无检测数据任务")
		return
	}
	for _, expireBean := range sslExpires {

		zlog.Info(innerLogName, fmt.Sprintf("正在检测域名: %s:%d", expireBean.Domain, expireBean.Port))
		host := fmt.Sprintf("%s:%d", expireBean.Domain, expireBean.Port)
		expiryTime, err := utils.CheckSSLCertificateExpiry(host)
		expireBean.LastDetect = time.Now()
		if err != nil {
			expireBean.VisitLog = err.Error()
		} else {
			expireBean.ValidTo = expiryTime
			expireBean.VisitLog = ""

			// 检查证书是否即将过期，并发送通知
			checkAndNotifySSLExpire(expireBean.Domain, expiryTime)
		}
		//更新数据
		wafSslExpireService.Modify(expireBean)
	}
	global.GWAF_RUNTIME_SSL_EXPIRE_CHECK = false
}

// SyncHostToSslCheck 同步已存在主机到SSL证书检测任务里
func SyncHostToSslCheck() {
	innerLogName := "SyncHostToSslCheck"
	zlog.Info(innerLogName, "准备进行同步已存在主机到SSL证书检测任务里")
	//检测信息 如果主机和端口不存在 则新增
	sslHost, sslHostCnt, err := wafHostService.GetAllSSLHost()
	if err != nil {
		zlog.Error(innerLogName, "sync host to ssl expire:", err.Error())
		return
	}
	if sslHostCnt == 0 {
		zlog.Error(innerLogName, "sync host not find ssl host")
		return
	}
	for _, hostBean := range sslHost {
		if wafSslExpireService.CheckIsExist(hostBean.Host, hostBean.Port) == 0 {
			//插入新的数据
			wafSslExpireService.Add(hostBean.Host, hostBean.Port)
		}
	}
	global.GWAF_RUNTIME_SSL_SYNC_HOST = false
}

// checkAndNotifySSLExpire 检查SSL证书是否即将过期，并发送通知
func checkAndNotifySSLExpire(domain string, expiryTime time.Time) {
	// 计算剩余天数
	daysLeft := int(time.Until(expiryTime).Hours() / 24)

	// 从配置读取提前提醒天数（默认30天）
	expireDays := int(global.GCONFIG_RECORD_SSLOrder_EXPIRE_DAY)
	if expireDays <= 0 {
		expireDays = 30 // 默认值
	}

	// 定义需要提醒的天数阈值
	// 基于配置的天数，设置多个提醒节点：配置天数、一半、7天、3天、1天
	alertThresholds := []int{}
	alertThresholds = append(alertThresholds, expireDays) // 例如：30天
	if expireDays > 15 {
		alertThresholds = append(alertThresholds, expireDays/2) // 例如：15天
	}
	if expireDays > 7 {
		alertThresholds = append(alertThresholds, 7) // 7天
	}
	if expireDays > 3 {
		alertThresholds = append(alertThresholds, 3) // 3天
	}
	alertThresholds = append(alertThresholds, 1) // 1天

	// 检查是否需要提醒：剩余天数等于某个阈值，或者少于最小阈值
	shouldAlert := false

	// 情况1：剩余天数正好在阈值上
	for _, threshold := range alertThresholds {
		if daysLeft == threshold {
			shouldAlert = true
			break
		}
	}

	// 情况2：剩余天数小于配置天数（在提醒范围内）
	if daysLeft <= expireDays && daysLeft >= 0 {
		shouldAlert = true
	}

	// 情况3：已经过期
	if daysLeft < 0 {
		shouldAlert = true
	}

	// 如果需要提醒，发送通知
	if shouldAlert {
		serverName := global.GWAF_CUSTOM_SERVER_NAME
		if serverName == "" {
			serverName = "未命名服务器"
		}

		var noticeMsg string
		if daysLeft < 0 {
			noticeMsg = fmt.Sprintf("SSL证书已过期 %d 天", -daysLeft)
		} else if daysLeft == 0 {
			noticeMsg = "SSL证书今天过期"
		} else if daysLeft == 1 {
			noticeMsg = "SSL证书明天过期"
		} else {
			noticeMsg = fmt.Sprintf("SSL证书即将在 %d 天后过期", daysLeft)
		}

		zlog.Info("SSLExpireCheck", fmt.Sprintf("%s: %s (剩余%d天)", domain, noticeMsg, daysLeft))

		// 发送SSL证书过期通知到消息队列
		global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.SSLExpireMessageInfo{
			BaseMessageInfo: innerbean.BaseMessageInfo{
				OperaType: "SSL证书过期提醒",
				Server:    serverName,
			},
			Domain:     domain,
			ExpireTime: expiryTime.Format("2006-01-02 15:04:05"),
			DaysLeft:   daysLeft,
		})
	}
}
