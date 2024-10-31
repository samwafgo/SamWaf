package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model/spec"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
)

var (
	wafHostService      = waf_service.WafHostServiceApp
	wafSslConfigService = waf_service.SslConfigServiceApp
)

/*
*
SSL证书自动续期
*/
func SSLReload() {
	innerLogName := "TaskSSL"
	zlog.Info(innerLogName, "准备进行ssl证书自动加载")
	if global.GCONFIG_RECORD_AUTO_LOAD_SSL == 1 {
		zlog.Info(innerLogName, "自动加载ssl开关:开启")
		//1.遍历所有证书夹得内容
		//2.如果对应得位置有内容
		//3.就开始判断数据是否是正常的，如果正常则备份现有，然后现有的证书替换掉
		//4.重新查询让关联的主机信息重新加载
		sslConfigReps, sslConfigSize, err := wafSslConfigService.GetAllListInner()
		if err != nil {
			zlog.Error(innerLogName, "ssl config:", err)
			return
		}
		if sslConfigSize <= 0 {
			zlog.Info(innerLogName, "没有ssl证书")
			return
		}
		for _, rep := range sslConfigReps {
			err, updateSslConfig, backSslConfig := rep.CheckKeyAndCertFileLoad(utils.GetCurrentDir())
			if err != nil {
				zlog.Error(innerLogName, "ssl config:", err.Error())
				continue
			}
			wafSslConfigService.AddInner(backSslConfig)
			err = wafSslConfigService.ModifyInner(updateSslConfig)
			/*fmt.Printf("updateSslConfig: %+v\n", updateSslConfig)
			fmt.Printf("backSslConfig: %+v\n", backSslConfig)*/
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
