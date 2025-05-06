package wafssl

import (
	"SamWaf/service/waf_service"
	"os"
)

// 初始化dns所需要的参数信息
func InitDnsProviderEnvInfo() {
	privateInfos, _, err := waf_service.WafPrivateInfoServiceApp.GetListPureApi()
	if err == nil {
		for _, info := range privateInfos {
			err := os.Setenv(info.PrivateKey, info.PrivateValue)
			if err != nil {
				return
			}
		}
	}

}
