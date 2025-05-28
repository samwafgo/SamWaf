package wafssl

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/service/waf_service"
	"fmt"
	"os"
	"strings"
)

// LoadDnsProviderEnvInfo 初始化dns所需要的参数信息
func LoadDnsProviderEnvInfo(groupName string, belongCloud string) {
	privateInfos, _, err := waf_service.WafPrivateInfoServiceApp.GetListByGroupAndBelongCloudPureApi(groupName, belongCloud)
	if err == nil {
		for _, info := range privateInfos {
			err := os.Setenv(info.PrivateKey, info.PrivateValue)
			if err != nil {
				return
			} else {
				zlog.Info(fmt.Sprintf("Cloud `%s` Group `%s` ENV `%s` LOADED", belongCloud, groupName, info.PrivateKey))
			}
		}
	}
	if global.GWAF_RELEASE == "false" {
		fmt.Println("当前环境变量：")
		for _, env := range os.Environ() {
			parts := strings.SplitN(env, "=", 2)
			key := parts[0]
			value := ""
			if len(parts) > 1 {
				value = parts[1]
			}
			fmt.Printf("%s = %s\n", key, value)
		}
	}
}
