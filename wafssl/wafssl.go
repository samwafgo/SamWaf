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
	// 清除旧的 DNS provider 相关环境变量，防止污染
	dnsEnvKeys := []string{
		// Tencent Cloud
		"TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "TENCENTCLOUD_REGION",
		// Alibaba Cloud
		"ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY", "ALICLOUD_REGION_ID",
		// Huawei Cloud
		"HUAWEICLOUD_DOMAIN_NAME", "HUAWEICLOUD_ACCESS_KEY_ID", "HUAWEICLOUD_ACCESS_KEY_SECRET", "HUAWEICLOUD_REGION",
		// Cloudflare
		"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_ACCOUNT_ID",
		// Baidu Cloud
		"BAIDUCLOUD_ACCESS_KEY", "BAIDUCLOUD_SECRET_ACCESS_KEY", "BAIDUCLOUD_REGION",
	}
	for _, key := range dnsEnvKeys {
		os.Unsetenv(key)
	}

	privateInfos, _, err := waf_service.WafPrivateInfoServiceApp.GetListByGroupAndBelongCloudPureApi(groupName, belongCloud)
	if err != nil {
		zlog.Error(fmt.Sprintf("Failed to load DNS provider env info for cloud `%s` group `%s`: %v", belongCloud, groupName, err))
		return
	}
	if len(privateInfos) == 0 {
		zlog.Warn(fmt.Sprintf("No DNS credentials found in DB for cloud `%s` group `%s` - DNS provider will have no auth", belongCloud, groupName))
		return
	}

	for _, info := range privateInfos {
		err := os.Setenv(info.PrivateKey, info.PrivateValue)
		if err != nil {
			zlog.Error(fmt.Sprintf("Failed to set env var `%s`: %v", info.PrivateKey, err))
			return
		}
		zlog.Info(fmt.Sprintf("Cloud `%s` Group `%s` ENV `%s` LOADED", belongCloud, groupName, info.PrivateKey))
	}

	zlog.Info(fmt.Sprintf("Successfully loaded %d credentials for cloud `%s` group `%s`", len(privateInfos), belongCloud, groupName))

	if global.GWAF_RELEASE == "false" {
		zlog.Debug("Current DNS-related environment variables:")
		for _, env := range os.Environ() {
			parts := strings.SplitN(env, "=", 2)
			key := parts[0]
			value := ""
			if len(parts) > 1 {
				value = parts[1]
			}
			zlog.Debug(fmt.Sprintf("%s = %s", key, value))
		}
	}
}
