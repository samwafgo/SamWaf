package wafconfig

import (
	"SamWaf/global"
	"SamWaf/utils"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

func loadACMEConfig(config *viper.Viper) {
	settings := global.DefaultACMEConfig()
	for _, item := range []struct {
		key      string
		value    *int
		min, max int
	}{
		{"acme.directory_timeout_seconds", &settings.DirectoryTimeoutSeconds, 5, 120},
		{"acme.directory_max_retries", &settings.DirectoryMaxRetries, 0, 5},
	} {
		if !config.IsSet(item.key) {
			continue
		}
		var raw string
		switch value := config.Get(item.key).(type) {
		case int, int64, uint64:
			raw = fmt.Sprint(value)
		case string:
			raw = strings.TrimSpace(value)
		}
		value, err := strconv.Atoi(raw)
		if err != nil || value < item.min || value > item.max {
			fmt.Printf("WARN ACME 配置 %s 应为 %d–%d 的整数，使用默认值 %d\n", item.key, item.min, item.max, *item.value)
			continue
		}
		*item.value = value
	}
	settings.TrustedCAs = loadACMETrustedCAs(config.Get("acme.trusted_cas"))
	global.GACME_CONFIG = settings
}

func loadACMETrustedCAs(raw interface{}) map[string]global.ACMETrustedCA {
	if raw == nil {
		return nil
	}
	entries, ok := raw.([]interface{})
	if !ok {
		fmt.Println("WARN ACME 配置 acme.trusted_cas 应为列表")
		return nil
	}
	var trusted map[string]global.ACMETrustedCA
	for i, rawEntry := range entries {
		entry, _ := rawEntry.(map[string]interface{})
		address, _ := entry["directory_url"].(string)
		address = strings.TrimSpace(address)
		if _, err := utils.ParseACMEDirectoryURL(address); err != nil {
			fmt.Printf("WARN ACME 配置 acme.trusted_cas 第 %d 项的 directory_url 无效\n", i+1)
			continue
		}
		if trusted == nil {
			trusted = make(map[string]global.ACMETrustedCA)
		}
		if _, exists := trusted[address]; exists {
			trusted[address] = global.ACMETrustedCA{ConfigError: "directory_url 重复配置"}
			continue
		}
		name, _ := entry["ca_file"].(string)
		if len(entry) != 2 || !utils.IsValidACMECAFilename(name) {
			trusted[address] = global.ACMETrustedCA{ConfigError: "ca_file 必须是 conf/acme-ca 下的 PEM 文件名"}
			continue
		}
		trusted[address] = global.ACMETrustedCA{CAFile: name}
	}
	return trusted
}
