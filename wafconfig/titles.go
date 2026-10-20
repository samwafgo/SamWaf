package wafconfig

import (
	"SamWaf/utils"
	"os"
	"path/filepath"
	"sync"

	"github.com/spf13/viper"
)

type AdminTitles struct {
	AdminTitle string `json:"admin_title"`
}

var adminTitlesState struct {
	sync.RWMutex
	titles AdminTitles
}

func GetAdminTitles() AdminTitles {
	adminTitlesState.RLock()
	defer adminTitlesState.RUnlock()
	return adminTitlesState.titles
}

func loadAdminTitles(config *viper.Viper) {
	adminTitlesState.Lock()
	defer adminTitlesState.Unlock()
	adminTitlesState.titles = AdminTitles{
		AdminTitle: config.GetString("ui.admin_title"),
	}
}

func UpdateAdminTitles(titles AdminTitles) error {
	return updateAdminTitles(filepath.Join(utils.GetCurrentDir(), "conf"), titles)
}

func updateAdminTitles(configDir string, titles AdminTitles) error {
	adminTitlesState.Lock()
	defer adminTitlesState.Unlock()

	if err := os.MkdirAll(configDir, os.ModePerm); err != nil {
		return err
	}
	config := viper.New()
	config.AddConfigPath(configDir)
	config.SetConfigName("config")
	config.SetConfigType("yml")
	if err := config.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
		return persistAdminTitles(config, titles, true)
	}
	return persistAdminTitles(config, titles, false)
}

// 调用方持有 adminTitlesState 写锁。
func persistAdminTitles(config *viper.Viper, titles AdminTitles, create bool) error {
	config.Set("ui.admin_title", titles.AdminTitle)
	var err error
	if create {
		err = config.SafeWriteConfig()
	} else {
		err = config.WriteConfig()
	}
	if err != nil {
		return err
	}
	adminTitlesState.titles = titles
	return nil
}
