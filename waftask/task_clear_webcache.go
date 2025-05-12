package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"SamWaf/service/waf_service"
	"SamWaf/wafenginecore/wafwebcache"
	"encoding/json"
	"fmt"
)

func TaskClearWebcache() {
	innerLogName := "TaskClearWebcache"
	zlog.Info(innerLogName, "开始执行网站缓存清理任务")

	// 获取所有运行中的主机
	hosts := waf_service.WafHostServiceApp.GetAllRunningHostApi()
	if len(hosts) == 0 {
		zlog.Info(innerLogName, "没有运行中的主机，无需清理缓存")
		return
	}

	// 遍历所有主机
	for _, host := range hosts {
		// 检查主机是否启用了缓存
		var cacheConfig model.CacheConfig
		err := json.Unmarshal([]byte(host.CacheJSON), &cacheConfig)
		if err != nil {
			zlog.Debug(innerLogName, fmt.Sprintf("解析主机 %s 的缓存配置失败: %v", host.Code, err))
			continue
		}

		// 如果主机启用了缓存且缓存位置包含文件缓存
		if cacheConfig.IsEnableCache == 1 && (cacheConfig.CacheLocation == "file" || cacheConfig.CacheLocation == "all") {
			// 确保缓存目录不为空
			if cacheConfig.CacheDir == "" {
				zlog.Warn(innerLogName, fmt.Sprintf("主机 %s 的缓存目录为空", host.Code))
				continue
			}

			zlog.Info(innerLogName, fmt.Sprintf("清理主机 %s 的缓存目录: %s", host.Code, cacheConfig.CacheDir))
			// 调用清理函数
			wafwebcache.CleanExpiredCache(cacheConfig.CacheDir)
		} else {
			zlog.Debug(innerLogName, fmt.Sprintf("主机 %s 未启用文件缓存，跳过清理", host.Code))
		}
	}

	zlog.Info(innerLogName, "网站缓存清理任务完成")
}
