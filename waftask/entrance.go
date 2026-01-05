package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"SamWaf/service/waf_service"
)

var (
	wafTaskService = waf_service.WafTaskServiceApp
)

// InitTaskDb 从数据库加载任务列表
// 任务初始化已经通过 migration 管理，这里只负责加载
func InitTaskDb() []model.Task {
	zlog.Info("从数据库加载任务列表...")

	list, total, err := wafTaskService.GetList()
	if err != nil {
		zlog.Error("加载任务列表失败", "error", err.Error())
		return []model.Task{}
	}

	zlog.Info("任务列表加载完成", "任务总数", total)
	return list
}
