package waftask

import (
	"SamWaf/enums"
	"SamWaf/model"
	"SamWaf/service/waf_service"
)

var (
	wafTaskService = waf_service.WafTaskServiceApp
)

func InitTaskDb() []model.Task {

	syncTaskToDb(model.Task{
		TaskName:   "每1秒执行qps清空",
		TaskUnit:   enums.TASK_SECOND,
		TaskAt:     "",
		TaskValue:  1,
		TaskMethod: enums.TASK_RUNTIME_QPS_CLEAN,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每1秒重置QPS数据",
		TaskUnit:   enums.TASK_SECOND,
		TaskAt:     "",
		TaskValue:  1,
		TaskMethod: enums.TASK_HOST_QPS_CLEAN,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每天凌晨3点进行数据归档操作",
		TaskUnit:   enums.TASK_DAY,
		TaskValue:  1,
		TaskAt:     "03:00",
		TaskMethod: enums.TASK_SHARE_DB,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每天10s进行一次统计",
		TaskUnit:   enums.TASK_SECOND,
		TaskValue:  10,
		TaskAt:     "",
		TaskMethod: enums.TASK_COUNTER,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每1分钟进行一次延迟信息提取",
		TaskUnit:   enums.TASK_MIN,
		TaskValue:  10,
		TaskAt:     "",
		TaskMethod: enums.TASK_DELAY_INFO,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每1分钟进行一次配置更新",
		TaskUnit:   enums.TASK_MIN,
		TaskValue:  1,
		TaskAt:     "",
		TaskMethod: enums.TASK_LOAD_CONFIG,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每1小时进行一次微信提取accesstoken",
		TaskUnit:   enums.TASK_HOUR,
		TaskValue:  1,
		TaskAt:     "",
		TaskMethod: enums.TASK_REFLUSH_WECHAT_ACCESS_TOKEN,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每天早5点删除历史信息",
		TaskUnit:   enums.TASK_DAY,
		TaskValue:  1,
		TaskAt:     "05:00",
		TaskMethod: enums.TASK_DELETE_HISTORY_INFO,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每天30分钟删除历史下载文件",
		TaskUnit:   enums.TASK_MIN,
		TaskValue:  30,
		TaskAt:     "",
		TaskMethod: enums.TASK_DELETE_HISTORY_DOWNLOAD_FILE,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每天02:13进行SSL证书申请",
		TaskUnit:   enums.TASK_DAY,
		TaskValue:  1,
		TaskAt:     "02:13",
		TaskMethod: enums.TASK_SSL_ORDER_RENEW,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每天03:00进行查询SSL绑定路径自动加载最新证书",
		TaskUnit:   enums.TASK_DAY,
		TaskValue:  1,
		TaskAt:     "03:00",
		TaskMethod: enums.TASK_SSL_PATH_LOAD,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每天05:00进行批量任务",
		TaskUnit:   enums.TASK_DAY,
		TaskValue:  1,
		TaskAt:     "05:00",
		TaskMethod: enums.TASK_BATCH,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每天06:00进行批量SSL过期检测",
		TaskUnit:   enums.TASK_DAY,
		TaskValue:  1,
		TaskAt:     "06:00",
		TaskMethod: enums.TASK_SSL_EXPIRE_CHECK,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每天早8晚8进行通知(需要开启通知)",
		TaskUnit:   enums.TASK_DAY,
		TaskValue:  1,
		TaskAt:     "08:00;20:00",
		TaskMethod: enums.TASK_NOTICE,
	})
	syncTaskToDb(model.Task{
		TaskName:   "每天5s进行健康度检测",
		TaskUnit:   enums.TASK_SECOND,
		TaskValue:  5,
		TaskAt:     "",
		TaskMethod: enums.TASK_HEALTH,
	})
	list, _, _ := wafTaskService.GetList()
	return list
}
func syncTaskToDb(task model.Task) {
	cnt := wafTaskService.CheckIsExist(task.TaskName)
	if cnt == 0 {
		wafTaskService.Add(task)
	}
}
