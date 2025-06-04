package model

import "SamWaf/model/baseorm"

// BatchTask 批量任务
type BatchTask struct {
	baseorm.BaseOrm
	BatchTaskName      string `json:"batch_task_name"`      //任务名
	BatchType          string `json:"batch_type"`           //任务类型
	BatchHostCode      string `json:"batch_host_code"`      //网站唯一码 是否绑定到某个主机上
	BatchSourceType    string `json:"batch_source_type"`    //来源类型(local,url)
	BatchTriggerType   string `json:"batch_trigger_type"`   //触发类型 定时任务 cron ,手动任务 manual
	BatchSource        string `json:"batch_source"`         //来源内容 路径或者实际的url内容
	BatchExecuteMethod string `json:"batch_execute_method"` //任务执行方式 追加,覆盖
	BatchExtraConfig   string `json:"batch_extra_config"`   //额外配置字段(JSON字符串)
	Remark             string `json:"remark"`               //备注
}
