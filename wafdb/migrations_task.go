package wafdb

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"fmt"
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// RunTaskInitMigrations 执行任务初始化迁移
func RunTaskInitMigrations(db *gorm.DB) error {
	zlog.Info("开始执行任务初始化数据库迁移...")

	m := gormigrate.New(db, gormigrate.DefaultOptions, []*gormigrate.Migration{
		// 迁移1: 初始化系统任务
		{
			ID: "202601050002_init_system_tasks",
			Migrate: func(tx *gorm.DB) error {
				zlog.Info("迁移 202601050002: 初始化系统任务")

				// 定义系统任务列表
				systemTasks := []model.Task{
					// 每秒级别任务
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每1秒执行qps清空",
						TaskUnit:   enums.TASK_SECOND,
						TaskAt:     "",
						TaskValue:  1,
						TaskMethod: enums.TASK_RUNTIME_QPS_CLEAN,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每1秒重置QPS数据",
						TaskUnit:   enums.TASK_SECOND,
						TaskAt:     "",
						TaskValue:  1,
						TaskMethod: enums.TASK_HOST_QPS_CLEAN,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每天10s进行一次统计",
						TaskUnit:   enums.TASK_SECOND,
						TaskValue:  10,
						TaskAt:     "",
						TaskMethod: enums.TASK_COUNTER,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每10s推送系统统计数据",
						TaskUnit:   enums.TASK_SECOND,
						TaskValue:  10,
						TaskAt:     "",
						TaskMethod: enums.TASK_STATS_PUSH,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每30s进行健康度检测",
						TaskUnit:   enums.TASK_SECOND,
						TaskValue:  30,
						TaskAt:     "",
						TaskMethod: enums.TASK_HEALTH,
					},
					// 每分钟级别
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每1分钟进行一次延迟信息提取",
						TaskUnit:   enums.TASK_MIN,
						TaskValue:  10,
						TaskAt:     "",
						TaskMethod: enums.TASK_DELAY_INFO,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每1分钟进行一次配置更新",
						TaskUnit:   enums.TASK_MIN,
						TaskValue:  1,
						TaskAt:     "",
						TaskMethod: enums.TASK_LOAD_CONFIG,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每5分钟进行CCWindows旧信息清除",
						TaskUnit:   enums.TASK_MIN,
						TaskValue:  5,
						TaskAt:     "",
						TaskMethod: enums.TASK_CLEAR_CC_WINDOWS,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每5分钟进行防火墙IP封禁规则清理",
						TaskUnit:   enums.TASK_MIN,
						TaskValue:  5,
						TaskAt:     "",
						TaskMethod: enums.TASK_FIREWALL_CLEAN_EXPIRED,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每天30分钟删除历史下载文件",
						TaskUnit:   enums.TASK_MIN,
						TaskValue:  30,
						TaskAt:     "",
						TaskMethod: enums.TASK_DELETE_HISTORY_DOWNLOAD_FILE,
					},
					// 每小时级别
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每1小时进行一次微信提取accesstoken",
						TaskUnit:   enums.TASK_HOUR,
						TaskValue:  1,
						TaskAt:     "",
						TaskMethod: enums.TASK_REFLUSH_WECHAT_ACCESS_TOKEN,
					},
					// 每日定时级别
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每天凌晨3点进行数据归档操作",
						TaskUnit:   enums.TASK_DAY,
						TaskValue:  1,
						TaskAt:     "03:00",
						TaskMethod: enums.TASK_SHARE_DB,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每天早5点删除历史信息",
						TaskUnit:   enums.TASK_DAY,
						TaskValue:  1,
						TaskAt:     "05:00",
						TaskMethod: enums.TASK_DELETE_HISTORY_INFO,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每天01:00进行GC回收",
						TaskUnit:   enums.TASK_DAY,
						TaskValue:  1,
						TaskAt:     "01:00",
						TaskMethod: enums.TASK_GC,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每天凌晨01:20进行数据库监控",
						TaskUnit:   enums.TASK_DAY,
						TaskValue:  1,
						TaskAt:     "01:20",
						TaskMethod: enums.TASK_DB_MONITOR,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每天02:13进行SSL证书申请",
						TaskUnit:   enums.TASK_DAY,
						TaskValue:  1,
						TaskAt:     "02:13",
						TaskMethod: enums.TASK_SSL_ORDER_RENEW,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每天03:00进行查询SSL绑定路径自动加载最新证书",
						TaskUnit:   enums.TASK_DAY,
						TaskValue:  1,
						TaskAt:     "03:00",
						TaskMethod: enums.TASK_SSL_PATH_LOAD,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每天05:00进行批量任务",
						TaskUnit:   enums.TASK_DAY,
						TaskValue:  1,
						TaskAt:     "05:00",
						TaskMethod: enums.TASK_BATCH,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每天06:00进行批量SSL过期检测",
						TaskUnit:   enums.TASK_DAY,
						TaskValue:  1,
						TaskAt:     "06:00",
						TaskMethod: enums.TASK_SSL_EXPIRE_CHECK,
					},
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:   "每天早8晚8进行通知(需要开启通知)",
						TaskUnit:   enums.TASK_DAY,
						TaskValue:  1,
						TaskAt:     "08:00;20:00",
						TaskMethod: enums.TASK_NOTICE,
					},
					// 每周级别
					{
						BaseOrm: baseorm.BaseOrm{
							Id:          uuid.GenUUID(),
							USER_CODE:   global.GWAF_USER_CODE,
							Tenant_ID:   global.GWAF_TENANT_ID,
							CREATE_TIME: customtype.JsonTime(time.Now()),
							UPDATE_TIME: customtype.JsonTime(time.Now()),
						},
						TaskName:          "每周六晚上23:00进行web文件缓存清除",
						TaskUnit:          enums.TASK_WEEKLY,
						TaskValue:         1,
						TaskAt:            "23:00",
						TaskDaysOfTheWeek: "6",
						TaskMethod:        enums.TASK_CLEAR_WEBCACHE,
					},
				}

				// 插入或更新任务
				for _, task := range systemTasks {
					// 检查任务是否已存在
					var count int64
					tx.Model(&model.Task{}).Where("task_method = ?", task.TaskMethod).Count(&count)

					if count == 0 {
						// 任务不存在，插入新任务
						if err := tx.Create(&task).Error; err != nil {
							zlog.Warn("创建任务失败", "task", task.TaskName, "error", err.Error())
							return fmt.Errorf("创建任务 %s 失败: %w", task.TaskName, err)
						}
						zlog.Info("任务创建成功", "task", task.TaskName)
					} else if count > 1 {
						// 如果存在重复的任务方法，先删除所有然后重新创建
						zlog.Warn("发现重复任务，清理后重建", "task_method", task.TaskMethod, "count", count)
						if err := tx.Where("task_method = ?", task.TaskMethod).Delete(&model.Task{}).Error; err != nil {
							return fmt.Errorf("清理重复任务 %s 失败: %w", task.TaskName, err)
						}
						if err := tx.Create(&task).Error; err != nil {
							return fmt.Errorf("重建任务 %s 失败: %w", task.TaskName, err)
						}
						zlog.Info("重复任务已清理并重建", "task", task.TaskName)
					} else {
						// 任务已存在，跳过
						zlog.Debug("任务已存在，跳过", "task", task.TaskName)
					}
				}

				zlog.Info("系统任务初始化完成", "任务总数", len(systemTasks))
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				zlog.Info("回滚 202601050002: 删除系统任务（保护用户自定义任务）")
				// 只删除系统预定义的任务，根据 task_method 来识别
				systemTaskMethods := []string{
					enums.TASK_RUNTIME_QPS_CLEAN,
					enums.TASK_HOST_QPS_CLEAN,
					enums.TASK_COUNTER,
					enums.TASK_STATS_PUSH,
					enums.TASK_HEALTH,
					enums.TASK_DELAY_INFO,
					enums.TASK_LOAD_CONFIG,
					enums.TASK_CLEAR_CC_WINDOWS,
					enums.TASK_FIREWALL_CLEAN_EXPIRED,
					enums.TASK_DELETE_HISTORY_DOWNLOAD_FILE,
					enums.TASK_REFLUSH_WECHAT_ACCESS_TOKEN,
					enums.TASK_SHARE_DB,
					enums.TASK_DELETE_HISTORY_INFO,
					enums.TASK_GC,
					enums.TASK_DB_MONITOR,
					enums.TASK_SSL_ORDER_RENEW,
					enums.TASK_SSL_PATH_LOAD,
					enums.TASK_BATCH,
					enums.TASK_SSL_EXPIRE_CHECK,
					enums.TASK_NOTICE,
					enums.TASK_CLEAR_WEBCACHE,
				}

				return tx.Where("task_method IN ?", systemTaskMethods).Delete(&model.Task{}).Error
			},
		},
	})

	// 执行迁移
	if err := m.Migrate(); err != nil {
		errMsg := fmt.Sprintf("任务初始化迁移失败: %v", err)
		zlog.Error("任务迁移执行错误", "error", err.Error())
		return fmt.Errorf("%s", errMsg)
	}

	zlog.Info("任务初始化迁移成功完成")
	return nil
}
