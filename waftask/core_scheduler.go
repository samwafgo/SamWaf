package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"fmt"
	"github.com/go-co-op/gocron"
	"time"
)

// TaskScheduler 用于封装任务调度器
type TaskScheduler struct {
	Scheduler *gocron.Scheduler
	Registry  *TaskRegistry
}

// NewTaskScheduler 创建新的任务调度器
func NewTaskScheduler(registry *TaskRegistry) *TaskScheduler {
	timezone, _ := time.LoadLocation("Asia/Shanghai")
	return &TaskScheduler{
		Scheduler: gocron.NewScheduler(timezone),
		Registry:  registry,
	}
}

// ScheduleTask 用于调度任务
// unit 表示单位："second"、"minute"、"hour"、"day"
// interval 表示时间间隔
// at 具体的时间
// taskMethod 是具体要执行的任务
func (ts *TaskScheduler) ScheduleTask(unit string, interval int, at string, taskMethod string) error {
	var job *gocron.Job
	var err error

	switch unit {
	case enums.TASK_SECOND:
		job, err = ts.Scheduler.Every(interval).Seconds().Do(func() {
			ts.Registry.ExecuteTask(taskMethod)
		})
	case enums.TASK_MIN:
		job, err = ts.Scheduler.Every(interval).Minutes().Do(func() {
			ts.Registry.ExecuteTask(taskMethod)
		})
	case enums.TASK_HOUR:
		job, err = ts.Scheduler.Every(interval).Hours().Do(func() {
			ts.Registry.ExecuteTask(taskMethod)
		})
	case enums.TASK_DAY:
		job, err = ts.Scheduler.Every(interval).Day().At(at).Do(func() {
			ts.Registry.ExecuteTask(taskMethod)
		})
	default:
		return fmt.Errorf("unsupported unit: %s", unit)
	}

	if err != nil {
		return fmt.Errorf("failed to schedule task: %v", err)
	}
	zlog.Debug(fmt.Sprintf("Task scheduled: %v every %d %s\n", job, interval, unit))
	return nil
}
func (ts *TaskScheduler) Start() {
	ts.Scheduler.StartAsync()
}
func (ts *TaskScheduler) Stop() {
	ts.Scheduler.Stop()
}

func (ts *TaskScheduler) RunManual(taskMethod string) {
	ts.Registry.ExecuteTask(taskMethod)
}
