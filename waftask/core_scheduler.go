package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"fmt"
	"github.com/go-co-op/gocron"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TaskScheduler 用于封装任务调度器
type TaskScheduler struct {
	Scheduler *gocron.Scheduler
	Registry  *TaskRegistry
	// 任务标签映射，用于管理任务的卸载和重载
	taskTags map[string]string // key: taskMethod, value: jobTag
	mu       sync.RWMutex      // 保护 taskTags 的并发访问
}

// NewTaskScheduler 创建新的任务调度器
func NewTaskScheduler(registry *TaskRegistry) *TaskScheduler {
	timezone, _ := time.LoadLocation("Asia/Shanghai")
	return &TaskScheduler{
		Scheduler: gocron.NewScheduler(timezone),
		Registry:  registry,
		taskTags:  make(map[string]string),
	}
}

// ScheduleTask 用于调度任务
// unit 表示单位："second"、"minute"、"hour"、"day"
// interval 表示时间间隔
// at 具体的时间
// taskMethod 是具体要执行的任务
// taskDaysOfTheWeek 如果是周级别 此处传入周几
func (ts *TaskScheduler) ScheduleTask(unit string, interval int, at string, taskMethod string, taskDaysOfTheWeek string) error {
	var job *gocron.Job
	var err error

	// 生成任务标签，用于后续管理
	jobTag := fmt.Sprintf("task_%s", taskMethod)

	switch unit {
	case enums.TASK_SECOND:
		job, err = ts.Scheduler.Every(interval).Seconds().Tag(jobTag).Do(func() {
			ts.Registry.ExecuteTask(taskMethod)
		})
	case enums.TASK_MIN:
		job, err = ts.Scheduler.Every(interval).Minutes().Tag(jobTag).Do(func() {
			ts.Registry.ExecuteTask(taskMethod)
		})
	case enums.TASK_HOUR:
		job, err = ts.Scheduler.Every(interval).Hours().Tag(jobTag).Do(func() {
			ts.Registry.ExecuteTask(taskMethod)
		})
	case enums.TASK_DAY:
		job, err = ts.Scheduler.Every(interval).Day().At(at).Tag(jobTag).Do(func() {
			ts.Registry.ExecuteTask(taskMethod)
		})
	case enums.TASK_WEEKLY:
		dayInt, err := strconv.Atoi(strings.TrimSpace(taskDaysOfTheWeek))
		if err != nil {
			return fmt.Errorf("无效的星期几格式: %s, 错误: %v", taskDaysOfTheWeek, err)
		}
		job, err = ts.Scheduler.Every(interval).Weekday(time.Weekday(dayInt)).At(at).Tag(jobTag).Do(func() {
			ts.Registry.ExecuteTask(taskMethod)
		})
	default:
		return fmt.Errorf("unsupported unit: %s", unit)
	}

	if err != nil {
		return fmt.Errorf("failed to schedule task: %v", err)
	}

	// 保存任务标签映射
	ts.mu.Lock()
	ts.taskTags[taskMethod] = jobTag
	ts.mu.Unlock()

	zlog.Debug(fmt.Sprintf("Task scheduled: %v every %d %s\n", job, interval, unit))
	return nil
}
func (ts *TaskScheduler) Start() {
	ts.Scheduler.StartAsync()
}
func (ts *TaskScheduler) Stop() {
	if ts != nil {
		ts.Scheduler.Stop()
	}
}

func (ts *TaskScheduler) RunManual(taskMethod string) {
	ts.Registry.ExecuteTask(taskMethod)
}

// UnscheduleTask 卸载指定的任务
func (ts *TaskScheduler) UnscheduleTask(taskMethod string) error {
	ts.mu.RLock()
	jobTag, exists := ts.taskTags[taskMethod]
	ts.mu.RUnlock()

	if !exists {
		zlog.Warn("任务未找到，无法卸载", "taskMethod", taskMethod)
		return fmt.Errorf("任务 %s 未找到", taskMethod)
	}

	// 通过标签移除任务
	err := ts.Scheduler.RemoveByTag(jobTag)
	if err != nil {
		zlog.Error("卸载任务失败", "taskMethod", taskMethod, "error", err.Error())
		return fmt.Errorf("卸载任务 %s 失败: %w", taskMethod, err)
	}

	// 从映射中移除
	ts.mu.Lock()
	delete(ts.taskTags, taskMethod)
	ts.mu.Unlock()

	zlog.Info("任务卸载成功", "taskMethod", taskMethod)
	return nil
}

// RescheduleTask 重新调度任务（先卸载再加载）
func (ts *TaskScheduler) RescheduleTask(unit string, interval int, at string, taskMethod string, taskDaysOfTheWeek string) error {
	// 先尝试卸载旧任务（如果存在）
	ts.mu.RLock()
	_, exists := ts.taskTags[taskMethod]
	ts.mu.RUnlock()

	if exists {
		if err := ts.UnscheduleTask(taskMethod); err != nil {
			zlog.Warn("卸载旧任务时出错，继续重新调度", "taskMethod", taskMethod, "error", err.Error())
		}
	}

	// 重新调度任务
	if err := ts.ScheduleTask(unit, interval, at, taskMethod, taskDaysOfTheWeek); err != nil {
		return fmt.Errorf("重新调度任务失败: %w", err)
	}

	zlog.Info("任务重新调度成功", "taskMethod", taskMethod, "unit", unit, "interval", interval, "at", at)
	return nil
}
