package waftask

import (
	"SamWaf/common/zlog"
	"fmt"
	"runtime/debug"
	"sync"
)

// TaskFunc 定义任务执行的函数类型
type TaskFunc func()

// TaskRegistry 用于管理所有的任务方法
type TaskRegistry struct {
	Tasks   map[string]TaskFunc
	mutexes map[string]*sync.Mutex // 每个任务分配一个独立的锁
}

// NewTaskRegistry 创建新的任务注册器
func NewTaskRegistry() *TaskRegistry {
	return &TaskRegistry{
		Tasks:   make(map[string]TaskFunc),
		mutexes: make(map[string]*sync.Mutex),
	}
}

// RegisterTask 注册一个任务方法
func (tr *TaskRegistry) RegisterTask(taskName string, taskFunc TaskFunc) {
	if _, exists := tr.Tasks[taskName]; exists {
		zlog.Error("TaskRegistry 任务方法 '" + taskName + "' 已存在")
	} else {
		tr.Tasks[taskName] = taskFunc
		tr.mutexes[taskName] = &sync.Mutex{} // 为每个任务分配一个独立的锁
	}
}

// ExecuteTask 根据标识符执行对应的任务方法
func (tr *TaskRegistry) ExecuteTask(taskName string) {
	innerName := "TaskRegistry ExecuteTask"
	if taskFunc, exists := tr.Tasks[taskName]; exists {

		go func() {
			zlog.Debug("正在执行任务", taskName)
			// 获取当前任务的锁
			taskMutex, exists := tr.mutexes[taskName]
			if !exists {
				zlog.Error(fmt.Sprintf("%s 任务方法 '%s' 未注册", innerName, taskName))
				return
			}

			// 如果任务锁正在占用，输出提示
			if !taskMutex.TryLock() { // 如果锁已经被占用
				zlog.Error(fmt.Sprintf("%s 任务方法 '%s' 正在执行 跳过当前执行", innerName, taskName))
				return
			}
			defer taskMutex.Unlock() // 确保任务完成后释放锁
			// 捕获任务执行中的异常并打印详细信息
			defer func() {
				if err := recover(); err != nil {
					// 处理异常，打印错误详情
					zlog.Error(fmt.Sprintf("任务 '%s' 执行出错: %v 调试信息:%s", taskName, err, debug.Stack()))
					debug.PrintStack()
				}
			}()
			taskFunc()
		}()
	} else {
		zlog.Error(fmt.Sprintf("%s 任务方法 '%s'  未找到", innerName, taskName))
	}
}

// GetTask 根据任务名称获取任务方法
// 如果任务存在，返回任务函数；如果任务不存在，返回nil和错误信息
func (tr *TaskRegistry) GetTask(taskName string) (TaskFunc, error) {
	if taskFunc, exists := tr.Tasks[taskName]; exists {
		return taskFunc, nil
	} else {
		return nil, fmt.Errorf("任务方法 '%s' 未找到", taskName)
	}
}
