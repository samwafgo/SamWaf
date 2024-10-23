package wafnotify

import (
	"SamWaf/common/zlog"
	"SamWaf/innerbean"
	"SamWaf/wafinterface"
	"fmt"
)

type WafNotifyService struct {
	notifier wafinterface.WafNotify
	enable   int64
	isStart  int64
}

// 初始化 NotifyService
func NewWafNotifyService(notifier wafinterface.WafNotify, enable int64) *WafNotifyService {
	return &WafNotifyService{notifier: notifier, enable: enable}
}

// 改激活状态
func (ls *WafNotifyService) ChangeEnable(enable int64) {
	if ls == nil {
		return
	}
	ls.enable = enable
}

// 处理并发送单条日志
func (ls *WafNotifyService) ProcessSingleLog(log innerbean.WebLog) error {
	if ls.enable == 0 {
		return nil
	}
	if ls.notifier == nil {
		zlog.Debug("not init kafka")
		return nil
	}

	// 日志处理逻辑
	zlog.Debug("Processing single log...")

	// 通知处理
	if err := ls.notifier.NotifySingle(log); err != nil {
		return fmt.Errorf("failed to notify single log: %v", err)
	}
	return nil
}

// 处理并发送多条日志
func (ls *WafNotifyService) ProcessBatchLogs(logs []innerbean.WebLog) error {
	if ls.enable == 0 {
		zlog.Debug("kafka没有开启")
		return nil
	}
	// 日志处理逻辑
	zlog.Debug("Processing batch logs...")

	// 通知处理
	if err := ls.notifier.NotifyBatch(logs); err != nil {
		return fmt.Errorf("failed to notify batch logs: %v", err)
	}
	return nil
}
