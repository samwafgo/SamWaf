package wafdb

import (
	"SamWaf/common/zlog"
	"context"
	"fmt"
	"time"

	"gorm.io/gorm/logger"
)

// GormZLogger 是一个实现了 gorm.Logger 接口的自定义日志记录器
type GormZLogger struct {
	SlowThreshold        time.Duration
	IgnoreRecordNotFound bool
	LogLevel             logger.LogLevel
	ParameterizedQueries bool
}

// NewGormZLogger 创建一个新的 GormZLogger 实例
func NewGormZLogger() *GormZLogger {
	return &GormZLogger{
		SlowThreshold:        time.Second, // 慢查询阈值
		LogLevel:             logger.Info, // 默认日志级别
		IgnoreRecordNotFound: true,        // 忽略记录未找到错误
	}
}

// LogMode 设置日志级别
func (l *GormZLogger) LogMode(level logger.LogLevel) logger.Interface {
	newLogger := *l
	newLogger.LogLevel = level
	return &newLogger
}

// Info 打印信息日志
func (l *GormZLogger) Info(ctx context.Context, msg string, data ...interface{}) {
	if l.LogLevel >= logger.Info {
		zlog.Info(fmt.Sprintf(msg, data...))
	}
}

// Warn 打印警告日志
func (l *GormZLogger) Warn(ctx context.Context, msg string, data ...interface{}) {
	if l.LogLevel >= logger.Warn {
		zlog.Warn(fmt.Sprintf(msg, data...))
	}
}

// Error 打印错误日志
func (l *GormZLogger) Error(ctx context.Context, msg string, data ...interface{}) {
	if l.LogLevel >= logger.Error {
		zlog.Error(fmt.Sprintf(msg, data...))
	}
}

// Trace 记录 SQL 执行情况
func (l *GormZLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if l.LogLevel <= logger.Silent {
		return
	}

	elapsed := time.Since(begin)
	sql, rows := fc()

	// 构建日志消息，简化格式使其更加整洁
	logMsg := fmt.Sprintf("SQL执行 [%.3fms] [rows:%v] %s", float64(elapsed.Nanoseconds())/1e6, rows, sql)

	// 根据不同情况记录不同级别的日志
	switch {
	case err != nil && l.LogLevel >= logger.Error && (!l.IgnoreRecordNotFound || !isRecordNotFoundError(err)):
		zlog.Error(fmt.Sprintf("SQL错误 %v %s", err, logMsg))
	case elapsed > l.SlowThreshold && l.SlowThreshold != 0 && l.LogLevel >= logger.Warn:
		zlog.Warn(fmt.Sprintf("慢SQL %s", logMsg))
	case l.LogLevel >= logger.Info:
		zlog.Debug(logMsg)
	}
}

// isRecordNotFoundError 检查错误是否为记录未找到错误
func isRecordNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "record not found"
}
