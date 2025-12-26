package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger 插件日志记录器
type Logger struct {
	logger     *log.Logger
	logFile    *lumberjack.Logger
	pluginName string
	mu         sync.Mutex
}

var (
	globalLoggers = make(map[string]*Logger)
	loggerMu      sync.RWMutex
)

// NewLogger 创建新的日志记录器
// pluginName: 插件名称（用于日志标识）
// logDir: 日志目录
// pluginID: 插件ID（用于日志文件名）
func NewLogger(pluginName string, logDir string, pluginID string) (*Logger, error) {
	// 检查是否已存在
	loggerMu.RLock()
	if existingLogger, exists := globalLoggers[pluginID]; exists {
		loggerMu.RUnlock()
		return existingLogger, nil
	}
	loggerMu.RUnlock()

	// 确保日志目录存在
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %w", err)
	}

	// 日志文件名：pluginID.log
	logFileName := fmt.Sprintf("%s.log", pluginID)
	logFilePath := filepath.Join(logDir, logFileName)

	// 配置 lumberjack 日志轮转
	lumberJackLogger := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    50,   // 每个日志文件最大 50MB
		MaxBackups: 10,   // 保留 10 个备份
		MaxAge:     7,    // 保留 7 天
		Compress:   true, // 压缩旧日志
	}

	// 创建多写入器：同时写入文件和标准输出
	multiWriter := io.MultiWriter(os.Stdout, lumberJackLogger)

	// 创建 logger
	logger := log.New(multiWriter, "", 0)

	pluginLogger := &Logger{
		logger:     logger,
		logFile:    lumberJackLogger,
		pluginName: pluginName,
	}

	// 缓存日志实例
	loggerMu.Lock()
	globalLoggers[pluginID] = pluginLogger
	loggerMu.Unlock()

	pluginLogger.Info("插件日志系统初始化成功", "log_file", logFilePath)

	return pluginLogger, nil
}

// GetLogger 获取已存在的日志实例
func GetLogger(pluginID string) (*Logger, bool) {
	loggerMu.RLock()
	defer loggerMu.RUnlock()

	logger, exists := globalLoggers[pluginID]
	return logger, exists
}

// formatMessage 格式化日志消息
func (l *Logger) formatMessage(level string, msg string, keysAndValues ...interface{}) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	message := fmt.Sprintf("[%s] [%s] [%s] %s", timestamp, level, l.pluginName, msg)

	// 添加额外的字段
	if len(keysAndValues) > 0 {
		for i := 0; i < len(keysAndValues); i += 2 {
			if i+1 < len(keysAndValues) {
				message += fmt.Sprintf(" %v=%v", keysAndValues[i], keysAndValues[i+1])
			}
		}
	}

	return message
}

// Debug 调试日志
func (l *Logger) Debug(msg string, keysAndValues ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	message := l.formatMessage("DEBUG", msg, keysAndValues...)
	l.logger.Println(message)
}

// Info 信息日志
func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	message := l.formatMessage("INFO", msg, keysAndValues...)
	l.logger.Println(message)
}

// Warn 警告日志
func (l *Logger) Warn(msg string, keysAndValues ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	message := l.formatMessage("WARN", msg, keysAndValues...)
	l.logger.Println(message)
}

// Error 错误日志
func (l *Logger) Error(msg string, keysAndValues ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	message := l.formatMessage("ERROR", msg, keysAndValues...)
	l.logger.Println(message)
}

// Fatal 致命错误日志
func (l *Logger) Fatal(msg string, keysAndValues ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	message := l.formatMessage("FATAL", msg, keysAndValues...)
	l.logger.Println(message)
}

// Close 关闭日志
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// CloseAll 关闭所有日志实例
func CloseAll() error {
	loggerMu.Lock()
	defer loggerMu.Unlock()

	var lastErr error
	for id, logger := range globalLoggers {
		if err := logger.Close(); err != nil {
			lastErr = err
		}
		delete(globalLoggers, id)
	}

	return lastErr
}

// GetAllLoggers 获取所有日志实例（用于调试）
func GetAllLoggers() map[string]*Logger {
	loggerMu.RLock()
	defer loggerMu.RUnlock()

	result := make(map[string]*Logger, len(globalLoggers))
	for k, v := range globalLoggers {
		result[k] = v
	}
	return result
}
