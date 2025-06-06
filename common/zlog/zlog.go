package zlog

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
)

// 简单封装一下对 zap 日志库的使用
// 使用方式：
// zlog.Debug("hello", zap.String("name", "Kevin"), zap.Any("arbitraryObj", dummyObject))
// zlog.Info("hello", zap.String("name", "Kevin"), zap.Any("arbitraryObj", dummyObject))
// zlog.Warn("hello", zap.String("name", "Kevin"), zap.Any("arbitraryObj", dummyObject))
var logger *zap.Logger

// InitZLog 初始化zlog
func InitZLog(debugEnable bool, outputFormat string) {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	var encoder zapcore.Encoder
	if outputFormat == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else { // 默认使用控制台格式
		consoleConfig := zap.NewDevelopmentEncoderConfig()
		consoleConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		consoleConfig.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05.000")
		encoder = zapcore.NewConsoleEncoder(consoleConfig)
	}
	fileWriteSyncer := getFileLogWriter()

	if debugEnable == true {
		core := zapcore.NewTee(
			// 调试默认
			zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), zapcore.DebugLevel),
			zapcore.NewCore(encoder, fileWriteSyncer, zapcore.DebugLevel),
		)
		logger = zap.New(core)
	} else {
		core := zapcore.NewTee(
			zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), zapcore.InfoLevel),
			zapcore.NewCore(encoder, fileWriteSyncer, zapcore.InfoLevel),
			zapcore.NewCore(encoder, fileWriteSyncer, zapcore.ErrorLevel),
			zapcore.NewCore(encoder, fileWriteSyncer, zapcore.FatalLevel),
		)
		logger = zap.New(core)
	}

}

func getFileLogWriter() (writeSyncer zapcore.WriteSyncer) {
	exeDir := ""
	// 检测环境变量是否存在
	envVar := "SamWafIDE"
	if _, exists := os.LookupEnv(envVar); exists {
		exeDir = "."
	} else {
		exePath, err := os.Executable()
		if err != nil {
			fmt.Printf("Samwaf GetCurrent Exe Error: %v\n", err)
			// 使用当前工作目录作为备选方案
			if wd, wdErr := os.Getwd(); wdErr == nil {
				exeDir = wd
			} else {
				exeDir = "."
			}
		} else {
			exeDir = filepath.Dir(exePath)
		}
	}

	// 确保logs目录存在
	logDir := filepath.Join(exeDir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Samwaf Log Create logs error: %v\n", err)
		// 如果无法创建目录，使用临时目录
		logDir = os.TempDir()
	}

	logFile := filepath.Join(logDir, "log.log")
	fmt.Printf("Samwaf Log Path: %s\n", logFile)

	// 使用 lumberjack 实现 log rotate
	lumberJackLogger := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    100,
		MaxBackups: 60,
		MaxAge:     1,
		Compress:   false,
	}

	return zapcore.AddSync(lumberJackLogger)
}

func InfoCall(message string, fields ...zap.Field) {
	callerFields := getCallerInfoForLog()
	fields = append(fields, callerFields...)
	logger.Info(message, fields...)
}

func Info(message string, inter ...interface{}) {
	fields := append([]zap.Field{zap.String("pid", strconv.Itoa(os.Getpid()))}, zap.Any("info", inter))
	logger.Info(message, fields...)
}

func DebugCall(message string, fields ...zap.Field) {
	callerFields := getCallerInfoForLog()
	fields = append(fields, callerFields...)
	logger.Debug(message, fields...)
}
func Debug(message string, inter ...interface{}) {
	fields := append([]zap.Field{zap.String("pid", strconv.Itoa(os.Getpid()))}, zap.Any("debug", inter))
	logger.Debug(message, fields...)
}

func ErrorCall(message string, fields ...zap.Field) {
	callerFields := getCallerInfoForLog()
	fields = append(fields, callerFields...)
	logger.Error(message, fields...)
}
func Error(message string, inter ...interface{}) {
	fields := append([]zap.Field{zap.String("pid", strconv.Itoa(os.Getpid()))}, zap.Any("err", inter))

	logger.Error(message, fields...)
}

func WarnCall(message string, fields ...zap.Field) {
	callerFields := getCallerInfoForLog()
	fields = append(fields, callerFields...)
	logger.Warn(message, fields...)
}
func Warn(message string, inter ...interface{}) {
	fields := append([]zap.Field{zap.String("pid", strconv.Itoa(os.Getpid()))}, zap.Any("warn", inter))
	logger.Warn(message, fields...)
}

func getCallerInfoForLog() (callerFields []zap.Field) {

	pc, file, line, ok := runtime.Caller(2) // 回溯两层，拿到写日志的业务函数的信息
	if !ok {
		return
	}
	funcName := runtime.FuncForPC(pc).Name()
	funcName = path.Base(funcName) //Base函数返回路径的最后一个元素，只保留函数名

	callerFields = append(callerFields, zap.String("func", funcName), zap.String("file", file), zap.Int("line", line))
	return
}
