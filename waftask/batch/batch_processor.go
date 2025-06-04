package batch

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
)

// BatchProcessor 批量处理器接口
type BatchProcessor interface {
	// ProcessItem 处理单个项目
	ProcessBatch(items []string, task model.BatchTask, progress *BatchProgress) bool
	// GetExistingItems 获取已存在的项目
	GetExistingItems(items []string, task model.BatchTask, config interface{}) map[string]interface{}
	// NotifyEngine 通知引擎更新
	NotifyEngine(task model.BatchTask)
}

// BatchProcessorConfig 批量处理器配置
type BatchProcessorConfig struct {
	BatchSize int    // 批处理大小
	LogPrefix string // 日志前缀
}

// BatchProgress 批处理进度
type BatchProgress struct {
	TotalItems     int32 // 总项目数
	ProcessedItems int32 // 已处理项目数
	InsertedItems  int32 // 已插入项目数
	UpdatedItems   int32 // 已更新项目数
}

// AddProcessed 增加已处理数量
func (p *BatchProgress) AddProcessed(count int) {
	atomic.AddInt32(&p.ProcessedItems, int32(count))
}

// AddInserted 增加已插入数量
func (p *BatchProgress) AddInserted(count int) {
	atomic.AddInt32(&p.InsertedItems, int32(count))
}

// AddUpdated 增加已更新数量
func (p *BatchProgress) AddUpdated(count int) {
	atomic.AddInt32(&p.UpdatedItems, int32(count))
}

// GetProgress 获取进度百分比
func (p *BatchProgress) GetProgress() float64 {
	if p.TotalItems == 0 {
		return 100.0
	}
	return float64(p.ProcessedItems) / float64(p.TotalItems) * 100.0
}

// ProcessBatchTask 通用批量处理函数
func ProcessBatchTask(task model.BatchTask, processor BatchProcessor, config BatchProcessorConfig) {
	innerLogName := config.LogPrefix

	contentReader, err := openSource(task)
	if err != nil {
		zlog.Error(innerLogName, err.Error())
		return
	}
	defer contentReader.Close()

	// 判断数据库是否已经关闭
	if global.GWAF_LOCAL_DB == nil {
		zlog.Error(innerLogName, "数据库已经关闭批量处理终止")
		return
	}

	// 获取对应类型的提取器
	extractor := GetExtractor(task.BatchType)

	// 首先计算总行数，用于进度显示
	totalLines, validLines, err := countLinesWithExtractor(task, extractor)
	if err != nil {
		zlog.Error(innerLogName, fmt.Sprintf("计算总行数失败: %s", err.Error()))
		// 继续执行，但无法显示准确进度
	}

	// 创建进度跟踪器
	progress := &BatchProgress{
		TotalItems: int32(validLines),
	}

	zlog.Info(innerLogName, fmt.Sprintf("开始批量处理，总行数: %d，有效行数: %d", totalLines, validLines))

	// 收集有效的项目
	validItems := make([]string, 0, config.BatchSize)
	scanner := bufio.NewScanner(contentReader)
	hasAffectInfo := false

	// 按批次处理
	batchCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue // 跳过空行
		}

		// 使用特定类型的提取器
		item := extractor.ExtractItem(line)
		if !extractor.ValidateItem(item) {
			continue
		}

		validItems = append(validItems, item)
		batchCount++

		// 当收集到一批或者是最后一批时，进行批量处理
		if batchCount >= config.BatchSize {
			// 处理当前批次
			if processor.ProcessBatch(validItems, task, progress) {
				hasAffectInfo = true
			}

			// 记录进度
			progress.AddProcessed(len(validItems))
			zlog.Info(innerLogName, fmt.Sprintf("进度: %.2f%% (%d/%d)，已插入: %d，已更新: %d",
				progress.GetProgress(), progress.ProcessedItems, progress.TotalItems,
				progress.InsertedItems, progress.UpdatedItems))

			// 重置批次
			validItems = make([]string, 0, config.BatchSize)
			batchCount = 0
		}
	}

	// 处理最后一批不足BatchSize的项目
	if len(validItems) > 0 {
		if processor.ProcessBatch(validItems, task, progress) {
			hasAffectInfo = true
		}

		// 记录进度
		progress.AddProcessed(len(validItems))
		zlog.Info(innerLogName, fmt.Sprintf("进度: %.2f%% (%d/%d)，已插入: %d，已更新: %d",
			progress.GetProgress(), progress.ProcessedItems, progress.TotalItems,
			progress.InsertedItems, progress.UpdatedItems))
	}

	if hasAffectInfo {
		// 通知引擎进行实时生效
		processor.NotifyEngine(task)
	}

	// 输出最终处理结果
	zlog.Info(innerLogName, fmt.Sprintf("批量处理完成，总计处理: %d，插入: %d，更新: %d",
		progress.ProcessedItems, progress.InsertedItems, progress.UpdatedItems))

	// 检查扫描错误
	if err := scanner.Err(); err != nil {
		zlog.Error(innerLogName, fmt.Sprintf("扫描文件时发生错误: %s", err.Error()))
	}
}

// countLinesWithExtractor 使用提取器计算文件总行数和有效行数
func countLinesWithExtractor(task model.BatchTask, extractor ItemExtractor) (int, int, error) {
	contentReader, err := openSource(task)
	if err != nil {
		return 0, 0, err
	}
	defer contentReader.Close()

	scanner := bufio.NewScanner(contentReader)
	totalLines := 0
	validLines := 0

	for scanner.Scan() {
		line := scanner.Text()
		totalLines++

		line = strings.TrimSpace(line)
		if line == "" {
			continue // 跳过空行
		}

		item := extractor.ExtractItem(line)
		if extractor.ValidateItem(item) {
			validLines++
		}
	}

	return totalLines, validLines, scanner.Err()
}

// openSource 打开本地或远程数据源
func openSource(task model.BatchTask) (io.ReadCloser, error) {
	if task.BatchSourceType == "local" {
		f, err := os.Open(task.BatchSource)
		if err != nil {
			return nil, fmt.Errorf("failed to open local file: %v", err)
		}
		return f, nil
	}
	// remote
	resp, err := http.Get(task.BatchSource)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch remote data: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// extractIPFromLine 使用正则表达式从行中提取IP地址或网段
func extractIPFromLine(line string) string {
	// 匹配IPv4地址或IPv4网段
	ipv4Regex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)

	// 匹配IPv6地址或IPv6网段 (简化版本)
	ipv6Regex := regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?:/\d{1,3})?\b`)

	// 先尝试匹配IPv4
	if match := ipv4Regex.FindString(line); match != "" {
		return match
	}

	// 再尝试匹配IPv6
	if match := ipv6Regex.FindString(line); match != "" {
		return match
	}

	return line // 如果没有匹配到，返回原始行
}
