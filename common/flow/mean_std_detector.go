package flow

import (
	"fmt"
	"math"
)

// AnomalyHandler 异常处理回调函数类型
type AnomalyHandler func(result *DetectionResult)

// AnomalyAction 异常处理动作类型
type AnomalyAction int

const (
	ActionLog    AnomalyAction = iota // 记录日志
	ActionAlert                       // 发送告警
	ActionBlock                       // 阻断流量
	ActionLimit                       // 限制流量
	ActionCustom                      // 自定义处理
)

// AnomalyProcessor 异常处理器
type AnomalyProcessor struct {
	Action  AnomalyAction
	Handler AnomalyHandler
	Enabled bool
	Name    string
	// 新增恢复处理器
	RecoveryHandler AnomalyHandler
}

// 常量定义
const (
	// MinWindowSize 最小窗口大小
	MinWindowSize = 2
	// InvalidThreshold 无效阈值标识
	InvalidThreshold = -1
)

// DetectionResult 异常检测结果
type DetectionResult struct {
	IsAnomaly    bool      // 是否异常
	CurrentValue float64   // 当前值
	Mean         float64   // 均值
	StdDev       float64   // 标准差
	Threshold    float64   // 异常阈值 (k * 标准差)
	Deviation    float64   // 偏离度 (当前值与均值的差)
	WindowData   []float64 // 当前窗口数据
	WindowSize   int       // 窗口大小
	Confidence   string    // 置信度描述
	// 新增恢复相关字段
	IsRecovered   bool // 是否从异常状态恢复
	RecoveryCount int  // 连续正常计数
}

// String 返回检测结果的字符串表示
func (r *DetectionResult) String() string {
	if !r.IsAnomaly {
		return fmt.Sprintf("正常值: %.2f (均值: %.2f, 标准差: %.2f)",
			r.CurrentValue, r.Mean, r.StdDev)
	}
	return fmt.Sprintf("异常值: %.2f (均值: %.2f, 偏离: %.2f, 阈值: %.2f, %s)",
		r.CurrentValue, r.Mean, r.Deviation, r.Threshold, r.Confidence)
}

// MeanStdDetector 滑动窗口均值标准差异常检测器
type MeanStdDetector struct {
	window     []float64          // 滑动窗口数据
	size       int                // 窗口大小
	k          float64            // 异常检测系数(通常取2-3)
	sum        float64            // 窗口数据总和(优化计算)
	sumSq      float64            // 窗口数据平方和(优化计算)
	processors []AnomalyProcessor // 异常处理器列表
	// 新增恢复相关字段
	isInAnomalyState  bool // 当前是否处于异常状态
	normalCount       int  // 连续正常值计数
	recoveryThreshold int  // 恢复需要的连续正常值数量
}

// NewMeanStdDetector 创建新的异常检测器
// size: 滑动窗口大小，建议10-50
// k: 异常检测系数，k=2(95%置信度), k=3(99.7%置信度)
func NewMeanStdDetector(size int, k float64) *MeanStdDetector {
	if size < MinWindowSize {
		size = MinWindowSize
	}
	if k <= 0 {
		k = 2.0 // 默认2倍标准差
	}
	return &MeanStdDetector{
		size:              size,
		k:                 k,
		recoveryThreshold: 5, // 默认需要5个连续正常值才认为恢复
	}
}

// AddValue 添加新的数据点到滑动窗口
func (d *MeanStdDetector) AddValue(value float64) {
	// 如果窗口已满，移除最旧的数据
	if len(d.window) >= d.size {
		old := d.window[0]
		d.window = d.window[1:]
		d.sum -= old
		d.sumSq -= old * old
	}

	// 添加新数据
	d.window = append(d.window, value)
	d.sum += value
	d.sumSq += value * value
}

// IsAnomaly 简单的异常检测，只返回是否异常
func (d *MeanStdDetector) IsAnomaly(value float64) bool {
	return d.DetectAnomaly(value).IsAnomaly
}

// DetectAnomaly 完整的异常检测，返回详细结果
func (d *MeanStdDetector) DetectAnomaly(value float64) *DetectionResult {
	result := &DetectionResult{
		CurrentValue: value,
		WindowSize:   len(d.window),
	}

	// 窗口数据不足，无法检测
	if len(d.window) < MinWindowSize {
		result.IsAnomaly = false
		result.Threshold = InvalidThreshold
		result.Confidence = "数据不足"
		return result
	}

	// 计算统计指标
	n := float64(len(d.window))
	mean := d.sum / n
	variance := (d.sumSq - (d.sum*d.sum)/n) / n
	stdDev := math.Sqrt(math.Max(variance, 0))
	threshold := d.k * stdDev
	deviation := math.Abs(value - mean)

	// 填充结果
	result.Mean = mean
	result.StdDev = stdDev
	result.Threshold = threshold
	result.Deviation = deviation
	result.WindowData = make([]float64, len(d.window))
	copy(result.WindowData, d.window)

	// 判断是否异常
	isCurrentAnomaly := deviation > threshold
	result.IsAnomaly = isCurrentAnomaly

	// 恢复逻辑处理
	if !isCurrentAnomaly {
		// 当前值正常
		d.normalCount++
		result.RecoveryCount = d.normalCount

		// 检查是否从异常状态恢复
		if d.isInAnomalyState && d.normalCount >= d.recoveryThreshold {
			result.IsRecovered = true
			d.isInAnomalyState = false
			d.normalCount = 0 // 重置计数
		}
	} else {
		// 当前值异常
		d.isInAnomalyState = true
		d.normalCount = 0 // 重置正常计数
	}

	// 设置置信度描述
	if stdDev == 0 {
		if value == mean {
			result.Confidence = "完全正常"
		} else {
			result.IsAnomaly = true
			result.Confidence = "明显异常(零方差)"
		}
	} else {
		sigmaLevel := deviation / stdDev
		switch {
		case sigmaLevel > 3:
			result.Confidence = "高度异常(>3σ)"
		case sigmaLevel > 2:
			result.Confidence = "中度异常(>2σ)"
		case sigmaLevel > 1:
			result.Confidence = "轻微异常(>1σ)"
		default:
			result.Confidence = "正常范围"
		}
	}

	return result
}

// SetRecoveryThreshold 设置恢复阈值
func (d *MeanStdDetector) SetRecoveryThreshold(threshold int) {
	if threshold > 0 {
		d.recoveryThreshold = threshold
	}
}

// GetRecoveryStatus 获取恢复状态信息
func (d *MeanStdDetector) GetRecoveryStatus() map[string]interface{} {
	return map[string]interface{}{
		"is_in_anomaly_state": d.isInAnomalyState,
		"normal_count":        d.normalCount,
		"recovery_threshold":  d.recoveryThreshold,
		"recovery_progress":   float64(d.normalCount) / float64(d.recoveryThreshold),
	}
}

// GetWindowStats 获取当前窗口的统计信息
func (d *MeanStdDetector) GetWindowStats() map[string]interface{} {
	if len(d.window) == 0 {
		return map[string]interface{}{
			"window_size": 0,
			"mean":        0,
			"std_dev":     0,
			"min":         0,
			"max":         0,
		}
	}

	n := float64(len(d.window))
	mean := d.sum / n
	variance := (d.sumSq - (d.sum*d.sum)/n) / n
	stdDev := math.Sqrt(math.Max(variance, 0))

	// 计算最小值和最大值
	min, max := d.window[0], d.window[0]
	for _, v := range d.window[1:] {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	return map[string]interface{}{
		"window_size": len(d.window),
		"mean":        mean,
		"std_dev":     stdDev,
		"min":         min,
		"max":         max,
		"threshold":   d.k * stdDev,
		"k_factor":    d.k,
	}
}

// Reset 重置检测器
func (d *MeanStdDetector) Reset() {
	d.window = nil
	d.sum = 0
	d.sumSq = 0
}

// 保持向后兼容的方法

// Add 添加数据点(向后兼容)
func (d *MeanStdDetector) Add(value float64) {
	d.AddValue(value)
}

// IsAnomalyPrintValue 返回异常状态和阈值(向后兼容)
func (d *MeanStdDetector) IsAnomalyPrintValue(value float64) (bool, float64) {
	result := d.DetectAnomaly(value)
	if result.Threshold == InvalidThreshold {
		return false, InvalidThreshold
	}
	return result.IsAnomaly, result.Threshold
}

// IsAnomalyPrintFull 返回异常状态和窗口数据(向后兼容)
func (d *MeanStdDetector) IsAnomalyPrintFull(value float64) (bool, []float64) {
	result := d.DetectAnomaly(value)
	return result.IsAnomaly, result.WindowData
}

// AddAnomalyProcessor 添加异常处理器
func (d *MeanStdDetector) AddAnomalyProcessor(processor AnomalyProcessor) {
	d.processors = append(d.processors, processor)
}

// RemoveAnomalyProcessor 移除异常处理器
func (d *MeanStdDetector) RemoveAnomalyProcessor(name string) {
	for i, processor := range d.processors {
		if processor.Name == name {
			d.processors = append(d.processors[:i], d.processors[i+1:]...)
			break
		}
	}
}

// processAnomaly 处理异常情况
func (d *MeanStdDetector) processAnomaly(result *DetectionResult) {
	// 处理异常
	if result.IsAnomaly {
		// 执行所有启用的异常处理器
		for _, processor := range d.processors {
			if processor.Enabled && processor.Handler != nil {
				processor.Handler(result)
			}
		}
	}

	// 处理恢复
	if result.IsRecovered {
		// 执行恢复处理器
		for _, processor := range d.processors {
			if processor.Enabled && processor.RecoveryHandler != nil {
				processor.RecoveryHandler(result)
			}
		}
	}
}

// DetectAnomalyWithProcessing 检测异常并自动处理
func (d *MeanStdDetector) DetectAnomalyWithProcessing(value float64) *DetectionResult {
	result := d.DetectAnomaly(value)

	// 如果检测到异常，执行处理逻辑
	d.processAnomaly(result)

	return result
}

// 双窗口异常检测器
type DualWindowDetector struct {
	shortWindow *MeanStdDetector // 短期窗口(快速响应)
	longWindow  *MeanStdDetector // 长期窗口(稳定基线)

	// 状态管理
	sustainedHighCount int
	maxSustainedHigh   int

	// 异常处理器
	processors []AnomalyProcessor
}

func NewDualWindowDetector(shortSize, longSize int, k float64) *DualWindowDetector {
	return &DualWindowDetector{
		shortWindow:      NewMeanStdDetector(shortSize, k),
		longWindow:       NewMeanStdDetector(longSize, k),
		maxSustainedHigh: 20, // 最大持续高位次数
	}
}

// AddValue 向两个窗口添加数据
func (d *DualWindowDetector) AddValue(value float64) {
	d.shortWindow.AddValue(value)
	d.longWindow.AddValue(value)
}

// AddAnomalyProcessor 添加异常处理器
func (d *DualWindowDetector) AddAnomalyProcessor(processor AnomalyProcessor) {
	d.processors = append(d.processors, processor)
}

// SetSustainedHighThreshold 设置持续高位阈值
func (d *DualWindowDetector) SetSustainedHighThreshold(threshold int) {
	if threshold > 0 {
		d.maxSustainedHigh = threshold
	}
}

func (d *DualWindowDetector) DetectAnomaly(value float64) *DetectionResult {
	shortResult := d.shortWindow.DetectAnomaly(value)
	//longResult := d.longWindow.DetectAnomaly(value)

	// 获取统计信息
	shortStats := d.shortWindow.GetWindowStats()
	longStats := d.longWindow.GetWindowStats()

	shortMean := shortStats["mean"].(float64)
	longMean := longStats["mean"].(float64)

	// 检测持续高位状态
	if len(d.shortWindow.window) >= MinWindowSize && len(d.longWindow.window) >= MinWindowSize {
		if shortMean > longMean*1.5 { // 短期均值显著高于长期均值
			d.sustainedHighCount++
		} else {
			d.sustainedHighCount = 0
		}

		// 如果持续高位时间过长，发出警告
		if d.sustainedHighCount > d.maxSustainedHigh {
			shortResult.Confidence = fmt.Sprintf("持续高位运行警告(%d次)", d.sustainedHighCount)
			shortResult.IsAnomaly = true
			// 添加持续高位的特殊标记
			shortResult.Deviation = shortMean - longMean
		}
	}

	return shortResult
}

// DetectAnomalyWithProcessing 检测异常并自动处理
func (d *DualWindowDetector) DetectAnomalyWithProcessing(value float64) *DetectionResult {
	result := d.DetectAnomaly(value)

	// 执行异常处理器
	if result.IsAnomaly {
		for _, processor := range d.processors {
			if processor.Enabled && processor.Handler != nil {
				processor.Handler(result)
			}
		}
	}

	return result
}

// GetDualWindowStats 获取双窗口统计信息
func (d *DualWindowDetector) GetDualWindowStats() map[string]interface{} {
	shortStats := d.shortWindow.GetWindowStats()
	longStats := d.longWindow.GetWindowStats()

	return map[string]interface{}{
		"short_window":         shortStats,
		"long_window":          longStats,
		"sustained_high_count": d.sustainedHighCount,
		"max_sustained_high":   d.maxSustainedHigh,
		"short_mean":           shortStats["mean"],
		"long_mean":            longStats["mean"],
	}
}

// Reset 重置双窗口检测器
func (d *DualWindowDetector) Reset() {
	d.shortWindow.Reset()
	d.longWindow.Reset()
	d.sustainedHighCount = 0
}
