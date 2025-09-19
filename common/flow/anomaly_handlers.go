package flow

import (
	"SamWaf/common/zlog"
	"fmt"
	"strings"
	"time"
)

// LogAnomalyHandler 日志记录处理器 - 使用zlog
func LogAnomalyHandler(result *DetectionResult) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// 使用zlog记录日志
	zlog.Info("流量异常检测告警", map[string]interface{}{
		"timestamp":     timestamp,
		"current_value": result.CurrentValue,
		"mean":          result.Mean,
		"deviation":     result.Deviation,
		"threshold":     result.Threshold,
		"confidence":    result.Confidence,
		"is_anomaly":    result.IsAnomaly,
		"window_size":   result.WindowSize,
		"detail":        result.String(),
	})
}

// AlertAnomalyHandler 告警处理器 - 使用zlog
func AlertAnomalyHandler(result *DetectionResult) {
	// 使用zlog记录告警信息
	zlog.Warn("流量异常告警", map[string]interface{}{
		"alert_type":    "traffic_anomaly",
		"current_value": result.CurrentValue,
		"mean":          result.Mean,
		"deviation":     result.Deviation,
		"confidence":    result.Confidence,
		"severity":      getSeverityLevel(result),
	})

	fmt.Printf("🚨 异常告警: %s\n", result.String())

	// 示例：发送到告警通道
	alertMsg := fmt.Sprintf("检测到流量异常！当前值: %.2f, 均值: %.2f, 偏离度: %.2f, 置信度: %s",
		result.CurrentValue, result.Mean, result.Deviation, result.Confidence)

	// 这里可以调用实际的告警接口
	sendAlert(alertMsg)
}

// BlockAnomalyHandler 阻断处理器 - 使用zlog
func BlockAnomalyHandler(result *DetectionResult) {
	if result.Deviation > result.Threshold*2 { // 严重异常才阻断
		// 使用zlog记录阻断操作
		zlog.Error("严重异常流量阻断", map[string]interface{}{
			"action":        "block_traffic",
			"current_value": result.CurrentValue,
			"deviation":     result.Deviation,
			"threshold":     result.Threshold,
			"severity":      "critical",
			"reason":        "deviation_exceeds_2x_threshold",
		})

		fmt.Printf("🛑 严重异常，执行阻断: %s\n", result.String())
		// 这里可以调用防火墙或限流接口
		blockTraffic(result)
	}
}

// LimitAnomalyHandler 限流处理器 - 使用zlog
func LimitAnomalyHandler(result *DetectionResult) {
	if result.IsAnomaly {
		// 使用zlog记录限流操作
		zlog.Warn("异常流量限流", map[string]interface{}{
			"action":        "limit_traffic",
			"current_value": result.CurrentValue,
			"mean":          result.Mean,
			"deviation":     result.Deviation,
			"severity":      getSeverityLevel(result),
		})

		fmt.Printf("⚠️ 异常流量，启动限流: %s\n", result.String())
		// 这里可以调用限流接口
		limitTraffic(result)
	}
}

// CustomAnomalyHandler 自定义处理器示例 - 使用zlog
func CustomAnomalyHandler(result *DetectionResult) {
	// 根据异常程度执行不同处理
	switch {
	case result.Deviation > result.Threshold*3:
		// 极严重异常：立即阻断+告警
		zlog.Error("极严重流量异常", map[string]interface{}{
			"action":          "immediate_block_and_alert",
			"current_value":   result.CurrentValue,
			"deviation_ratio": result.Deviation / result.Threshold,
			"severity":        "critical",
			"auto_action":     true,
		})

		fmt.Printf("🔥 极严重异常，立即处理: %s\n", result.String())
		blockTraffic(result)
		sendAlert(fmt.Sprintf("极严重流量异常: %.2f", result.CurrentValue))

	case result.Deviation > result.Threshold*2:
		// 严重异常：限流+告警
		zlog.Warn("严重流量异常", map[string]interface{}{
			"action":          "limit_and_alert",
			"current_value":   result.CurrentValue,
			"deviation_ratio": result.Deviation / result.Threshold,
			"severity":        "high",
		})

		fmt.Printf("⚡ 严重异常，限流处理: %s\n", result.String())
		limitTraffic(result)
		sendAlert(fmt.Sprintf("严重流量异常: %.2f", result.CurrentValue))

	default:
		// 一般异常：仅记录
		zlog.Info("一般流量异常", map[string]interface{}{
			"action":          "log_only",
			"current_value":   result.CurrentValue,
			"deviation_ratio": result.Deviation / result.Threshold,
			"severity":        "medium",
		})

		fmt.Printf("📝 一般异常，记录日志: %s\n", result.String())
		LogAnomalyHandler(result)
	}
}

// getSeverityLevel 获取异常严重程度
func getSeverityLevel(result *DetectionResult) string {
	if result.Threshold == 0 {
		return "unknown"
	}

	ratio := result.Deviation / result.Threshold
	switch {
	case ratio > 3:
		return "critical"
	case ratio > 2:
		return "high"
	case ratio > 1:
		return "medium"
	default:
		return "low"
	}
}

// 辅助函数（需要根据实际系统实现）
func sendAlert(message string) {
	// 实现告警发送逻辑
	zlog.Info("发送告警", map[string]interface{}{
		"alert_message": message,
		"alert_type":    "traffic_anomaly",
	})
}

func blockTraffic(result *DetectionResult) {
	// 实现流量阻断逻辑
	zlog.Error("执行流量阻断", map[string]interface{}{
		"blocked_value": result.CurrentValue,
		"reason":        "anomaly_detection",
		"action_taken":  "traffic_blocked",
	})
}

func limitTraffic(result *DetectionResult) {
	// 实现流量限制逻辑
	zlog.Warn("执行流量限制", map[string]interface{}{
		"limited_value": result.CurrentValue,
		"reason":        "anomaly_detection",
		"action_taken":  "traffic_limited",
	})
}

// RecoveryLogHandler 恢复日志处理器
func RecoveryLogHandler(result *DetectionResult) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// 使用zlog记录恢复日志
	zlog.Info("流量异常恢复", map[string]interface{}{
		"timestamp":      timestamp,
		"current_value":  result.CurrentValue,
		"mean":           result.Mean,
		"recovery_count": result.RecoveryCount,
		"status":         "recovered",
		"detail":         fmt.Sprintf("系统已恢复正常，当前值: %.2f, 均值: %.2f", result.CurrentValue, result.Mean),
	})

	fmt.Printf("✅ 系统恢复正常: 当前值=%.2f, 均值=%.2f\n", result.CurrentValue, result.Mean)
}

// RecoveryUnblockHandler 恢复解除阻断处理器
func RecoveryUnblockHandler(result *DetectionResult) {
	// 使用zlog记录解除阻断
	zlog.Info("解除流量阻断", map[string]interface{}{
		"action":        "unblock_traffic",
		"current_value": result.CurrentValue,
		"mean":          result.Mean,
		"status":        "unblocked",
		"reason":        "traffic_recovered",
	})

	fmt.Printf("🔓 解除流量阻断: 当前值=%.2f\n", result.CurrentValue)

	// 这里调用实际的解除阻断接口
	unblockTraffic(result)
}

// RecoveryUnlimitHandler 恢复解除限流处理器
func RecoveryUnlimitHandler(result *DetectionResult) {
	// 使用zlog记录解除限流
	zlog.Info("解除流量限制", map[string]interface{}{
		"action":        "unlimit_traffic",
		"current_value": result.CurrentValue,
		"mean":          result.Mean,
		"status":        "unlimited",
		"reason":        "traffic_recovered",
	})

	fmt.Printf("🔄 解除流量限制: 当前值=%.2f\n", result.CurrentValue)

	// 这里调用实际的解除限流接口
	unlimitTraffic(result)
}

// RecoveryAlertHandler 恢复告警处理器
func RecoveryAlertHandler(result *DetectionResult) {
	// 使用zlog记录恢复告警
	zlog.Info("流量恢复告警", map[string]interface{}{
		"alert_type":    "traffic_recovery",
		"current_value": result.CurrentValue,
		"mean":          result.Mean,
		"status":        "recovered",
	})

	fmt.Printf("📢 恢复告警: 流量已恢复正常\n")

	// 发送恢复通知
	sendRecoveryAlert(fmt.Sprintf("流量已恢复正常，当前值: %.2f", result.CurrentValue))
}

// SustainedHighAnomalyHandler 持续高位专用处理器
func SustainedHighAnomalyHandler(result *DetectionResult) {
	if strings.Contains(result.Confidence, "持续高位") {
		// 使用zlog记录持续高位告警
		zlog.Error("系统持续高位运行告警", map[string]interface{}{
			"alert_type":         "sustained_high_operation",
			"current_value":      result.CurrentValue,
			"mean":               result.Mean,
			"deviation":          result.Deviation,
			"confidence":         result.Confidence,
			"severity":           "critical",
			"recommended_action": "review_system_capacity_and_scaling",
			"impact":             "potential_performance_degradation",
		})

		fmt.Printf("🔥 系统持续高位运行告警: %s\n", result.String())

		// 发送特殊告警
		sendSustainedHighAlert(result)
	}
}

// DualWindowAnomalyHandler 双窗口专用异常处理器
func DualWindowAnomalyHandler(result *DetectionResult) {
	switch {
	case strings.Contains(result.Confidence, "持续高位"):
		// 持续高位运行处理
		zlog.Warn("持续高位运行检测", map[string]interface{}{
			"detection_type": "sustained_high",
			"current_value":  result.CurrentValue,
			"deviation":      result.Deviation,
			"confidence":     result.Confidence,
			"action":         "capacity_review_needed",
		})
		fmt.Printf("📈 持续高位: %s\n", result.String())

	case result.Deviation > result.Threshold*3:
		// 极严重异常
		zlog.Error("极严重流量异常", map[string]interface{}{
			"detection_type":  "critical_anomaly",
			"current_value":   result.CurrentValue,
			"deviation_ratio": result.Deviation / result.Threshold,
			"action":          "immediate_intervention",
		})
		fmt.Printf("🚨 极严重异常: %s\n", result.String())

	default:
		// 一般异常
		zlog.Info("一般流量异常", map[string]interface{}{
			"detection_type": "normal_anomaly",
			"current_value":  result.CurrentValue,
			"confidence":     result.Confidence,
		})
		fmt.Printf("⚠️  一般异常: %s\n", result.String())
	}
}

// 辅助函数
func sendSustainedHighAlert(result *DetectionResult) {
	alertMsg := fmt.Sprintf("系统持续高位运行告警！当前值: %.2f, 建议检查系统容量和扩容策略", result.CurrentValue)

	zlog.Warn("发送持续高位告警", map[string]interface{}{
		"alert_message": alertMsg,
		"alert_type":    "sustained_high_operation",
		"priority":      "high",
	})

	// 这里可以调用实际的告警接口
	// 例如：发送邮件、短信、钉钉通知等
}
func unblockTraffic(result *DetectionResult) {
	// 实现解除流量阻断逻辑
	zlog.Info("执行解除流量阻断", map[string]interface{}{
		"unblocked_value": result.CurrentValue,
		"reason":          "traffic_recovered",
		"action_taken":    "traffic_unblocked",
	})
}

func unlimitTraffic(result *DetectionResult) {
	// 实现解除流量限制逻辑
	zlog.Info("执行解除流量限制", map[string]interface{}{
		"unlimited_value": result.CurrentValue,
		"reason":          "traffic_recovered",
		"action_taken":    "traffic_unlimited",
	})
}

func sendRecoveryAlert(message string) {
	// 实现恢复告警发送逻辑
	zlog.Info("发送恢复告警", map[string]interface{}{
		"alert_message": message,
		"alert_type":    "traffic_recovery",
	})
}
