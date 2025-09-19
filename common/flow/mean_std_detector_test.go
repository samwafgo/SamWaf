package flow

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNewMeanStdDetector(t *testing.T) {
	d := NewMeanStdDetector(10, 3)
	if d == nil {
		t.Fatal("NewMeanStdDetector failed")
	}
	//模拟测试 刚开始正常->异常->正常

	// 第一阶段：添加正常数据，建立基线
	normalValues := []float64{10.0, 11.0, 9.0, 10.5, 9.5, 10.2, 9.8, 10.1, 9.9, 10.3}
	for _, value := range normalValues {
		d.Add(value)
		// 在建立基线阶段，不应该检测到异常
		if d.IsAnomaly(value) {
			t.Logf("正常阶段检测到异常值: %.2f (这在建立基线时是正常的)", value)
		}
	}
	t.Logf("第一阶段完成：已添加%d个正常基线数据", len(normalValues))

	// 第二阶段：测试异常检测
	anomalyValues := []float64{25.0, 30.0, -5.0, 35.0} // 明显偏离正常范围的异常值
	anomalyDetected := 0
	for _, value := range anomalyValues {
		if d.IsAnomaly(value) {
			anomalyDetected++
			t.Logf("检测到异常值: %.2f", value)
		} else {
			t.Logf("未检测到异常值: %.2f (可能需要调整k值)", value)
		}
		d.Add(value) // 添加到窗口中
	}

	if anomalyDetected == 0 {
		t.Error("异常检测失败：没有检测到任何异常值")
	} else {
		t.Logf("第二阶段完成：检测到%d个异常值", anomalyDetected)
	}

	// 第三阶段：回归正常
	normalValues2 := []float64{10.1, 9.9, 10.2, 9.8, 10.0, 9.7, 10.3, 9.6, 10.4}
	normalDetected := 0
	for _, value := range normalValues2 {
		if !d.IsAnomaly(value) {
			normalDetected++
			t.Logf("正常值: %.2f", value)
		} else {
			t.Logf("仍被检测为异常: %.2f (滑动窗口还在调整中)", value)
		}
		d.Add(value)
	}

	t.Logf("第三阶段完成：%d个值被识别为正常", normalDetected)

	// 验证最终状态：最后几个正常值应该不被检测为异常
	finalNormalValues := []float64{10.0, 9.9, 10.1, 0}
	finalNormalCount := 0
	for _, value := range finalNormalValues {
		if !d.IsAnomaly(value) {
			finalNormalCount++
		}
	}

	if finalNormalCount < 2 {
		t.Error("最终正常化测试失败：系统未能回归正常状态")
	} else {
		t.Logf("测试成功：系统已回归正常状态，%d/%d个最终值被正确识别为正常", finalNormalCount, len(finalNormalValues))
	}
}

// 额外的测试用例：测试边界条件
func TestMeanStdDetectorEdgeCases(t *testing.T) {
	d := NewMeanStdDetector(5, 2.0)

	// 测试窗口未满时的行为
	if d.IsAnomaly(100.0) {
		t.Error("窗口数据不足时不应检测异常")
	}

	d.Add(10.0)
	if d.IsAnomaly(100.0) {
		t.Error("窗口数据不足时不应检测异常")
	}

	// 测试相同值的情况
	for i := 0; i < 5; i++ {
		d.Add(10.0)
	}

	// 当所有值都相同时，标准差为0，任何不同的值都应该被检测为异常
	if !d.IsAnomaly(15.0) {
		t.Error("当标准差为0时，不同的值应该被检测为异常")
	}

	if d.IsAnomaly(10.0) {
		t.Error("相同的值不应该被检测为异常")
	}
}

// 性能测试
func TestMeanStdDetectorPerformance(t *testing.T) {
	d := NewMeanStdDetector(100, 2.0)

	// 添加大量数据测试性能
	for i := 0; i < 10000; i++ {
		value := float64(i%20 + 10) // 生成10-29之间的循环数据
		d.Add(value)
		d.IsAnomaly(value)
	}

	t.Log("性能测试完成：处理了10000个数据点")
}

// 手动测试
func TestMeanStdDetectorManual(t *testing.T) {
	d := NewMeanStdDetector(10, 3)
	if d == nil {
		t.Fatal("NewMeanStdDetector failed")
	}

	normalValues := []float64{10.0, 11.0, 9.0, 10.5, 9.5, 10.2, 9.8, 10.1, 9.9, 10.3, 5000}
	for _, value := range normalValues {
		d.Add(value)
		anomaly, window := d.IsAnomalyPrintFull(value)
		if anomaly {
			t.Logf("正常阶段检测到异常值: %.2f (这在建立基线时是正常的) 当前window数据: %v", value, window)
		}
	}

}

// 在现有测试文件中添加新的测试函数

// TestMeanStdDetectorImproved 改进后的测试示例
func TestMeanStdDetectorImproved(t *testing.T) {
	// 创建检测器：窗口大小10，2倍标准差阈值
	detector := NewMeanStdDetector(10, 2.0)

	// 模拟正常流量数据
	normalTraffic := []float64{100, 105, 95, 110, 90, 102, 98, 107, 93, 101}

	fmt.Println("=== 正常流量阶段 ===")
	for _, traffic := range normalTraffic {
		detector.AddValue(traffic)
		result := detector.DetectAnomaly(traffic)
		fmt.Printf("%s\n", result.String())
	}

	// 模拟异常流量
	anomalyTraffic := []float64{200, 50, 300, 10}

	fmt.Println("\n=== 异常流量检测 ===")
	for _, traffic := range anomalyTraffic {
		result := detector.DetectAnomaly(traffic)
		fmt.Printf("%s\n", result.String())

		// 添加到窗口中
		detector.AddValue(traffic)
	}

	// 打印当前窗口统计信息
	fmt.Println("\n=== 窗口统计信息 ===")
	stats := detector.GetWindowStats()
	for key, value := range stats {
		fmt.Printf("%s: %.2f\n", key, value)
	}
}

// TestFlowAnomalyDetectionDemo 流量异常检测演示
func TestFlowAnomalyDetectionDemo(t *testing.T) {
	// 创建流量异常检测器
	flowDetector := NewMeanStdDetector(20, 2.5) // 20个数据点窗口，2.5倍标准差

	// 模拟一天的网络流量数据 (MB/s)
	dailyTraffic := []float64{
		// 凌晨低流量
		10, 8, 12, 9, 11, 7, 13, 10,
		// 上午逐渐增加
		15, 18, 22, 25, 30, 35, 40,
		// 中午高峰
		45, 50, 48, 52, 47,
		// 下午稳定
		40, 42, 38, 41, 39,
		// 异常流量攻击
		150, 200, 180, 220,
		// 恢复正常
		35, 40, 38, 42, 36,
	}

	fmt.Println("=== 网络流量异常检测演示 ===")
	anomalyCount := 0

	for i, traffic := range dailyTraffic {
		// 先检测再添加
		result := flowDetector.DetectAnomaly(traffic)

		if result.IsAnomaly {
			anomalyCount++
			fmt.Printf("[%02d] ⚠️  %s\n", i+1, result.String())
		} else {
			fmt.Printf("[%02d] ✅ %s\n", i+1, result.String())
		}

		// 添加到检测器
		flowDetector.AddValue(traffic)
	}

	fmt.Printf("\n检测完成：共发现 %d 个异常流量点\n", anomalyCount)

	// 最终统计
	stats := flowDetector.GetWindowStats()
	fmt.Printf("最终窗口统计：均值=%.1f, 标准差=%.1f, 阈值=%.1f\n",
		stats["mean"], stats["std_dev"], stats["threshold"])
}

// TestFlowAnomalyDetectionWithHandling 带异常处理的流量检测测试
func TestFlowAnomalyDetectionWithHandling(t *testing.T) {
	// 创建流量异常检测器
	flowDetector := NewMeanStdDetector(20, 2.5)

	// 添加使用zlog的异常处理器
	flowDetector.AddAnomalyProcessor(AnomalyProcessor{
		Action:  ActionLog,
		Handler: LogAnomalyHandler, // 现在使用zlog
		Enabled: true,
		Name:    "zlog_logger",
	})

	flowDetector.AddAnomalyProcessor(AnomalyProcessor{
		Action:  ActionAlert,
		Handler: AlertAnomalyHandler, // 现在使用zlog
		Enabled: true,
		Name:    "zlog_alerter",
	})

	flowDetector.AddAnomalyProcessor(AnomalyProcessor{
		Action:  ActionCustom,
		Handler: CustomAnomalyHandler, // 现在使用zlog
		Enabled: true,
		Name:    "zlog_custom",
	})

	// 模拟流量数据
	dailyTraffic := []float64{
		// 正常流量
		10, 8, 12, 9, 11, 7, 13, 10, 15, 18,
		// 异常攻击流量
		150, 200, 180, 220,
		// 恢复正常
		35, 40, 38, 42, 36,
	}

	fmt.Println("=== 带异常处理的流量检测演示 ===")
	anomalyCount := 0

	for i, traffic := range dailyTraffic {
		// 使用带处理的检测方法
		result := flowDetector.DetectAnomalyWithProcessing(traffic)

		if result.IsAnomaly {
			anomalyCount++
			fmt.Printf("[%02d] ⚠️  异常已处理: %.2f\n", i+1, traffic)
		} else {
			fmt.Printf("[%02d] ✅ 正常流量: %.2f\n", i+1, traffic)
		}

		// 添加到检测器
		flowDetector.AddValue(traffic)

		// 模拟实时处理间隔
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf("\n检测完成：共处理 %d 个异常流量点\n", anomalyCount)
}

// TestRealTimeAnomalyProcessing 实时异常处理测试
func TestRealTimeAnomalyProcessing(t *testing.T) {
	detector := NewMeanStdDetector(10, 2.0)

	// 添加实时处理器
	detector.AddAnomalyProcessor(AnomalyProcessor{
		Action:  ActionCustom,
		Enabled: true,
		Name:    "realtime",
		Handler: func(result *DetectionResult) {
			// 实时处理逻辑
			timestamp := time.Now().Format("15:04:05")
			switch {
			case result.Deviation > result.Threshold*3:
				fmt.Printf("[%s] 🔥 极严重异常 %.2f - 立即阻断\n", timestamp, result.CurrentValue)
			case result.Deviation > result.Threshold*2:
				fmt.Printf("[%s] ⚡ 严重异常 %.2f - 启动限流\n", timestamp, result.CurrentValue)
			default:
				fmt.Printf("[%s] ⚠️  一般异常 %.2f - 记录日志\n", timestamp, result.CurrentValue)
			}
		},
	})

	// 模拟实时数据流
	trafficStream := []float64{10, 12, 11, 9, 50, 100, 200, 15, 13, 11}

	fmt.Println("=== 实时异常处理演示 ===")
	for _, traffic := range trafficStream {
		detector.AddValue(traffic)
		detector.DetectAnomalyWithProcessing(traffic)
		time.Sleep(500 * time.Millisecond) // 模拟实时间隔
	}
}

// TestFlowAnomalyDetectionWithRecovery 带恢复机制的流量检测测试
func TestFlowAnomalyDetectionWithRecovery(t *testing.T) {

	//初始化日志
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "console")
	// 创建流量异常检测器
	flowDetector := NewMeanStdDetector(10, 2.0)
	flowDetector.SetRecoveryThreshold(3) // 设置3个连续正常值后恢复

	// 添加异常和恢复处理器
	flowDetector.AddAnomalyProcessor(AnomalyProcessor{
		Action:          ActionLog,
		Handler:         LogAnomalyHandler,
		RecoveryHandler: RecoveryLogHandler,
		Enabled:         true,
		Name:            "logger_with_recovery",
	})

	flowDetector.AddAnomalyProcessor(AnomalyProcessor{
		Action:          ActionBlock,
		Handler:         BlockAnomalyHandler,
		RecoveryHandler: RecoveryUnblockHandler,
		Enabled:         true,
		Name:            "blocker_with_recovery",
	})

	// 模拟完整的异常-恢复周期
	trafficData := []float64{
		// 正常流量建立基线
		10, 12, 11, 9, 10, 11, 9, 12, 10, 11,
		// 异常流量
		50, 60, 55,
		// 恢复正常
		10, 11, 12, 9, 10, 11,
		// 高位运行
		100, 120, 110, 130, 120, 110,
		// 继续高位运行
		92, 93, 94, 95, 94, 98,
		//降至低位
		10, 11, 12, 9, 10, 11,
	}

	fmt.Println("=== 异常检测与恢复演示 ===")
	for i, traffic := range trafficData {
		// 先添加到窗口，再检测
		flowDetector.AddValue(traffic)
		result := flowDetector.DetectAnomalyWithProcessing(traffic)

		if result.IsAnomaly {
			fmt.Printf("[%02d] ⚠️  异常: %.2f\n", i+1, traffic)
		} else if result.IsRecovered {
			fmt.Printf("[%02d] 🎉 恢复: %.2f (连续正常%d次)\n", i+1, traffic, result.RecoveryCount)
		} else {
			fmt.Printf("[%02d] ✅ 正常: %.2f\n", i+1, traffic)
		}

		// 显示恢复状态
		status := flowDetector.GetRecoveryStatus()
		if status["is_in_anomaly_state"].(bool) {
			fmt.Printf("     恢复进度: %d/%d (%.1f%%)\n",
				status["normal_count"], status["recovery_threshold"],
				status["recovery_progress"].(float64)*100)
		}

		time.Sleep(200 * time.Millisecond)
	}
}

// TestDualWindowDetectorBasic 双窗口检测器基础功能测试
func TestDualWindowDetectorBasic(t *testing.T) {
	// 创建双窗口检测器：短窗口5，长窗口15，2倍标准差
	detector := NewDualWindowDetector(5, 15, 2.0)

	fmt.Println("=== 双窗口检测器基础功能测试 ===")

	// 第一阶段：建立长期基线（低流量）
	lowTraffic := []float64{10, 12, 11, 9, 10, 11, 9, 12, 10, 11, 9, 10, 12, 11, 10}
	fmt.Println("\n--- 建立长期基线（低流量） ---")
	for i, traffic := range lowTraffic {
		detector.AddValue(traffic)
		result := detector.DetectAnomaly(traffic)
		fmt.Printf("[%02d] 值: %.1f, 异常: %v, %s\n", i+1, traffic, result.IsAnomaly, result.Confidence)
	}

	// 第二阶段：短期高流量（应该被检测为正常，因为还没有持续太久）
	highTraffic := []float64{25, 30, 28, 32, 27, 29, 31, 26, 30, 28}
	fmt.Println("\n--- 短期高流量阶段 ---")
	for i, traffic := range highTraffic {
		detector.AddValue(traffic)
		result := detector.DetectAnomaly(traffic)
		fmt.Printf("[%02d] 值: %.1f, 异常: %v, %s\n", i+len(lowTraffic)+1, traffic, result.IsAnomaly, result.Confidence)
	}

	// 第三阶段：持续高流量（应该触发持续高位警告）
	sustainedHighTraffic := []float64{35, 40, 38, 42, 36, 39, 41, 37, 40, 38, 35, 42, 39, 36, 40}
	fmt.Println("\n--- 持续高流量阶段 ---")
	for i, traffic := range sustainedHighTraffic {
		detector.AddValue(traffic)
		result := detector.DetectAnomaly(traffic)
		fmt.Printf("[%02d] 值: %.1f, 异常: %v, %s\n", i+len(lowTraffic)+len(highTraffic)+1, traffic, result.IsAnomaly, result.Confidence)
	}

	// 打印最终统计
	stats := detector.GetDualWindowStats()
	fmt.Printf("\n=== 最终统计 ===\n")
	fmt.Printf("短窗口均值: %.2f\n", stats["short_mean"])
	fmt.Printf("长窗口均值: %.2f\n", stats["long_mean"])
	fmt.Printf("持续高位计数: %d\n", stats["sustained_high_count"])
}

// TestDualWindowSustainedHighDetection 持续高位检测专项测试
func TestDualWindowSustainedHighDetection(t *testing.T) {
	detector := NewDualWindowDetector(5, 20, 2.0)
	detector.SetSustainedHighThreshold(10) // 设置较低的阈值便于测试

	fmt.Println("=== 持续高位检测专项测试 ===")

	// 建立低基线
	for i := 0; i < 20; i++ {
		detector.AddValue(10.0 + float64(i%3)) // 9-12之间波动
	}

	fmt.Println("\n--- 基线建立完成，开始高位运行 ---")

	// 模拟系统从低位突然跳到高位并持续运行
	highValues := []float64{50, 52, 48, 51, 49, 53, 47, 50, 52, 48, 51, 49, 50, 52, 48}

	sustainedDetected := false
	for i, value := range highValues {
		detector.AddValue(value)
		result := detector.DetectAnomaly(value)

		fmt.Printf("[%02d] 值: %.1f, 异常: %v", i+1, value, result.IsAnomaly)
		if result.IsAnomaly && result.Confidence != "正常范围" {
			fmt.Printf(", %s", result.Confidence)
			if !sustainedDetected && result.Confidence != "正常范围" {
				sustainedDetected = true
				fmt.Printf(" ← 首次检测到持续高位")
			}
		}
		fmt.Println()
	}

	if !sustainedDetected {
		t.Error("未能检测到持续高位运行状态")
	} else {
		fmt.Println("✅ 成功检测到持续高位运行状态")
	}
}

// TestDualWindowVsSingleWindow 双窗口与单窗口对比测试
func TestDualWindowVsSingleWindow(t *testing.T) {
	// 创建检测器
	singleDetector := NewMeanStdDetector(10, 2.0)
	dualDetector := NewDualWindowDetector(5, 15, 2.0)
	dualDetector.SetSustainedHighThreshold(8)

	fmt.Println("=== 双窗口 vs 单窗口对比测试 ===")

	// 测试场景：历史低峰 -> 高峰持续运行
	testData := []float64{
		// 历史低峰
		5, 7, 6, 8, 5, 6, 7, 5, 8, 6,
		// 突然跳到高位并持续
		25, 28, 26, 30, 27, 29, 31, 26, 28, 30, 27, 29, 25, 28, 26,
	}

	fmt.Printf("%-5s %-8s %-15s %-15s %-20s %-20s\n", "序号", "数值", "单窗口异常", "双窗口异常", "单窗口置信度", "双窗口置信度")
	fmt.Println(strings.Repeat("-", 100))

	singleAnomalies := 0
	dualAnomalies := 0
	dualSustainedWarnings := 0

	for i, value := range testData {
		// 单窗口检测
		singleDetector.AddValue(value)
		singleResult := singleDetector.DetectAnomaly(value)

		// 双窗口检测
		dualDetector.AddValue(value)
		dualResult := dualDetector.DetectAnomaly(value)

		if singleResult.IsAnomaly {
			singleAnomalies++
		}
		if dualResult.IsAnomaly {
			dualAnomalies++
			if strings.Contains(dualResult.Confidence, "持续高位") {
				dualSustainedWarnings++
			}
		}

		fmt.Printf("%-5d %-8.1f %-15v %-15v %-20s %-20s\n",
			i+1, value,
			singleResult.IsAnomaly, dualResult.IsAnomaly,
			singleResult.Confidence, dualResult.Confidence)
	}

	fmt.Printf("\n=== 对比结果 ===\n")
	fmt.Printf("单窗口异常次数: %d\n", singleAnomalies)
	fmt.Printf("双窗口异常次数: %d\n", dualAnomalies)
	fmt.Printf("双窗口持续高位警告: %d\n", dualSustainedWarnings)

	// 验证双窗口能检测到持续高位问题
	if dualSustainedWarnings == 0 {
		t.Error("双窗口检测器未能识别持续高位运行问题")
	} else {
		fmt.Printf("✅ 双窗口成功识别了持续高位运行问题\n")
	}
}

// TestDualWindowWithHandlers 双窗口检测器异常处理器测试
func TestDualWindowWithHandlers(t *testing.T) {
	//初始化日志
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "console")

	detector := NewDualWindowDetector(5, 15, 2.0)
	detector.SetSustainedHighThreshold(5)

	// 添加专门的持续高位处理器
	detector.AddAnomalyProcessor(AnomalyProcessor{
		Action:  ActionCustom,
		Enabled: true,
		Name:    "sustained_high_handler",
		Handler: func(result *DetectionResult) {
			if strings.Contains(result.Confidence, "持续高位") {
				zlog.Warn("持续高位运行告警", map[string]interface{}{
					"alert_type":    "sustained_high_traffic",
					"current_value": result.CurrentValue,
					"deviation":     result.Deviation,
					"confidence":    result.Confidence,
					"action_needed": "review_system_capacity",
				})
				fmt.Printf("🔥 持续高位告警: %s\n", result.String())
			} else {
				zlog.Info("一般异常检测", map[string]interface{}{
					"current_value": result.CurrentValue,
					"confidence":    result.Confidence,
				})
			}
		},
	})

	fmt.Println("=== 双窗口异常处理器测试 ===")

	// 测试数据：低基线 -> 持续高位
	testSequence := []float64{
		// 建立低基线
		10, 12, 11, 9, 10, 11, 9, 12, 10, 11, 9, 10, 12, 11, 10,
		// 持续高位运行
		30, 32, 31, 33, 29, 31, 34, 30, 32, 31, 30, 33, 31, 29, 32,
	}

	handlerTriggered := false
	sustainedHighDetected := false

	for i, value := range testSequence {
		detector.AddValue(value)
		result := detector.DetectAnomalyWithProcessing(value)

		if result.IsAnomaly {
			handlerTriggered = true
			if strings.Contains(result.Confidence, "持续高位") {
				sustainedHighDetected = true
				fmt.Printf("[%02d] 🚨 持续高位: %.1f - %s\n", i+1, value, result.Confidence)
			} else {
				fmt.Printf("[%02d] ⚠️  一般异常: %.1f - %s\n", i+1, value, result.Confidence)
			}
		} else {
			fmt.Printf("[%02d] ✅ 正常: %.1f\n", i+1, value)
		}

		time.Sleep(50 * time.Millisecond)
	}

	if !handlerTriggered {
		t.Error("异常处理器未被触发")
	}
	if !sustainedHighDetected {
		t.Error("未检测到持续高位运行状态")
	}

	fmt.Printf("\n✅ 测试完成：异常处理器正常工作，持续高位检测有效\n")
}

// TestDualWindowRealWorldScenario 双窗口真实场景测试
func TestDualWindowRealWorldScenario(t *testing.T) {
	detector := NewDualWindowDetector(10, 30, 2.0)
	detector.SetSustainedHighThreshold(15)

	fmt.Println("=== 双窗口真实场景测试 ===")

	// 模拟真实的网络流量场景
	scenarios := map[string][]float64{
		"正常日间流量":  {15, 18, 20, 22, 25, 23, 21, 19, 17, 20, 22, 24, 21, 18, 16},
		"突发异常流量":  {150, 200, 180, 220, 160},                                                        // 真正的异常攻击
		"系统升级后高位": {45, 48, 50, 47, 49, 51, 46, 48, 50, 47, 49, 52, 48, 46, 50, 49, 47, 51, 48, 50}, // 系统升级后持续高位
		"恢复正常":    {20, 22, 18, 21, 19, 23, 20, 18, 22, 21},
	}

	totalAnomalies := 0
	sustainedHighWarnings := 0

	for scenario, data := range scenarios {
		fmt.Printf("\n--- %s ---\n", scenario)

		for i, value := range data {
			detector.AddValue(value)
			result := detector.DetectAnomaly(value)

			if result.IsAnomaly {
				totalAnomalies++
				if strings.Contains(result.Confidence, "持续高位") {
					sustainedHighWarnings++
					fmt.Printf("[%02d] 🔥 %s: %.1f\n", i+1, result.Confidence, value)
				} else {
					fmt.Printf("[%02d] ⚠️  异常: %.1f - %s\n", i+1, value, result.Confidence)
				}
			} else {
				fmt.Printf("[%02d] ✅ 正常: %.1f\n", i+1, value)
			}
		}
	}

	fmt.Printf("\n=== 场景测试总结 ===\n")
	fmt.Printf("总异常检测次数: %d\n", totalAnomalies)
	fmt.Printf("持续高位警告次数: %d\n", sustainedHighWarnings)

	// 验证检测效果
	if totalAnomalies == 0 {
		t.Error("未检测到任何异常，检测器可能过于宽松")
	}
	if sustainedHighWarnings == 0 {
		t.Error("未检测到持续高位运行，可能需要调整参数")
	}

	fmt.Printf("✅ 双窗口检测器在真实场景中表现良好\n")
}
