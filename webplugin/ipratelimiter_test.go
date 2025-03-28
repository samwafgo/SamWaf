package webplugin

import (
	"fmt"
	"golang.org/x/time/rate"
	"sync"
	"testing"
	"time"
)

func TestIPRateLimiter(t *testing.T) {
	// 创建一个限流器，设置为每秒2个请求，最大突发10个请求
	// 相当于5秒内最多允许10个请求
	limiter := NewIPRateLimiter(rate.Limit(2), 10)

	// 测试单个IP的限流
	t.Run("单IP限流测试", func(t *testing.T) {
		ip := "192.168.1.1"
		ipLimiter := limiter.GetLimiter(ip)

		// 模拟11个连续请求
		allowedCount := 0
		for i := 0; i < 11; i++ {
			if ipLimiter.Allow() {
				allowedCount++
			}
		}

		// 由于突发限制为10，所以应该只有10个请求被允许
		if allowedCount != 10 {
			t.Errorf("预期允许10个请求，实际允许了%d个请求", allowedCount)
		}

		// 等待一段时间后，应该可以继续发送请求
		time.Sleep(1 * time.Second)
		if !ipLimiter.Allow() {
			t.Error("等待1秒后应该允许新的请求")
		}
	})

	// 测试多个IP是否相互独立
	t.Run("多IP独立限流测试", func(t *testing.T) {
		ip1 := "192.168.1.2"
		ip2 := "192.168.1.3"

		ipLimiter1 := limiter.GetLimiter(ip1)
		ipLimiter2 := limiter.GetLimiter(ip2)

		// IP1发送10个请求
		for i := 0; i < 10; i++ {
			ipLimiter1.Allow()
		}

		// IP1应该被限流
		if ipLimiter1.Allow() {
			t.Error("IP1应该被限流")
		}

		// IP2不应该受IP1的影响
		if !ipLimiter2.Allow() {
			t.Error("IP2不应该受IP1的限流影响")
		}
	})

	// 测试并发场景
	t.Run("并发请求测试", func(t *testing.T) {
		ip := "192.168.1.4"
		var wg sync.WaitGroup
		successCount := 0
		var mu sync.Mutex

		// 创建20个并发请求
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if limiter.GetLimiter(ip).Allow() {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		// 由于突发限制为10，所以应该只有10个请求被允许
		if successCount > 10 {
			t.Errorf("并发场景下预期最多允许10个请求，实际允许了%d个请求", successCount)
		}
	})

	// 测试实际场景：5秒内最多10个请求
	t.Run("实际场景测试：5秒内最多10个请求", func(t *testing.T) {
		// 创建一个新的限流器，设置为每秒2个请求（5秒10个）
		scenarioLimiter := NewIPRateLimiter(rate.Limit(2), 10)
		ip := "192.168.1.5"
		ipLimiter := scenarioLimiter.GetLimiter(ip)

		fmt.Println("开始测试5秒内最多10个请求的场景...")

		// 第一秒：尝试发送4个请求，应该允许前3个（初始令牌桶有2个，每秒产生2个）
		allowedInFirstSecond := 0
		for i := 0; i < 4; i++ {
			if ipLimiter.Allow() {
				allowedInFirstSecond++
			}
		}
		fmt.Printf("第1秒：尝试4个请求，允许了%d个\n", allowedInFirstSecond)

		// 等待1秒
		time.Sleep(1 * time.Second)

		// 第二秒：尝试发送3个请求，应该允许2个
		allowedInSecondSecond := 0
		for i := 0; i < 3; i++ {
			if ipLimiter.Allow() {
				allowedInSecondSecond++
			}
		}
		fmt.Printf("第2秒：尝试3个请求，允许了%d个\n", allowedInSecondSecond)

		// 等待1秒
		time.Sleep(1 * time.Second)

		// 第三秒：尝试发送3个请求，应该允许2个
		allowedInThirdSecond := 0
		for i := 0; i < 3; i++ {
			if ipLimiter.Allow() {
				allowedInThirdSecond++
			}
		}
		fmt.Printf("第3秒：尝试3个请求，允许了%d个\n", allowedInThirdSecond)

		// 验证总体结果
		totalAllowed := allowedInFirstSecond + allowedInSecondSecond + allowedInThirdSecond
		fmt.Printf("总计：尝试10个请求，允许了%d个\n", totalAllowed)

		if totalAllowed > 10 {
			t.Errorf("5秒内应该最多允许10个请求，实际允许了%d个", totalAllowed)
		}
	})
}

// 测试实际的CC防护场景
func TestCCProtection(t *testing.T) {
	// 模拟配置：5秒内最多允许10个请求
	timeWindow := 5
	maxRequests := 10

	// 计算每秒速率
	ratePerSecond := rate.Limit(float64(maxRequests) / float64(timeWindow))

	// 创建限流器
	limiter := NewIPRateLimiter(ratePerSecond, maxRequests)

	// 测试IP
	ip := "192.168.1.100"

	fmt.Printf("模拟CC防护：%d秒内最多允许%d个请求（每秒%.2f个）\n",
		timeWindow, maxRequests, float64(maxRequests)/float64(timeWindow))

	// 模拟正常用户：每秒2个请求
	t.Run("正常用户测试", func(t *testing.T) {
		//ipLimiter := limiter.GetLimiter(ip)

		// 重置限流器
		limiter.ips = make(map[string]*rate.Limiter)

		success := 0
		fail := 0

		// 模拟5秒，每秒发送2个请求
		for second := 1; second <= timeWindow; second++ {
			for i := 0; i < 2; i++ {
				if limiter.GetLimiter(ip).Allow() {
					success++
				} else {
					fail++
				}
			}
			time.Sleep(1 * time.Second)
		}

		fmt.Printf("正常用户（每秒2个请求）：成功=%d, 失败=%d\n", success, fail)

		// 正常用户应该不会被限流
		if fail > 0 {
			t.Errorf("正常用户不应该被限流，但有%d个请求被拒绝", fail)
		}
	})

	// 模拟CC攻击：短时间内发送大量请求
	t.Run("CC攻击测试", func(t *testing.T) {
		// 重置限流器
		limiter.ips = make(map[string]*rate.Limiter)

		success := 0
		fail := 0

		// 短时间内发送20个请求
		for i := 0; i < 20; i++ {
			if limiter.GetLimiter(ip).Allow() {
				success++
			} else {
				fail++
			}
		}

		fmt.Printf("CC攻击（短时间内20个请求）：成功=%d, 失败=%d\n", success, fail)

		// 应该有请求被限流
		if fail == 0 {
			t.Error("CC攻击应该被限流，但所有请求都成功了")
		}

		// 成功的请求不应超过最大允许数
		if success > maxRequests {
			t.Errorf("成功请求数不应超过%d，但实际为%d", maxRequests, success)
		}
	})
}

// 测试滑动窗口模式的限流器
func TestWindowIPRateLimiter(t *testing.T) {
	// 创建一个滑动窗口限流器，设置为5秒内最多10个请求
	timeWindow := 5
	maxRequests := 10
	limiter := NewWindowIPRateLimiter(timeWindow, maxRequests)

	// 测试IP
	ip := "192.168.1.200"

	// 测试基本限流功能
	t.Run("滑动窗口基本限流测试", func(t *testing.T) {
		// 重置限流器
		limiter.requests = make(map[string][]time.Time)
		limiter.ips = make(map[string]*rate.Limiter)

		// 连续发送11个请求
		allowedCount := 0
		for i := 0; i < 11; i++ {
			if limiter.Allow(ip) {
				allowedCount++
			}
		}

		// 应该只有10个请求被允许
		if allowedCount != 10 {
			t.Errorf("滑动窗口模式下预期允许10个请求，实际允许了%d个请求", allowedCount)
		}

		// 等待1秒后，应该仍然不允许新请求（因为窗口是5秒）
		time.Sleep(1 * time.Second)
		if limiter.Allow(ip) {
			t.Error("等待1秒后不应该允许新的请求，因为窗口期是5秒")
		}

		// 等待5秒后，应该允许新请求
		time.Sleep(5 * time.Second)
		if !limiter.Allow(ip) {
			t.Error("等待5秒后应该允许新的请求")
		}
	})

	// 测试滑动窗口特性
	t.Run("滑动窗口特性测试", func(t *testing.T) {
		// 重置限流器
		limiter.requests = make(map[string][]time.Time)
		limiter.ips = make(map[string]*rate.Limiter)

		fmt.Println("开始测试滑动窗口特性...")

		// 第1秒：发送5个请求
		allowedInFirstSecond := 0
		for i := 0; i < 5; i++ {
			if limiter.Allow(ip) {
				allowedInFirstSecond++
			}
		}
		fmt.Printf("第1秒：尝试5个请求，允许了%d个\n", allowedInFirstSecond)

		// 等待3秒
		time.Sleep(3 * time.Second)

		// 第4秒：再发送5个请求
		allowedInFourthSecond := 0
		for i := 0; i < 5; i++ {
			if limiter.Allow(ip) {
				allowedInFourthSecond++
			}
		}
		fmt.Printf("第4秒：尝试5个请求，允许了%d个\n", allowedInFourthSecond)

		// 第4秒：尝试再发送1个请求，应该被拒绝
		if limiter.Allow(ip) {
			t.Error("第4秒：已经发送了10个请求，应该被限流")
		}

		// 等待2秒（此时第1秒的请求应该过期）
		time.Sleep(2 * time.Second)

		// 第6秒：应该可以发送5个新请求（因为第1秒的5个请求已经滑出窗口）
		allowedInSixthSecond := 0
		for i := 0; i < 5; i++ {
			if limiter.Allow(ip) {
				allowedInSixthSecond++
			}
		}
		fmt.Printf("第6秒：尝试5个请求，允许了%d个\n", allowedInSixthSecond)

		// 验证结果
		if allowedInSixthSecond != 5 {
			t.Errorf("第6秒应该允许5个请求（因为窗口滑动），但实际允许了%d个", allowedInSixthSecond)
		}
	})

	// 测试清理过期记录功能
	t.Run("清理过期记录测试", func(t *testing.T) {
		// 重置限流器
		limiter.requests = make(map[string][]time.Time)
		limiter.ips = make(map[string]*rate.Limiter)

		// 添加一些IP和请求记录
		ips := []string{"192.168.1.201", "192.168.1.202", "192.168.1.203"}
		for _, testIP := range ips {
			for i := 0; i < 5; i++ {
				limiter.Allow(testIP)
			}
		}

		// 验证记录数量
		if len(limiter.requests) != 3 {
			t.Errorf("应该有3个IP的请求记录，但实际有%d个", len(limiter.requests))
		}

		// 等待窗口期过后
		time.Sleep(time.Duration(timeWindow+1) * time.Second)

		// 清理过期记录
		limiter.CleanupOldRecords()

		// 验证记录是否被清理
		if len(limiter.requests) != 0 {
			t.Errorf("过期记录应该被清理，但仍有%d个记录", len(limiter.requests))
		}
	})

	// 比较两种模式的行为差异
	t.Run("两种模式行为对比", func(t *testing.T) {
		// 创建平均速率模式限流器
		ratePerSecond := rate.Limit(float64(maxRequests) / float64(timeWindow))
		rateLimiter := NewIPRateLimiter(ratePerSecond, maxRequests)

		// 创建滑动窗口模式限流器
		windowLimiter := NewWindowIPRateLimiter(timeWindow, maxRequests)

		// 重置限流器
		rateLimiter.ips = make(map[string]*rate.Limiter)
		windowLimiter.requests = make(map[string][]time.Time)
		windowLimiter.ips = make(map[string]*rate.Limiter)

		fmt.Println("\n开始对比两种模式的行为差异...")

		// 测试突发请求场景
		rateIP := "192.168.1.210"
		windowIP := "192.168.1.211"

		// 平均速率模式：突发8个请求
		rateAllowed := 0
		for i := 0; i < 8; i++ {
			if rateLimiter.GetLimiter(rateIP).Allow() {
				rateAllowed++
			}
		}

		// 滑动窗口模式：突发8个请求
		windowAllowed := 0
		for i := 0; i < 8; i++ {
			if windowLimiter.Allow(windowIP) {
				windowAllowed++
			}
		}

		fmt.Printf("突发8个请求：平均速率模式允许%d个，滑动窗口模式允许%d个\n",
			rateAllowed, windowAllowed)

		// 等待3秒
		time.Sleep(3 * time.Second)

		// 平均速率模式：再发送5个请求
		rateAllowedLater := 0
		for i := 0; i < 5; i++ {
			if rateLimiter.GetLimiter(rateIP).Allow() {
				rateAllowedLater++
			}
		}

		// 滑动窗口模式：再发送5个请求
		windowAllowedLater := 0
		for i := 0; i < 5; i++ {
			if windowLimiter.Allow(windowIP) {
				windowAllowedLater++
			}
		}

		fmt.Printf("3秒后再发送5个请求：平均速率模式允许%d个，滑动窗口模式允许%d个\n",
			rateAllowedLater, windowAllowedLater)

		// 验证结果
		totalRateAllowed := rateAllowed + rateAllowedLater
		totalWindowAllowed := windowAllowed + windowAllowedLater

		fmt.Printf("总计：平均速率模式允许%d个，滑动窗口模式允许%d个\n",
			totalRateAllowed, totalWindowAllowed)

		// 修改：平均速率模式会随时间生成新令牌，所以允许的请求可能超过初始设定
		// 滑动窗口模式不应该超过最大请求数
		if totalWindowAllowed > maxRequests {
			t.Errorf("滑动窗口模式不应超过%d个请求，但实际允许了%d个",
				maxRequests, totalWindowAllowed)
		}

		// 添加注释说明平均速率模式的行为特点，而不是将其视为错误
		fmt.Printf("注意：平均速率模式允许了%d个请求，超过了初始设定的%d个，这是因为随着时间推移会生成新的令牌\n",
			totalRateAllowed, maxRequests)
	})
}

// 测试实际CC防护场景（滑动窗口模式）
func TestWindowCCProtection(t *testing.T) {
	// 模拟配置：5秒内最多允许10个请求
	timeWindow := 5
	maxRequests := 10

	// 创建滑动窗口限流器
	limiter := NewWindowIPRateLimiter(timeWindow, maxRequests)

	// 测试IP
	ip := "192.168.1.220"

	fmt.Printf("\n模拟CC防护（滑动窗口模式）：%d秒内最多允许%d个请求\n",
		timeWindow, maxRequests)

	// 模拟正常用户：每秒2个请求
	t.Run("正常用户测试（滑动窗口）", func(t *testing.T) {
		// 重置限流器
		limiter.requests = make(map[string][]time.Time)
		limiter.ips = make(map[string]*rate.Limiter)

		success := 0
		fail := 0

		// 模拟5秒，每秒发送2个请求
		for second := 1; second <= timeWindow; second++ {
			for i := 0; i < 2; i++ {
				if limiter.Allow(ip) {
					success++
				} else {
					fail++
				}
			}
			time.Sleep(1 * time.Second)
		}

		fmt.Printf("正常用户（每秒2个请求）：成功=%d, 失败=%d\n", success, fail)

		// 正常用户应该不会被限流
		if fail > 0 {
			t.Errorf("正常用户不应该被限流，但有%d个请求被拒绝", fail)
		}
	})

	// 模拟CC攻击：短时间内发送大量请求
	t.Run("CC攻击测试（滑动窗口）", func(t *testing.T) {
		// 重置限流器
		limiter.requests = make(map[string][]time.Time)
		limiter.ips = make(map[string]*rate.Limiter)

		success := 0
		fail := 0

		// 短时间内发送20个请求
		for i := 0; i < 20; i++ {
			if limiter.Allow(ip) {
				success++
			} else {
				fail++
			}
		}

		fmt.Printf("CC攻击（短时间内20个请求）：成功=%d, 失败=%d\n", success, fail)

		// 应该有请求被限流
		if fail == 0 {
			t.Error("CC攻击应该被限流，但所有请求都成功了")
		}

		// 成功的请求不应超过最大允许数
		if success > maxRequests {
			t.Errorf("成功请求数不应超过%d，但实际为%d", maxRequests, success)
		}
	})

	// 测试滑动窗口的特性：请求逐渐滑出窗口
	t.Run("滑动窗口特性测试（CC防护）", func(t *testing.T) {
		// 重置限流器
		limiter.requests = make(map[string][]time.Time)
		limiter.ips = make(map[string]*rate.Limiter)

		// 第1秒：发送10个请求（达到限制）
		firstBatchSuccess := 0
		for i := 0; i < 10; i++ {
			if limiter.Allow(ip) {
				firstBatchSuccess++
			}
		}

		// 第1秒：再发送1个请求（应该被拒绝）
		if limiter.Allow(ip) {
			t.Error("达到限制后应该被拒绝")
		}

		fmt.Printf("第1秒：尝试10个请求，允许了%d个，额外请求被拒绝\n", firstBatchSuccess)

		// 等待3秒（窗口未完全滑动）
		time.Sleep(3 * time.Second)

		// 第4秒：尝试发送5个请求（应该全部被拒绝，因为窗口内仍有10个请求）
		fourthSecondSuccess := 0
		for i := 0; i < 5; i++ {
			if limiter.Allow(ip) {
				fourthSecondSuccess++
			}
		}

		fmt.Printf("第4秒：尝试5个请求，允许了%d个\n", fourthSecondSuccess)

		// 等待3秒（窗口完全滑动，第1秒的请求应该全部滑出）
		time.Sleep(3 * time.Second)

		// 第7秒：应该可以发送10个新请求
		seventhSecondSuccess := 0
		for i := 0; i < 10; i++ {
			if limiter.Allow(ip) {
				seventhSecondSuccess++
			}
		}

		fmt.Printf("第7秒：尝试10个请求，允许了%d个\n", seventhSecondSuccess)

		// 验证结果
		if seventhSecondSuccess != 10 {
			t.Errorf("窗口完全滑动后应该允许10个请求，但实际允许了%d个", seventhSecondSuccess)
		}
	})
}

// 测试清除指定IP的滑动窗口记录
func TestClearWindowForIP(t *testing.T) {
	// 创建一个滑动窗口限流器
	timeWindow := 5
	maxRequests := 10
	limiter := NewWindowIPRateLimiter(timeWindow, maxRequests)

	// 测试IP
	ip := "192.168.1.250"

	t.Run("清除滑动窗口记录测试", func(t *testing.T) {
		// 重置限流器
		limiter.requests = make(map[string][]time.Time)
		limiter.ips = make(map[string]*rate.Limiter)

		// 先发送8个请求
		for i := 0; i < 8; i++ {
			limiter.Allow(ip)
		}

		// 验证请求记录数量
		if len(limiter.requests[ip]) != 8 {
			t.Errorf("应该记录8个请求，但实际记录了%d个", len(limiter.requests[ip]))
		}

		// 清除该IP的记录
		limiter.ClearWindowForIP(ip)

		// 验证记录是否被清除
		if len(limiter.requests[ip]) != 0 {
			t.Errorf("清除后应该有0个请求记录，但实际有%d个", len(limiter.requests[ip]))
		}

		// 验证是否可以继续发送请求
		allowedAfterClear := 0
		for i := 0; i < maxRequests; i++ {
			if limiter.Allow(ip) {
				allowedAfterClear++
			}
		}

		// 清除后应该可以发送最大请求数
		if allowedAfterClear != maxRequests {
			t.Errorf("清除后应该允许%d个请求，但实际允许了%d个", maxRequests, allowedAfterClear)
		}

		// 超过限制后应该被拒绝
		if limiter.Allow(ip) {
			t.Error("超过限制后应该被拒绝")
		}
	})

	// 测试平均速率模式下的清除功能
	t.Run("平均速率模式下清除记录测试", func(t *testing.T) {
		// 创建平均速率模式限流器
		ratePerSecond := rate.Limit(float64(maxRequests) / float64(timeWindow))
		rateLimiter := NewIPRateLimiter(ratePerSecond, maxRequests)

		// 发送足够多的请求，消耗所有令牌
		for i := 0; i < maxRequests; i++ {
			rateLimiter.GetLimiter(ip).Allow()
		}

		// 此时应该被限流
		if rateLimiter.GetLimiter(ip).Allow() {
			t.Error("消耗所有令牌后应该被限流")
		}

		// 清除该IP的记录
		rateLimiter.ClearWindowForIP(ip)

		// 清除后应该可以继续发送请求
		if !rateLimiter.GetLimiter(ip).Allow() {
			t.Error("清除后应该允许新的请求")
		}
	})

	// 测试不存在的IP
	t.Run("清除不存在IP的记录", func(t *testing.T) {
		// 重置限流器
		limiter.requests = make(map[string][]time.Time)
		limiter.ips = make(map[string]*rate.Limiter)

		// 清除一个不存在的IP
		nonExistIP := "10.0.0.1"

		// 不应该抛出异常
		limiter.ClearWindowForIP(nonExistIP)

		// 验证是否可以正常使用
		if !limiter.Allow(nonExistIP) {
			t.Error("清除不存在的IP后，应该允许该IP的请求")
		}
	})

	// 测试实际场景：IP被限流后手动解除
	t.Run("IP被限流后手动解除", func(t *testing.T) {
		// 重置限流器
		limiter.requests = make(map[string][]time.Time)
		limiter.ips = make(map[string]*rate.Limiter)

		fmt.Println("\n测试IP被限流后手动解除的场景...")

		// 发送足够多的请求，触发限流
		allowedCount := 0
		for i := 0; i < maxRequests+1; i++ {
			if limiter.Allow(ip) {
				allowedCount++
			}
		}

		fmt.Printf("发送%d个请求，允许了%d个，最后一个被拒绝\n",
			maxRequests+1, allowedCount)

		// 验证是否被限流
		if limiter.Allow(ip) {
			t.Error("应该被限流")
		}

		// 手动解除限流
		fmt.Println("手动解除限流...")
		limiter.ClearWindowForIP(ip)

		// 验证是否解除成功
		newAllowedCount := 0
		for i := 0; i < 5; i++ {
			if limiter.Allow(ip) {
				newAllowedCount++
			}
		}

		fmt.Printf("解除限流后，发送5个请求，允许了%d个\n", newAllowedCount)

		if newAllowedCount != 5 {
			t.Errorf("解除限流后应该允许5个请求，但实际允许了%d个", newAllowedCount)
		}
	})
}
