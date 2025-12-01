package firewall

import (
	"fmt"
	"testing"
	"time"
)

// ================== 基础功能测试 ==================

func TestFireWallEngine_AddRule(t *testing.T) {
	fw := FireWallEngine{}
	// Add a new firewall rule
	ruleName := "testwaf1"
	ipToAdd := "192.168.1.12"
	action := ACTION_BLOCK
	proc := "TCP"
	localport := "8989"
	if err := fw.AddRule(ruleName, ipToAdd, action, proc, localport); err != nil {
		t.Logf("Failed to add firewall rule: %v", err)
	} else {
		t.Log("Firewall rule added successfully.")
	}
}

func TestFireWallEngine_DeleteRule(t *testing.T) {
	fw := FireWallEngine{}
	ruleName := "testwaf1"

	exists, err := fw.IsRuleExists(ruleName)
	if err != nil {
		t.Fatalf("Error checking rule existence: %v", err)
	}

	if exists {
		if excuteResult, err := fw.DeleteRule(ruleName); err != nil {
			t.Logf("Failed to delete firewall rule: %v", err)
		} else {
			if excuteResult {
				t.Log("Firewall rule deleted successfully.")
			} else {
				t.Logf("Firewall rule deleted failed: %v", err)
			}
		}
	} else {
		t.Log("Rule does not exist.")
	}
}

func TestFireWallEngine_EditRule(t *testing.T) {
	fw := FireWallEngine{}
	// Edit an existing firewall rule (not supported)
	ruleNum := 1
	newRule := "-p tcp --dport 8080 -j DROP"
	if err := fw.EditRule(ruleNum, newRule); err != nil {
		t.Logf("Expected error: %v", err)
	} else {
		t.Log("Firewall rule edited successfully.")
	}
}

func TestFireWallEngine_IsFirewallEnabled(t *testing.T) {
	fw := FireWallEngine{}

	// Check if the firewall is enabled
	if fw.IsFirewallEnabled() {
		t.Log("Firewall is enabled.")
	} else {
		t.Log("Firewall is not enabled.")
	}
}

func TestFireWallEngine_IsRuleExists(t *testing.T) {
	fw := FireWallEngine{}

	// Check if the rule exists
	ruleName := "testwaf"
	exists, err := fw.IsRuleExists(ruleName)
	if err != nil {
		t.Logf("Error checking rule existence: %v", err)
	}

	if exists {
		t.Log("Rule exists.")
	} else {
		t.Log("Rule does not exist.")
	}
}

// ================== IP封禁功能测试 ==================

// TestBlockIP 测试单个IP封禁
func TestBlockIP(t *testing.T) {
	fw := FireWallEngine{}
	testIP := "192.168.100.100"

	t.Logf("开始测试封禁IP: %s", testIP)

	// 先确保IP未被封禁
	fw.UnblockIP(testIP)

	// 封禁IP
	err := fw.BlockIP(testIP, "测试封禁")
	if err != nil {
		t.Fatalf("封禁IP失败: %v", err)
	}
	t.Logf("✓ 成功封禁IP: %s", testIP)

	// 等待规则生效
	time.Sleep(100 * time.Millisecond)

	// 验证IP已被封禁
	blocked, err := fw.IsIPBlocked(testIP)
	if err != nil {
		t.Fatalf("检查IP封禁状态失败: %v", err)
	}
	if !blocked {
		t.Fatalf("IP应该已被封禁，但检查结果为未封禁")
	}
	t.Logf("✓ 验证IP已被封禁")

	// 测试重复封禁
	err = fw.BlockIP(testIP, "重复测试")
	if err == nil {
		t.Logf("注意: 重复封禁应该返回错误，但未返回")
	}

	// 清理：解除封禁
	err = fw.UnblockIP(testIP)
	if err != nil {
		t.Fatalf("解除封禁失败: %v", err)
	}
	t.Logf("✓ 成功解除封禁")

	// 验证IP已解除封禁
	blocked, err = fw.IsIPBlocked(testIP)
	if err != nil {
		t.Fatalf("检查IP封禁状态失败: %v", err)
	}
	if blocked {
		t.Fatalf("IP应该已解除封禁，但检查结果为已封禁")
	}
	t.Logf("✓ 验证IP已解除封禁")
}

// TestUnblockIP 测试解除IP封禁
func TestUnblockIP(t *testing.T) {
	fw := FireWallEngine{}
	testIP := "192.168.100.101"

	t.Logf("开始测试解除封禁IP: %s", testIP)

	// 先封禁IP
	fw.BlockIP(testIP, "测试")
	time.Sleep(100 * time.Millisecond)

	// 解除封禁
	err := fw.UnblockIP(testIP)
	if err != nil {
		t.Fatalf("解除封禁失败: %v", err)
	}
	t.Logf("✓ 成功解除封禁")

	// 测试解除未封禁的IP
	err = fw.UnblockIP(testIP)
	if err == nil {
		t.Logf("注意: 解除未封禁的IP应该返回错误，但未返回")
	}
}

// TestIsIPBlocked 测试检查IP封禁状态
func TestIsIPBlocked(t *testing.T) {
	fw := FireWallEngine{}
	testIP := "192.168.100.102"

	t.Logf("开始测试检查IP封禁状态: %s", testIP)

	// 先确保IP未被封禁
	fw.UnblockIP(testIP)
	time.Sleep(100 * time.Millisecond)

	// 检查未封禁状态
	blocked, err := fw.IsIPBlocked(testIP)
	if err != nil {
		t.Fatalf("检查IP封禁状态失败: %v", err)
	}
	if blocked {
		t.Fatalf("IP应该未被封禁，但检查结果为已封禁")
	}
	t.Logf("✓ 验证IP未被封禁")

	// 封禁IP
	fw.BlockIP(testIP, "测试")
	time.Sleep(100 * time.Millisecond)

	// 检查已封禁状态
	blocked, err = fw.IsIPBlocked(testIP)
	if err != nil {
		t.Fatalf("检查IP封禁状态失败: %v", err)
	}
	if !blocked {
		t.Fatalf("IP应该已被封禁，但检查结果为未封禁")
	}
	t.Logf("✓ 验证IP已被封禁")

	// 清理
	fw.UnblockIP(testIP)
}

// TestBlockIPList 测试批量封禁IP
func TestBlockIPList(t *testing.T) {
	fw := FireWallEngine{}
	testIPs := []string{
		"192.168.100.110",
		"192.168.100.111",
		"192.168.100.112",
		"192.168.100.113",
		"192.168.100.114",
	}

	t.Logf("开始测试批量封禁IP，共 %d 个", len(testIPs))

	// 先清理可能存在的规则
	for _, ip := range testIPs {
		fw.UnblockIP(ip)
	}
	time.Sleep(100 * time.Millisecond)

	// 批量封禁
	successCount, failedIPs, err := fw.BlockIPList(testIPs)
	if err != nil && successCount == 0 {
		t.Fatalf("批量封禁完全失败: %v", err)
	}
	t.Logf("✓ 成功封禁 %d 个IP", successCount)
	if len(failedIPs) > 0 {
		t.Logf("失败的IP: %v", failedIPs)
	}

	// 验证封禁结果
	time.Sleep(100 * time.Millisecond)
	for _, ip := range testIPs {
		blocked, err := fw.IsIPBlocked(ip)
		if err != nil {
			t.Logf("检查IP %s 封禁状态失败: %v", ip, err)
			continue
		}
		if blocked {
			t.Logf("✓ IP %s 已被封禁", ip)
		} else {
			t.Logf("× IP %s 未被封禁", ip)
		}
	}

	// 清理：批量解除封禁
	successCount, failedIPs, err = fw.UnblockIPList(testIPs)
	t.Logf("✓ 批量解除封禁完成，成功 %d 个", successCount)
	if len(failedIPs) > 0 {
		t.Logf("解除失败的IP: %v", failedIPs)
	}
}

// TestUnblockIPList 测试批量解除封禁
func TestUnblockIPList(t *testing.T) {
	fw := FireWallEngine{}
	testIPs := []string{
		"192.168.100.120",
		"192.168.100.121",
		"192.168.100.122",
	}

	t.Logf("开始测试批量解除封禁IP，共 %d 个", len(testIPs))

	// 先批量封禁
	fw.BlockIPList(testIPs)
	time.Sleep(100 * time.Millisecond)

	// 批量解除封禁
	successCount, failedIPs, err := fw.UnblockIPList(testIPs)
	if err != nil && successCount == 0 {
		t.Fatalf("批量解除封禁完全失败: %v", err)
	}
	t.Logf("✓ 成功解除 %d 个IP的封禁", successCount)
	if len(failedIPs) > 0 {
		t.Logf("失败的IP: %v", failedIPs)
	}
}

// TestGetBlockedIPList 测试获取已封禁IP列表
func TestGetBlockedIPList(t *testing.T) {
	fw := FireWallEngine{}
	testIPs := []string{
		"192.168.100.130",
		"192.168.100.131",
		"192.168.100.132",
	}

	t.Log("开始测试获取已封禁IP列表")

	// 先清理
	fw.UnblockIPList(testIPs)
	time.Sleep(100 * time.Millisecond)

	// 批量封禁测试IP
	fw.BlockIPList(testIPs)
	time.Sleep(100 * time.Millisecond)

	// 获取已封禁IP列表
	blockedIPs, err := fw.GetBlockedIPList()
	if err != nil {
		t.Fatalf("获取已封禁IP列表失败: %v", err)
	}

	t.Logf("✓ 当前已封禁IP数量: %d", len(blockedIPs))
	t.Logf("已封禁IP列表: %v", blockedIPs)

	// 验证测试IP是否在列表中
	for _, testIP := range testIPs {
		found := false
		for _, blockedIP := range blockedIPs {
			if blockedIP == testIP {
				found = true
				break
			}
		}
		if found {
			t.Logf("✓ IP %s 在已封禁列表中", testIP)
		} else {
			t.Logf("× IP %s 不在已封禁列表中", testIP)
		}
	}

	// 清理
	fw.UnblockIPList(testIPs)
}

// TestClearAllBlockedIPs 测试清除所有封禁
func TestClearAllBlockedIPs(t *testing.T) {
	fw := FireWallEngine{}
	testIPs := []string{
		"192.168.100.140",
		"192.168.100.141",
		"192.168.100.142",
	}

	t.Log("开始测试清除所有封禁规则")

	// 先添加一些测试规则
	fw.BlockIPList(testIPs)
	time.Sleep(100 * time.Millisecond)

	// 清除所有封禁
	count, err := fw.ClearAllBlockedIPs()
	if err != nil {
		t.Fatalf("清除所有封禁失败: %v", err)
	}
	t.Logf("✓ 成功清除 %d 条封禁规则", count)

	// 验证是否清除干净
	blockedIPs, err := fw.GetBlockedIPList()
	if err != nil {
		t.Fatalf("获取已封禁IP列表失败: %v", err)
	}
	t.Logf("清除后剩余封禁规则数量: %d", len(blockedIPs))
}

// TestCIDRNotation 测试CIDR格式的IP封禁
func TestCIDRNotation(t *testing.T) {
	fw := FireWallEngine{}
	testCIDR := "192.168.100.0/24"

	t.Logf("开始测试CIDR格式封禁: %s", testCIDR)

	// 先清理
	fw.UnblockIP(testCIDR)
	time.Sleep(100 * time.Millisecond)

	// 封禁CIDR
	err := fw.BlockIP(testCIDR, "测试CIDR封禁")
	if err != nil {
		t.Fatalf("封禁CIDR失败: %v", err)
	}
	t.Logf("✓ 成功封禁CIDR: %s", testCIDR)

	// 验证封禁状态
	time.Sleep(100 * time.Millisecond)
	blocked, err := fw.IsIPBlocked(testCIDR)
	if err != nil {
		t.Fatalf("检查CIDR封禁状态失败: %v", err)
	}
	if !blocked {
		t.Logf("注意: CIDR应该已被封禁，但检查结果为未封禁")
	} else {
		t.Logf("✓ 验证CIDR已被封禁")
	}

	// 清理
	err = fw.UnblockIP(testCIDR)
	if err != nil {
		t.Fatalf("解除CIDR封禁失败: %v", err)
	}
	t.Logf("✓ 成功解除CIDR封禁")
}

// ================== 性能测试 ==================

// BenchmarkBlockIP 性能测试：封禁单个IP
func BenchmarkBlockIP(b *testing.B) {
	fw := FireWallEngine{}
	baseIP := "10.0.0."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := fmt.Sprintf("%s%d", baseIP, i%254+1)
		fw.BlockIP(ip, "benchmark test")
	}

	// 清理
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		ip := fmt.Sprintf("%s%d", baseIP, i%254+1)
		fw.UnblockIP(ip)
	}
}

// BenchmarkIsIPBlocked 性能测试：检查IP封禁状态
func BenchmarkIsIPBlocked(b *testing.B) {
	fw := FireWallEngine{}
	testIP := "10.0.0.100"

	// 准备：先封禁一个IP
	fw.BlockIP(testIP, "benchmark test")
	time.Sleep(100 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fw.IsIPBlocked(testIP)
	}

	// 清理
	b.StopTimer()
	fw.UnblockIP(testIP)
}
