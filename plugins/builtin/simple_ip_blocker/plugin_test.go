package main

import (
	"context"
	"testing"

	plugininterface "SamWaf/plugin/interface"
)

// TestPluginBasics 测试插件基础功能
func TestPluginBasics(t *testing.T) {
	plugin := NewSimpleIPBlockerPlugin()

	// 测试基础信息
	if plugin.Name() != "Simple IP Blocker" {
		t.Errorf("期望插件名称为 'Simple IP Blocker', 实际得到 '%s'", plugin.Name())
	}

	if plugin.Version() != "1.0.0" {
		t.Errorf("期望版本为 '1.0.0', 实际得到 '%s'", plugin.Version())
	}

	if plugin.Type() != "ip_filter" {
		t.Errorf("期望类型为 'ip_filter', 实际得到 '%s'", plugin.Type())
	}
}

// TestPluginInit 测试插件初始化
func TestPluginInit(t *testing.T) {
	plugin := NewSimpleIPBlockerPlugin()

	config := map[string]interface{}{
		"blocked_ips": []interface{}{
			"1.1.1.1",
			"2.2.2.2",
		},
		"block_reason": "测试屏蔽",
	}

	err := plugin.Init(config)
	if err != nil {
		t.Fatalf("插件初始化失败: %v", err)
	}

	// 验证屏蔽IP已加载
	blockedIPs := plugin.GetBlockedIPs()
	if len(blockedIPs) < 2 {
		t.Errorf("期望至少有2个屏蔽IP，实际有 %d 个", len(blockedIPs))
	}
}

// TestIPFilter 测试IP过滤功能
func TestIPFilter(t *testing.T) {
	plugin := NewSimpleIPBlockerPlugin()
	plugin.Init(map[string]interface{}{})

	ctx := context.Background()

	// 测试用例
	testCases := []struct {
		name          string
		ip            string
		expectAllowed bool
		expectRisk    int
	}{
		{
			name:          "屏蔽IP - 8.8.8.8",
			ip:            "8.8.8.8",
			expectAllowed: false,
			expectRisk:    8,
		},
		{
			name:          "正常IP - 192.168.1.1",
			ip:            "192.168.1.1",
			expectAllowed: true,
			expectRisk:    0,
		},
		{
			name:          "正常IP - 10.0.0.1",
			ip:            "10.0.0.1",
			expectAllowed: true,
			expectRisk:    0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &plugininterface.IPFilterRequest{
				IP:          tc.ip,
				RequestPath: "/test",
				UserAgent:   "test-agent",
			}

			resp, err := plugin.Filter(ctx, req)
			if err != nil {
				t.Fatalf("过滤失败: %v", err)
			}

			if resp.Allowed != tc.expectAllowed {
				t.Errorf("IP %s: 期望 Allowed=%v, 实际得到 %v",
					tc.ip, tc.expectAllowed, resp.Allowed)
			}

			if resp.RiskLevel != tc.expectRisk {
				t.Errorf("IP %s: 期望 RiskLevel=%d, 实际得到 %d",
					tc.ip, tc.expectRisk, resp.RiskLevel)
			}
		})
	}
}

// TestWafCheck 测试WAF检查功能
func TestWafCheck(t *testing.T) {
	plugin := NewSimpleIPBlockerPlugin()
	plugin.Init(map[string]interface{}{})

	ctx := context.Background()

	// 测试屏蔽IP
	req := &plugininterface.WafCheckRequest{
		RequestID: "test-001",
		IP:        "8.8.8.8",
		Method:    "GET",
		URL:       "/api/test",
		Headers: map[string]string{
			"User-Agent": "test-agent",
		},
	}

	resp, err := plugin.Check(ctx, req)
	if err != nil {
		t.Fatalf("WAF检查失败: %v", err)
	}

	if resp.Allowed {
		t.Error("期望屏蔽 8.8.8.8，但实际允许通过")
	}

	if resp.RiskLevel != 8 {
		t.Errorf("期望风险等级为 8，实际得到 %d", resp.RiskLevel)
	}

	if resp.Action != "block" {
		t.Errorf("期望动作为 'block'，实际得到 '%s'", resp.Action)
	}
}

// TestDynamicIPManagement 测试动态IP管理
func TestDynamicIPManagement(t *testing.T) {
	plugin := NewSimpleIPBlockerPlugin()
	plugin.Init(map[string]interface{}{})

	// 添加新的屏蔽IP
	plugin.AddBlockedIP("3.3.3.3", "动态添加的屏蔽IP")

	// 验证已添加
	blocked, reason := plugin.IsBlocked("3.3.3.3")
	if !blocked {
		t.Error("期望 3.3.3.3 被屏蔽，但实际未屏蔽")
	}
	if reason != "动态添加的屏蔽IP" {
		t.Errorf("期望原因为 '动态添加的屏蔽IP'，实际得到 '%s'", reason)
	}

	// 移除屏蔽IP
	plugin.RemoveBlockedIP("3.3.3.3")

	// 验证已移除
	blocked, _ = plugin.IsBlocked("3.3.3.3")
	if blocked {
		t.Error("期望 3.3.3.3 已移除屏蔽，但实际仍被屏蔽")
	}
}

// TestHealthCheck 测试健康检查
func TestHealthCheck(t *testing.T) {
	plugin := NewSimpleIPBlockerPlugin()
	plugin.Init(map[string]interface{}{})

	ctx := context.Background()
	err := plugin.HealthCheck(ctx)
	if err != nil {
		t.Errorf("健康检查失败: %v", err)
	}
}

// TestShutdown 测试插件关闭
func TestShutdown(t *testing.T) {
	plugin := NewSimpleIPBlockerPlugin()
	plugin.Init(map[string]interface{}{})

	err := plugin.Shutdown()
	if err != nil {
		t.Errorf("插件关闭失败: %v", err)
	}

	// 验证资源已清理
	if len(plugin.blockedIPs) != 0 {
		t.Error("期望屏蔽IP列表已清空，但实际还有数据")
	}
}

// BenchmarkIPFilter 性能基准测试
func BenchmarkIPFilter(b *testing.B) {
	plugin := NewSimpleIPBlockerPlugin()
	plugin.Init(map[string]interface{}{})

	ctx := context.Background()
	req := &plugininterface.IPFilterRequest{
		IP:          "192.168.1.1",
		RequestPath: "/test",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plugin.Filter(ctx, req)
	}
}
