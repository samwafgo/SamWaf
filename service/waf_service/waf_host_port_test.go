package waf_service

import (
	"strconv"
	"strings"
	"testing"
)

// checkBindMorePortContains 模拟修复后 CheckAvailablePortExistApi 中
// "扫描 BindMorePort 字段" 的核心逻辑，可脱离 DB 独立测试
func checkBindMorePortContains(bindMorePorts []string, targetPort int) bool {
	portStr := strconv.Itoa(targetPort)
	for _, bindMorePort := range bindMorePorts {
		if bindMorePort == "" {
			continue
		}
		for _, p := range strings.Split(bindMorePort, ",") {
			if strings.TrimSpace(p) == portStr {
				return true
			}
		}
	}
	return false
}

// TestCheckBindMorePort_ContainsPort
// Fix3 核心逻辑：给定一组主机的 BindMorePort 字段值，判断目标端口是否被使用
func TestCheckBindMorePort_ContainsPort(t *testing.T) {
	tests := []struct {
		name          string
		bindMorePorts []string // 模拟多个主机的 bind_more_port 字段
		targetPort    int
		want          bool
	}{
		{
			name:          "端口在副端口列表中（单个主机）",
			bindMorePorts: []string{"8080,9090"},
			targetPort:    8080,
			want:          true,
		},
		{
			name:          "端口在副端口列表末尾",
			bindMorePorts: []string{"8080,9090"},
			targetPort:    9090,
			want:          true,
		},
		{
			name:          "端口不在任何副端口列表中",
			bindMorePorts: []string{"8080,9090", "7070,7071"},
			targetPort:    6060,
			want:          false,
		},
		{
			name:          "端口在第二个主机的副端口中",
			bindMorePorts: []string{"8080", "9090,6060"},
			targetPort:    6060,
			want:          true,
		},
		{
			name:          "副端口列表为空",
			bindMorePorts: []string{"", ""},
			targetPort:    8080,
			want:          false,
		},
		{
			name:          "副端口有多余空格",
			bindMorePorts: []string{" 8080 , 9090 "},
			targetPort:    8080,
			want:          true,
		},
		{
			name:          "单个副端口精确匹配",
			bindMorePorts: []string{"8080"},
			targetPort:    8080,
			want:          true,
		},
		{
			name:          "避免数字前缀误匹配：808 不应匹配 8080",
			bindMorePorts: []string{"8080,9090"},
			targetPort:    808,
			want:          false,
		},
		{
			name:          "避免数字后缀误匹配：80800 不应匹配 8080",
			bindMorePorts: []string{"8080,9090"},
			targetPort:    80800,
			want:          false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := checkBindMorePortContains(tc.bindMorePorts, tc.targetPort)
			if got != tc.want {
				t.Errorf("checkBindMorePortContains(%v, %d) = %v，期望 %v",
					tc.bindMorePorts, tc.targetPort, got, tc.want)
			}
		})
	}
}

// TestCheckAvailablePortExistApi_BindMorePortScenario
// 文档化测试：描述 Fix3 修复前后的行为差异
//
// 修复前：CheckAvailablePortExistApi 只查 WHERE port=X
//   - 站点 A: Port=80, BindMorePort="8080"
//   - CheckAvailablePortExistApi(8080) → 返回 0（误判为无人使用）
//   - 结果：RemovePortServer 会把 8080 端口的 HTTP server 关掉
//
// 修复后：同时扫描 bind_more_port 字段
//   - CheckAvailablePortExistApi(8080) → 返回 1（正确识别为在用）
//   - 结果：RemovePortServer 不会关闭 8080 端口
func TestCheckAvailablePortExistApi_BindMorePortScenario(t *testing.T) {
	// 模拟：主机 A Port=80 BindMorePort="8080"，没有主机以 8080 为主端口
	mainPortHosts := []int{80, 443, 9090}             // 所有主机的主端口
	bindMorePortList := []string{"8080", "7070,7071"} // 所有主机的 BindMorePort 字段

	targetPort := 8080

	// 旧逻辑：只查主端口
	foundByMainPort := false
	for _, p := range mainPortHosts {
		if p == targetPort {
			foundByMainPort = true
			break
		}
	}

	// 新逻辑：主端口 + BindMorePort
	foundByBindMore := checkBindMorePortContains(bindMorePortList, targetPort)
	foundNew := foundByMainPort || foundByBindMore

	if foundByMainPort {
		t.Errorf("测试数据有误：不应该有主机以 %d 为主端口", targetPort)
	}
	if !foundByBindMore {
		t.Error("Fix3：新逻辑应能在 BindMorePort 中找到端口 8080")
	}
	if !foundNew {
		t.Error("Fix3：修复后的逻辑应返回端口 8080 仍在使用中")
	}

	// 明确表达：旧逻辑会错误地关掉端口，新逻辑不会
	t.Logf("旧逻辑 foundByMainPort=%v（会错误关掉端口）", foundByMainPort)
	t.Logf("新逻辑 foundNew=%v（正确保留端口）", foundNew)
}
