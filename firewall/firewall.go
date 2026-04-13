//go:build linux

package firewall

import (
	"bufio"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Charset string

const (
	UTF8    = Charset("UTF-8")
	GB18030 = Charset("GB18030")
)

const ACTION_ALLOW string = "allow"
const ACTION_BLOCK string = "block"
const ACTION_BYPASS string = "bypass"

const (
	PROTOCOL_ANY   = "any"  // 任意协议
	PROTOCOL_TCP   = "TCP"  // TCP 协议
	PROTOCOL_UDP   = "UDP"  // UDP 协议
	DIRECTION_IN   = "in"   // 入站
	DIRECTION_OUT  = "out"  // 出站
	DIRECTION_BOTH = "both" // 双向
)

type FireWallEngine struct{}

// IPBlockInfo IP封禁信息结构
type IPBlockInfo struct {
	IP        string    // IP地址
	Reason    string    // 封禁原因
	BlockTime time.Time // 封禁时间
	Protocol  string    // 协议类型
	Direction string    // 方向
}

func (fw *FireWallEngine) IsFirewallEnabled() bool {
	if runtime.GOOS == "linux" {
		out, err := exec.Command("iptables", "-L").CombinedOutput()
		if err != nil {
			return false
		}
		return len(out) > 0
	}
	return false
}

func (fw *FireWallEngine) executeCommand(cmd *exec.Cmd) (error, string) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println(err)
		return err, err.Error()
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Println(err)
		return err, err.Error()
	}
	if err := cmd.Start(); err != nil {
		fmt.Println(err)
		return err, err.Error()
	}
	var printstr string
	in := bufio.NewScanner(stdout)
	for in.Scan() {
		printstr += in.Text() + "\n"
	}
	errScanner := bufio.NewScanner(stderr)
	for errScanner.Scan() {
		printstr += errScanner.Text() + "\n"
	}
	waitErr := cmd.Wait()
	if waitErr != nil {
		return waitErr, printstr
	}
	return nil, printstr
}

// isIPInRules 直接用原始 IP 检查 iptables 中是否存在 DROP 规则，支持单 IP 和 CIDR
func (fw *FireWallEngine) isIPInRules(ip string) (bool, error) {
	cmd := exec.Command("iptables-save")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[ERROR] 获取iptables规则失败: %v\n", err)
		return false, fmt.Errorf("failed to list iptables rules: %v, output: %s", err, string(output))
	}
	outputStr := string(output)
	// 单 IP 在 iptables-save 中会带 /32 后缀，CIDR 原样存储
	exists := strings.Contains(outputStr, "-A INPUT -s "+ip+" -j DROP") ||
		strings.Contains(outputStr, "-A INPUT -s "+ip+"/32 -j DROP")
	return exists, nil
}

// AddRule Linux 下忽略规则名，直接用 ipToAdd 执行 iptables 封禁
func (fw *FireWallEngine) AddRule(ruleName, ipToAdd, action, proc, localport string) error {
	fmt.Printf("[DEBUG] 添加防火墙规则: ip=%s\n", ipToAdd)
	cmd := exec.Command("iptables", "-I", "INPUT", "1", "-s", ipToAdd, "-j", "DROP")
	fmt.Printf("[DEBUG] 执行命令: iptables -I INPUT 1 -s %s -j DROP\n", ipToAdd)
	err, output := fw.executeCommand(cmd)
	if err != nil {
		fmt.Printf("[ERROR] 添加规则失败: %v, 输出: %s\n", err, output)
		return fmt.Errorf("failed to add rule for %s: %v, output: %s", ipToAdd, err, output)
	}
	fmt.Printf("[DEBUG] 添加规则成功, 输出: %s\n", output)
	return nil
}

func (fw *FireWallEngine) EditRule(ruleNum int, newRule string) error {
	return fmt.Errorf("editRule is not supported on Linux")
}

// DeleteRule Linux 下直接将 ruleName 当作 IP 执行 iptables 删除
// 生产代码不直接调用此方法（通过 UnblockIP），此方法保留供测试使用
func (fw *FireWallEngine) DeleteRule(ruleName string) (bool, error) {
	fmt.Printf("[DEBUG] 删除防火墙规则: ip=%s\n", ruleName)
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ruleName, "-j", "DROP")
	fmt.Printf("[DEBUG] 执行命令: iptables -D INPUT -s %s -j DROP\n", ruleName)
	err, output := fw.executeCommand(cmd)
	if err != nil {
		fmt.Printf("[ERROR] 删除规则失败: %v, 输出: %s\n", err, output)
		return false, fmt.Errorf("failed to delete rule for %s: %v, output: %s", ruleName, err, output)
	}
	fmt.Printf("[DEBUG] 删除规则成功\n")
	return true, nil
}

// IsRuleExists Linux 下直接将 ruleName 当作 IP 检查 iptables 规则
// 生产代码不直接调用此方法，此方法保留供测试使用
func (fw *FireWallEngine) IsRuleExists(ruleName string) (bool, error) {
	fmt.Printf("[DEBUG] 检查规则是否存在: ip=%s\n", ruleName)
	return fw.isIPInRules(ruleName)
}

// BlockIP 封禁指定IP地址，支持单个IP或CIDR格式
func (fw *FireWallEngine) BlockIP(ip string, reason string) error {
	fmt.Printf("[INFO] 开始封禁IP: %s, 原因: %s\n", ip, reason)

	exists, err := fw.isIPInRules(ip)
	if err != nil {
		return fmt.Errorf("检查IP状态失败: %v", err)
	}
	if exists {
		fmt.Printf("[WARN] IP %s 已经被封禁\n", ip)
		return fmt.Errorf("IP %s already blocked", ip)
	}

	cmd := exec.Command("iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP")
	fmt.Printf("[DEBUG] 执行命令: iptables -I INPUT 1 -s %s -j DROP\n", ip)
	execErr, output := fw.executeCommand(cmd)
	if execErr != nil {
		fmt.Printf("[ERROR] 封禁IP失败: %s, error: %v, output: %s\n", ip, execErr, output)
		return fmt.Errorf("failed to block IP %s: %v, output: %s", ip, execErr, output)
	}

	fmt.Printf("[INFO] 成功封禁IP: %s\n", ip)
	return nil
}

// UnblockIP 解除对指定IP的封禁，支持单个IP或CIDR格式
func (fw *FireWallEngine) UnblockIP(ip string) error {
	fmt.Printf("[INFO] 开始解除IP封禁: %s\n", ip)

	exists, err := fw.isIPInRules(ip)
	if err != nil {
		return fmt.Errorf("检查IP状态失败: %v", err)
	}
	if !exists {
		fmt.Printf("[WARN] IP %s 未被封禁\n", ip)
		return fmt.Errorf("IP %s is not blocked", ip)
	}

	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	fmt.Printf("[DEBUG] 执行命令: iptables -D INPUT -s %s -j DROP\n", ip)
	execErr, output := fw.executeCommand(cmd)
	if execErr != nil {
		fmt.Printf("[ERROR] 解除IP封禁失败: %s, error: %v, output: %s\n", ip, execErr, output)
		return fmt.Errorf("failed to unblock IP %s: %v, output: %s", ip, execErr, output)
	}

	fmt.Printf("[INFO] 成功解除IP封禁: %s\n", ip)
	return nil
}

// IsIPBlocked 检查IP是否已被封禁
func (fw *FireWallEngine) IsIPBlocked(ip string) (bool, error) {
	fmt.Printf("[DEBUG] 检查IP是否被封禁: %s\n", ip)
	blocked, err := fw.isIPInRules(ip)
	if blocked {
		fmt.Printf("[DEBUG] IP %s 已被封禁\n", ip)
	} else {
		fmt.Printf("[DEBUG] IP %s 未被封禁\n", ip)
	}
	return blocked, err
}

// BlockIPList 批量封禁IP列表
func (fw *FireWallEngine) BlockIPList(ips []string) (successCount int, failedIPs []string, err error) {
	failedIPs = []string{}
	for _, ip := range ips {
		if e := fw.BlockIP(ip, ""); e != nil {
			failedIPs = append(failedIPs, ip)
		} else {
			successCount++
		}
	}
	if len(failedIPs) > 0 {
		return successCount, failedIPs, fmt.Errorf("failed to block %d IPs", len(failedIPs))
	}
	return successCount, failedIPs, nil
}

// UnblockIPList 批量解除IP封禁
func (fw *FireWallEngine) UnblockIPList(ips []string) (successCount int, failedIPs []string, err error) {
	failedIPs = []string{}
	for _, ip := range ips {
		if e := fw.UnblockIP(ip); e != nil {
			failedIPs = append(failedIPs, ip)
		} else {
			successCount++
		}
	}
	if len(failedIPs) > 0 {
		return successCount, failedIPs, fmt.Errorf("failed to unblock %d IPs", len(failedIPs))
	}
	return successCount, failedIPs, nil
}

// GetBlockedIPList 获取所有已封禁的IP列表
func (fw *FireWallEngine) GetBlockedIPList() ([]string, error) {
	cmd := exec.Command("iptables-save")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get blocked IP list: %v", err)
	}

	blockedIPs := []string{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "-A INPUT -s") && strings.Contains(line, "-j DROP") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "-s" && i+1 < len(parts) {
					ip := parts[i+1]
					// 单个IP在 iptables-save 中会带 /32 后缀，去掉还原原始格式；CIDR 不受影响
					ip = strings.TrimSuffix(ip, "/32")
					blockedIPs = append(blockedIPs, ip)
					break
				}
			}
		}
	}
	return blockedIPs, nil
}

// ClearAllBlockedIPs 清除所有封禁规则
func (fw *FireWallEngine) ClearAllBlockedIPs() (int, error) {
	blockedIPs, err := fw.GetBlockedIPList()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, ip := range blockedIPs {
		if fw.UnblockIP(ip) == nil {
			count++
		}
	}
	return count, nil
}
