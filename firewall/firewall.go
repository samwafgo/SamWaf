//go:build linux

package firewall

import (
	"bufio"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
)

type Charset string

const (
	UTF8    = Charset("UTF-8")
	GB18030 = Charset("GB18030")
)

const ACTION_ALLOW string = "allow" //，allow 表示允许连接，block 表示阻止连接，bypass 表示只允许安全连接。 =
const ACTION_BLOCK string = "block"
const ACTION_BYPASS string = "bypass"

const (
	RULE_PREFIX    = "SamWAF_Block_" // 规则名称前缀
	PROTOCOL_ANY   = "any"           // 任意协议
	PROTOCOL_TCP   = "TCP"           // TCP 协议
	PROTOCOL_UDP   = "UDP"           // UDP 协议
	DIRECTION_IN   = "in"            // 入站
	DIRECTION_OUT  = "out"           // 出站
	DIRECTION_BOTH = "both"          // 双向
)

type FireWallEngine struct {
}

// IPBlockInfo IP封禁信息结构
type IPBlockInfo struct {
	IP        string    // IP地址
	RuleName  string    // 规则名称
	Reason    string    // 封禁原因（预留字段，实际存储在数据库）
	BlockTime time.Time // 封禁时间（预留字段，实际存储在数据库）
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

func (fw *FireWallEngine) executeCommand(cmd *exec.Cmd) (error error, printstr string) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println(err)
		return err, err.Error()
	}
	cmd.Start()
	in := bufio.NewScanner(stdout)
	printstr = ""
	for in.Scan() {
		cmdRe := ConvertByte2String(in.Bytes(), "GB18030")
		//fmt.Println(cmdRe)
		printstr += cmdRe
	}
	cmd.Wait()
	return nil, printstr
}

func (fw *FireWallEngine) AddRule(ruleName, ipToAdd, action, proc, localport string) error {
	// iptables -I INPUT 1 -s <ip> -j DROP
	// 使用 -I 插入到链的开头，确保规则优先执行
	fmt.Printf("[DEBUG] 添加防火墙规则: ip=%s\n", ipToAdd)

	cmd := exec.Command("iptables", "-I", "INPUT", "1", "-s", ipToAdd, "-j", "DROP")
	fmt.Printf("[DEBUG] 执行命令: iptables -I INPUT 1 -s %s -j DROP\n", ipToAdd)

	err, output := fw.executeCommand(cmd)
	if err != nil {
		fmt.Printf("[ERROR] 添加规则失败: %v, 输出: %s\n", err, output)
		return err
	}

	fmt.Printf("[DEBUG] 添加规则成功, 输出: %s\n", output)
	return err
}

func (fw *FireWallEngine) EditRule(ruleNum int, newRule string) error {
	return fmt.Errorf("editRule is not supported on Windows")
}

func (fw *FireWallEngine) DeleteRule(ruleName string) (bool, error) {
	// iptables -D INPUT -s <ip> -j DROP
	// 从规则名中提取IP
	fmt.Printf("[DEBUG] 删除防火墙规则: name=%s\n", ruleName)

	ip := extractIPFromRuleName(ruleName)
	if ip == "" {
		fmt.Printf("[ERROR] 无效的规则名: %s\n", ruleName)
		return false, fmt.Errorf("invalid rule name: %s", ruleName)
	}

	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	fmt.Printf("[DEBUG] 执行命令: iptables -D INPUT -s %s -j DROP\n", ip)

	err, output := fw.executeCommand(cmd)
	if err != nil {
		fmt.Printf("[ERROR] 删除规则失败: %v, 输出: %s\n", err, output)
		return false, fmt.Errorf("failed to delete rule: %s, output: %s", err, output)
	}

	fmt.Printf("[DEBUG] 删除规则成功\n")
	return true, nil
}
func (fw *FireWallEngine) IsRuleExists(ruleName string) (bool, error) {
	// 从规则名中提取IP
	fmt.Printf("[DEBUG] 检查规则是否存在: name=%s\n", ruleName)

	ip := extractIPFromRuleName(ruleName)
	if ip == "" {
		fmt.Printf("[ERROR] 无效的规则名: %s\n", ruleName)
		return false, fmt.Errorf("invalid rule name: %s", ruleName)
	}

	cmd := exec.Command("iptables-save")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[ERROR] 获取iptables规则失败: %v\n", err)
		return false, fmt.Errorf("failed to list iptables rules: %s, output: %s", err, string(output))
	}

	// 查找DROP规则
	exists := strings.Contains(string(output), "-A INPUT -s "+ip+" -j DROP") ||
		strings.Contains(string(output), "-A INPUT -s "+ip+"/32 -j DROP")

	if exists {
		fmt.Printf("[DEBUG] 规则存在: %s (IP: %s)\n", ruleName, ip)
	} else {
		fmt.Printf("[DEBUG] 规则不存在: %s (IP: %s)\n", ruleName, ip)
	}

	return exists, nil
}
func ConvertByte2String(byte []byte, charset Charset) string {
	var str string
	switch charset {
	case GB18030:
		var decodeBytes, _ = simplifiedchinese.GB18030.NewDecoder().Bytes(byte)
		str = string(decodeBytes)
	case UTF8:
		fallthrough
	default:
		str = string(byte)
	}
	return str
}

// BlockIP 封禁指定IP地址
// ip: 要封禁的IP地址，支持单个IP或CIDR格式
// reason: 封禁原因（可选，后续会存储到数据库）
func (fw *FireWallEngine) BlockIP(ip string, reason string) error {
	fmt.Printf("[INFO] 开始封禁IP: %s, 原因: %s\n", ip, reason)

	// 生成规则名称
	ruleName := generateRuleName(ip)
	fmt.Printf("[DEBUG] 生成规则名称: %s\n", ruleName)

	// 检查规则是否已存在
	exists, _ := fw.IsRuleExists(ruleName)
	if exists {
		fmt.Printf("[WARN] IP %s 已经被封禁\n", ip)
		return fmt.Errorf("IP %s already blocked", ip)
	}

	// 添加iptables规则: iptables -I INPUT 1 -s <ip> -j DROP
	// 使用 -I 插入到链的开头，确保规则在 ESTABLISHED 连接规则之前执行
	cmd := exec.Command("iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP")
	err, output := fw.executeCommand(cmd)
	if err != nil {
		fmt.Printf("[ERROR] 封禁IP失败: %s, error: %v, output: %s\n", ip, err, output)
		return fmt.Errorf("failed to block IP %s: %v, output: %s", ip, err, output)
	}

	fmt.Printf("[INFO] 成功封禁IP: %s\n", ip)
	return nil
}

// UnblockIP 解除对指定IP的封禁
func (fw *FireWallEngine) UnblockIP(ip string) error {
	fmt.Printf("[INFO] 开始解除IP封禁: %s\n", ip)

	ruleName := generateRuleName(ip)

	// 检查规则是否存在
	exists, _ := fw.IsRuleExists(ruleName)
	if !exists {
		fmt.Printf("[WARN] IP %s 未被封禁\n", ip)
		return fmt.Errorf("IP %s is not blocked", ip)
	}

	// 删除iptables规则: iptables -D INPUT -s <ip> -j DROP
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	err, output := fw.executeCommand(cmd)
	if err != nil {
		fmt.Printf("[ERROR] 解除IP封禁失败: %s, error: %v, output: %s\n", ip, err, output)
		return fmt.Errorf("failed to unblock IP %s: %v, output: %s", ip, err, output)
	}

	fmt.Printf("[INFO] 成功解除IP封禁: %s\n", ip)
	return nil
}

// IsIPBlocked 检查IP是否已被封禁
func (fw *FireWallEngine) IsIPBlocked(ip string) (bool, error) {
	fmt.Printf("[DEBUG] 检查IP是否被封禁: %s\n", ip)
	ruleName := generateRuleName(ip)
	blocked, err := fw.IsRuleExists(ruleName)
	if blocked {
		fmt.Printf("[DEBUG] IP %s 已被封禁\n", ip)
	} else {
		fmt.Printf("[DEBUG] IP %s 未被封禁\n", ip)
	}
	return blocked, err
}

// BlockIPList 批量封禁IP列表
// ips: IP地址列表
// 返回成功数量、失败的IP列表和错误信息
func (fw *FireWallEngine) BlockIPList(ips []string) (successCount int, failedIPs []string, err error) {
	successCount = 0
	failedIPs = []string{}

	for _, ip := range ips {
		err := fw.BlockIP(ip, "")
		if err != nil {
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
	successCount = 0
	failedIPs = []string{}

	for _, ip := range ips {
		err := fw.UnblockIP(ip)
		if err != nil {
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
		// 查找DROP规则: -A INPUT -s <ip> -j DROP
		if strings.Contains(line, "-A INPUT -s") && strings.Contains(line, "-j DROP") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "-s" && i+1 < len(parts) {
					ip := parts[i+1]
					// 移除CIDR后缀（如果有）
					ip = strings.TrimSuffix(ip, "/32")
					blockedIPs = append(blockedIPs, ip)
					break
				}
			}
		}
	}

	return blockedIPs, nil
}

// ClearAllBlockedIPs 清除所有封禁规则（谨慎使用）
func (fw *FireWallEngine) ClearAllBlockedIPs() (int, error) {
	blockedIPs, err := fw.GetBlockedIPList()
	if err != nil {
		return 0, err
	}

	count := 0
	for _, ip := range blockedIPs {
		err := fw.UnblockIP(ip)
		if err == nil {
			count++
		}
	}

	return count, nil
}

// generateRuleName 生成规则名称
func generateRuleName(ip string) string {
	// 将IP中的点替换为下划线，避免命令行解析问题
	safeName := strings.ReplaceAll(ip, ".", "_")
	safeName = strings.ReplaceAll(safeName, "/", "_")
	return RULE_PREFIX + safeName
}

// extractIPFromRuleName 从规则名中提取IP
func extractIPFromRuleName(ruleName string) string {
	if !strings.HasPrefix(ruleName, RULE_PREFIX) {
		return ""
	}
	safeName := strings.TrimPrefix(ruleName, RULE_PREFIX)
	ip := strings.ReplaceAll(safeName, "_", ".")
	return ip
}
