//go:build windows

package firewall

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
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
	const firewallRegistryPath = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, firewallRegistryPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()

	enabled, _, err := key.GetIntegerValue("EnableFirewall")
	if err != nil {
		return false
	}
	return enabled == 1
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
	// 构建命令参数
	args := []string{"advfirewall", "firewall", "add", "rule", "name=" + ruleName, "dir=in", "action=" + action}

	// 处理协议参数 - Windows netsh 不支持 "any" 协议，需要分别创建规则或使用 any
	if proc == PROTOCOL_ANY || proc == "any" {
		// 对于 any 协议，不指定 protocol 和 localport 参数，这样会匹配所有协议
		args = append(args, "remoteip="+ipToAdd)
		fmt.Printf("[DEBUG] 添加防火墙规则 (ANY协议): name=%s, action=%s, remoteip=%s\n", ruleName, action, ipToAdd)
	} else {
		// 指定具体协议
		args = append(args, "protocol="+proc)
		if localport != "" && localport != "any" {
			args = append(args, "localport="+localport)
		}
		args = append(args, "remoteip="+ipToAdd)
		fmt.Printf("[DEBUG] 添加防火墙规则: name=%s, action=%s, protocol=%s, localport=%s, remoteip=%s\n",
			ruleName, action, proc, localport, ipToAdd)
	}

	cmd := exec.Command("netsh", args...)
	fmt.Printf("[DEBUG] 执行命令: netsh %s\n", strings.Join(args, " "))

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
	fmt.Printf("[DEBUG] 删除防火墙规则: name=%s\n", ruleName)

	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s", ruleName))
	err, output := fw.executeCommand(cmd)

	fmt.Printf("[DEBUG] 删除规则输出: %s\n", output)

	//已删除 1 规则。确定。
	if err == nil {
		if strings.Contains(output, "No rules match the specified criteria") {
			fmt.Printf("[WARN] 规则不存在: %s\n", ruleName)
			return false, fmt.Errorf("error:delete firewall rule: %s, output: %s", ruleName, output)
		}
		if strings.Contains(output, "没有与指定标准相匹配的规则。") {
			fmt.Printf("[WARN] 规则不存在: %s\n", ruleName)
			return false, fmt.Errorf("error:delete firewall rule: %s, output: %s", ruleName, output)
		}
		if strings.Contains(output, "已删除") || strings.Contains(output, "Ok") {
			fmt.Printf("[DEBUG] 删除规则成功: %s\n", ruleName)
			return true, nil
		}
	}

	fmt.Printf("[ERROR] 删除规则失败: %s, error: %v\n", ruleName, err)
	return false, fmt.Errorf("error:delete firewall rule: %s, output: %s", ruleName, output)
}
func (fw *FireWallEngine) IsRuleExists(ruleName string) (bool, error) {
	fmt.Printf("[DEBUG] 检查规则是否存在: name=%s\n", ruleName)

	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	err, output := fw.executeCommand(cmd)

	if err == nil {
		if strings.Contains(output, "No rules match the specified criteria") {
			fmt.Printf("[DEBUG] 规则不存在 (EN): %s\n", ruleName)
			return false, nil
		}
		if strings.Contains(output, "没有与指定标准相匹配的规则。") {
			fmt.Printf("[DEBUG] 规则不存在 (CN): %s\n", ruleName)
			return false, nil
		}
		// 改进规则存在的判断逻辑 - 只要输出中包含规则名就认为存在
		if strings.Contains(output, ruleName) {
			fmt.Printf("[DEBUG] 规则存在: %s\n", ruleName)
			return true, nil
		}
	}

	fmt.Printf("[WARN] 检查规则失败: %s, error: %v, output: %s\n", ruleName, err, output)
	return false, fmt.Errorf("failed to show firewall rule: %s, output: %s", err, string(output))
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

// BlockIP 封禁指定IP地址（入站+出站双向封禁）
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

	// 添加入站阻止规则 - 使用 any 协议会匹配所有协议
	err := fw.AddRule(ruleName, ip, ACTION_BLOCK, PROTOCOL_ANY, "")
	if err != nil {
		fmt.Printf("[ERROR] 封禁IP失败: %s, error: %v\n", ip, err)
		return fmt.Errorf("failed to block IP %s: %v", ip, err)
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

	// 删除规则
	success, err := fw.DeleteRule(ruleName)
	if err != nil {
		fmt.Printf("[ERROR] 解除IP封禁失败: %s, error: %v\n", ip, err)
		return fmt.Errorf("failed to unblock IP %s: %v", ip, err)
	}

	if !success {
		fmt.Printf("[ERROR] 删除规则失败: %s\n", ip)
		return fmt.Errorf("failed to unblock IP %s: rule deletion failed", ip)
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
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all")
	err, output := fw.executeCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocked IP list: %v", err)
	}

	blockedIPs := []string{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 查找包含规则前缀的规则名
		if strings.Contains(line, RULE_PREFIX) {
			// 提取IP地址
			parts := strings.Split(line, RULE_PREFIX)
			if len(parts) > 1 {
				ip := strings.TrimSpace(strings.Split(parts[1], " ")[0])
				ip = strings.ReplaceAll(ip, "-", ".")
				if ip != "" {
					blockedIPs = append(blockedIPs, ip)
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
