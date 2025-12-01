//go:build darwin

package firewall

import (
	"bufio"
	"fmt"
	"os/exec"
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

	// Mac 特有常量
	PF_TABLE_NAME = "samwaf_blocked" // pf table 名称
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
	// 检查 pf 是否启用
	cmd := exec.Command("pfctl", "-s", "info")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[WARN] 检查防火墙状态失败: %v\n", err)
		return false
	}

	// 查找 "Status: Enabled"
	return strings.Contains(string(output), "Status: Enabled")
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
		cmdRe := ConvertByte2String(in.Bytes(), "UTF-8")
		printstr += cmdRe + "\n"
	}
	cmd.Wait()
	return nil, printstr
}

func (fw *FireWallEngine) AddRule(ruleName, ipToAdd, action, proc, localport string) error {
	// Mac 使用 pfctl 添加 IP 到 table
	fmt.Printf("[DEBUG] 添加防火墙规则 (Mac): ip=%s\n", ipToAdd)

	// 确保 table 存在
	err := fw.ensureTableExists()
	if err != nil {
		return fmt.Errorf("failed to ensure table exists: %v", err)
	}

	// 添加 IP 到 table
	cmd := exec.Command("pfctl", "-t", PF_TABLE_NAME, "-T", "add", ipToAdd)
	fmt.Printf("[DEBUG] 执行命令: pfctl -t %s -T add %s\n", PF_TABLE_NAME, ipToAdd)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[ERROR] 添加规则失败: %v, 输出: %s\n", err, string(output))
		return err
	}

	fmt.Printf("[DEBUG] 添加规则成功, 输出: %s\n", string(output))
	return nil
}

func (fw *FireWallEngine) EditRule(ruleNum int, newRule string) error {
	return fmt.Errorf("editRule is not supported on macOS")
}

func (fw *FireWallEngine) DeleteRule(ruleName string) (bool, error) {
	fmt.Printf("[DEBUG] 删除防火墙规则 (Mac): name=%s\n", ruleName)

	// 从规则名中提取IP
	ip := extractIPFromRuleName(ruleName)
	if ip == "" {
		fmt.Printf("[ERROR] 无效的规则名: %s\n", ruleName)
		return false, fmt.Errorf("invalid rule name: %s", ruleName)
	}

	// 从 table 中删除 IP
	cmd := exec.Command("pfctl", "-t", PF_TABLE_NAME, "-T", "delete", ip)
	fmt.Printf("[DEBUG] 执行命令: pfctl -t %s -T delete %s\n", PF_TABLE_NAME, ip)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	fmt.Printf("[DEBUG] 删除规则输出: %s\n", outputStr)

	if err != nil {
		// 如果IP不在表中，也算成功（幂等性）
		if strings.Contains(outputStr, "no addresses deleted") {
			fmt.Printf("[WARN] IP不在表中: %s\n", ip)
			return false, fmt.Errorf("IP %s not in table", ip)
		}
		fmt.Printf("[ERROR] 删除规则失败: %v\n", err)
		return false, err
	}

	fmt.Printf("[DEBUG] 删除规则成功\n")
	return true, nil
}

func (fw *FireWallEngine) IsRuleExists(ruleName string) (bool, error) {
	fmt.Printf("[DEBUG] 检查规则是否存在 (Mac): name=%s\n", ruleName)

	// 从规则名中提取IP
	ip := extractIPFromRuleName(ruleName)
	if ip == "" {
		fmt.Printf("[ERROR] 无效的规则名: %s\n", ruleName)
		return false, fmt.Errorf("invalid rule name: %s", ruleName)
	}

	// 检查 IP 是否在 table 中
	cmd := exec.Command("pfctl", "-t", PF_TABLE_NAME, "-T", "show")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// table 可能不存在
		fmt.Printf("[DEBUG] 获取table失败 (table可能不存在): %v\n", err)
		return false, nil
	}

	outputStr := string(output)
	exists := strings.Contains(outputStr, ip)

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
	fmt.Printf("[INFO] 开始封禁IP (Mac): %s, 原因: %s\n", ip, reason)

	// 生成规则名称
	ruleName := generateRuleName(ip)
	fmt.Printf("[DEBUG] 生成规则名称: %s\n", ruleName)

	// 检查规则是否已存在
	exists, _ := fw.IsRuleExists(ruleName)
	if exists {
		fmt.Printf("[WARN] IP %s 已经被封禁\n", ip)
		return fmt.Errorf("IP %s already blocked", ip)
	}

	// 确保 pf 已启用和 table 存在
	if err := fw.ensureTableExists(); err != nil {
		return fmt.Errorf("failed to ensure table exists: %v", err)
	}

	// 添加 IP 到 pf table
	cmd := exec.Command("pfctl", "-t", PF_TABLE_NAME, "-T", "add", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[ERROR] 封禁IP失败: %s, error: %v, output: %s\n", ip, err, string(output))
		return fmt.Errorf("failed to block IP %s: %v, output: %s", ip, err, string(output))
	}

	fmt.Printf("[INFO] 成功封禁IP: %s\n", ip)
	return nil
}

// UnblockIP 解除对指定IP的封禁
func (fw *FireWallEngine) UnblockIP(ip string) error {
	fmt.Printf("[INFO] 开始解除IP封禁 (Mac): %s\n", ip)

	ruleName := generateRuleName(ip)

	// 检查规则是否存在
	exists, _ := fw.IsRuleExists(ruleName)
	if !exists {
		fmt.Printf("[WARN] IP %s 未被封禁\n", ip)
		return fmt.Errorf("IP %s is not blocked", ip)
	}

	// 从 table 中删除 IP
	cmd := exec.Command("pfctl", "-t", PF_TABLE_NAME, "-T", "delete", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[ERROR] 解除IP封禁失败: %s, error: %v, output: %s\n", ip, err, string(output))
		return fmt.Errorf("failed to unblock IP %s: %v, output: %s", ip, err, string(output))
	}

	fmt.Printf("[INFO] 成功解除IP封禁: %s\n", ip)
	return nil
}

// IsIPBlocked 检查IP是否已被封禁
func (fw *FireWallEngine) IsIPBlocked(ip string) (bool, error) {
	fmt.Printf("[DEBUG] 检查IP是否被封禁 (Mac): %s\n", ip)
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
	fmt.Printf("[DEBUG] 获取已封禁IP列表 (Mac)\n")

	cmd := exec.Command("pfctl", "-t", PF_TABLE_NAME, "-T", "show")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[ERROR] 获取IP列表失败: %v\n", err)
		return nil, fmt.Errorf("failed to get blocked IP list: %v", err)
	}

	blockedIPs := []string{}
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			blockedIPs = append(blockedIPs, line)
		}
	}

	fmt.Printf("[DEBUG] 找到 %d 个已封禁的IP\n", len(blockedIPs))
	return blockedIPs, nil
}

// ClearAllBlockedIPs 清除所有封禁规则（谨慎使用）
func (fw *FireWallEngine) ClearAllBlockedIPs() (int, error) {
	fmt.Printf("[INFO] 清除所有封禁规则 (Mac)\n")

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

	fmt.Printf("[INFO] 成功清除 %d 条规则\n", count)
	return count, nil
}

// generateRuleName 生成规则名称
func generateRuleName(ip string) string {
	// 将IP中的点替换为下划线，避免命令行解析问题
	safeName := strings.ReplaceAll(ip, ".", "_")
	safeName = strings.ReplaceAll(safeName, "/", "_")
	safeName = strings.ReplaceAll(safeName, ":", "_") // IPv6 支持
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

// ensureTableExists 确保 pf table 存在并配置规则
func (fw *FireWallEngine) ensureTableExists() error {
	fmt.Printf("[DEBUG] 确保pf table存在\n")

	// 检查 table 是否存在
	cmd := exec.Command("pfctl", "-t", PF_TABLE_NAME, "-T", "show")
	_, err := cmd.CombinedOutput()
	if err == nil {
		// table 已存在
		fmt.Printf("[DEBUG] pf table %s 已存在\n", PF_TABLE_NAME)
		return nil
	}

	// 创建 table
	// 注意：在 macOS 上，需要通过配置文件或 pfctl 的 anchor 来创建持久化的 table
	// 这里我们先尝试直接添加一个空IP来初始化 table
	fmt.Printf("[DEBUG] 初始化pf table %s\n", PF_TABLE_NAME)

	// 尝试添加并立即删除一个临时IP来初始化表
	tempIP := "127.0.0.254"
	cmd = exec.Command("pfctl", "-t", PF_TABLE_NAME, "-T", "add", tempIP)
	_, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[WARN] 初始化table失败: %v\n", err)
		fmt.Printf("[INFO] 这是正常的，table会在第一次使用时自动创建\n")
	}

	// 删除临时IP
	cmd = exec.Command("pfctl", "-t", PF_TABLE_NAME, "-T", "delete", tempIP)
	cmd.CombinedOutput()

	return nil
}

// SetupPFRule 设置 pf 规则（需要手动调用一次来配置基础规则）
// 这个方法需要在系统启动时或首次使用时调用
func (fw *FireWallEngine) SetupPFRule() error {
	fmt.Printf("[INFO] 设置pf基础规则 (Mac)\n")

	// 创建一个临时的 pf 规则文件
	ruleContent := fmt.Sprintf(`
# SamWAF IP Block Table
table <%s> persist

# Block incoming traffic from blocked IPs
block in quick from <%s> to any
`, PF_TABLE_NAME, PF_TABLE_NAME)

	fmt.Printf("[INFO] pf规则内容:\n%s\n", ruleContent)
	fmt.Printf("[INFO] 请手动将以上规则添加到 /etc/pf.conf 并执行 'sudo pfctl -f /etc/pf.conf'\n")
	fmt.Printf("[INFO] 或者使用 anchor 功能动态加载规则\n")

	return nil
}
