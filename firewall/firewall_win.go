//go:build !linux

package firewall

import (
	"bufio"
	"fmt"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/text/encoding/simplifiedchinese"
	"os/exec"
	"strings"
)

type Charset string

const (
	UTF8    = Charset("UTF-8")
	GB18030 = Charset("GB18030")
)

const ACTION_ALLOW string = "allow" //，allow 表示允许连接，block 表示阻止连接，bypass 表示只允许安全连接。 =
const ACTION_BLOCK string = "block"
const ACTION_BYPASS string = "bypass"

type FireWallEngine struct {
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

	/*s := fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=in action=allow protocol=TCP localport=8080 remoteip=%s`, ruleName, ipToAdd)
	cmd = exec.Command("netsh", s)*/
	/*cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf(`name="%s"`, ruleName),
		fmt.Sprintf(`dir=in action=allow protocol=TCP localport=8080 remoteip=%s`, ipToAdd),
	)*/
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName, "dir=in", "action="+action, "protocol="+proc, "localport="+localport,
		"remoteip="+ipToAdd,
	)
	err, _ := fw.executeCommand(cmd)
	return err
}

func (fw *FireWallEngine) EditRule(ruleNum int, newRule string) error {
	return fmt.Errorf("editRule is not supported on Windows")
}

func (fw *FireWallEngine) DeleteRule(ruleName string) (bool, error) {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s", ruleName))
	err, output := fw.executeCommand(cmd)
	fmt.Println(output)
	//已删除 1 规则。确定。
	if err == nil {
		if strings.Contains(output, "No rules match the specified criteria") {
			return false, fmt.Errorf("error:delete firewall rule: %s, output: %s", ruleName, output)
		}
		if strings.Contains(output, "没有与指定标准相匹配的规则。") {
			return false, fmt.Errorf("error:delete firewall rule: %s, output: %s", ruleName, output)
		}
		if strings.Contains(output, "已删除") {
			return true, nil
		}
	}
	return false, fmt.Errorf("error:delete firewall rule: %s, output: %s", ruleName, output)
}
func (fw *FireWallEngine) IsRuleExists(ruleName string) (bool, error) {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
	err, output := fw.executeCommand(cmd)
	if err == nil {
		if strings.Contains(output, "No rules match the specified criteria") {
			return false, nil
		}
		if strings.Contains(output, "没有与指定标准相匹配的规则。") {
			return false, nil
		}
		if strings.Contains(output, " "+ruleName+"-----") {
			return true, nil
		}
	}
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
