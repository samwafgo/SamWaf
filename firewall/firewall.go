//go:build linux

package firewall

import (
	"bufio"
	"fmt"
	"golang.org/x/text/encoding/simplifiedchinese"
	"os/exec"
	"runtime"
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
	cmd := exec.Command("iptables", "-A", "INPUT", ipToAdd)
	err, _ := fw.executeCommand(cmd)
	return err
}

func (fw *FireWallEngine) EditRule(ruleNum int, newRule string) error {
	return fmt.Errorf("editRule is not supported on Windows")
}

func (fw *FireWallEngine) DeleteRule(ruleName string) (bool, error) {
	var cmd *exec.Cmd
	cmd = exec.Command("iptables", "-D", "INPUT", fmt.Sprintf("%s", ruleName))
	err, _ := fw.executeCommand(cmd)
	return false, err
}
func (fw *FireWallEngine) IsRuleExists(ruleName string) (bool, error) {
	cmd := exec.Command("iptables-save")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to list iptables rules: %s, output: %s", err, string(output))
	}
	return strings.Contains(string(output), "-A INPUT -s "+ruleName+" -j ACCEPT"), nil
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
