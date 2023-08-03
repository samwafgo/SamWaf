package firewall

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"os/exec"
	"runtime"
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
	} else if runtime.GOOS == "windows" {
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
	return false
}

func (fw *FireWallEngine) executeCommand(cmd *exec.Cmd) error {
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(fmt.Sprint(err) + ": " + ConvertByte2String(output, "UTF8"))
		return err
	}
	fmt.Println(string(output))
	return nil
}

func (fw *FireWallEngine) AddRule(ruleName, ipToAdd, action, proc, localport string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "linux" {
		cmd = exec.Command("iptables", "-A", "INPUT", ipToAdd)
	} else if runtime.GOOS == "windows" {
		/*s := fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=in action=allow protocol=TCP localport=8080 remoteip=%s`, ruleName, ipToAdd)
		cmd = exec.Command("netsh", s)*/
		/*cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf(`name="%s"`, ruleName),
			fmt.Sprintf(`dir=in action=allow protocol=TCP localport=8080 remoteip=%s`, ipToAdd),
		)*/
		cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName, "dir=in", "action="+action, "protocol="+proc, "localport="+localport,
			"remoteip="+ipToAdd,
		)
	} else {
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return fw.executeCommand(cmd)
}

func (fw *FireWallEngine) EditRule(ruleNum int, newRule string) error {
	return fmt.Errorf("editRule is not supported on Windows")
}

func (fw *FireWallEngine) DeleteRule(ruleNum int) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "linux" {
		cmd = exec.Command("iptables", "-D", "INPUT", fmt.Sprintf("%d", ruleNum))
	} else if runtime.GOOS == "windows" {
		cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=Rule%d", ruleNum))
	} else {
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return fw.executeCommand(cmd)
}

func GbkToUtf8(gbk []byte) ([]byte, error) {
	reader := transform.NewReader(bytes.NewReader(gbk), simplifiedchinese.GBK.NewDecoder())
	return ioutil.ReadAll(reader)
}
func ConvertByte2String(byte []byte, charset string) string {
	var str string
	switch charset {
	case "GB18030":
		var decodeBytes, _ = simplifiedchinese.GB18030.NewDecoder().Bytes(byte)
		str = string(decodeBytes)
	case "UTF8":
		fallthrough
	default:
		str = string(byte)
	}
	return str
}
