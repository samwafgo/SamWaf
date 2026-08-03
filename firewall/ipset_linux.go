//go:build linux

package firewall

import (
	"SamWaf/common/wafexec"
	"fmt"
	"os/exec"
	"strings"
)

// 说明：本文件在 Linux 下用 ipset 提供"批量封禁大列表(上万~十万条威胁情报 IP)"的能力，
// 区别于 firewall.go 里逐条 iptables 规则(仅适合少量手工封禁)。
//   - 一个命名 set 装十万 IP/CIDR，配一条 `iptables -m set --match-set <set> src -j DROP` 规则，
//     收包匹配走内核哈希 O(1)，而非 INPUT 链上万条线性规则。
//   - 全量重建用 `ipset restore` 从 stdin 一次灌入 + `swap` 原子替换，单次 fork，避免旧实现的 O(n²)。
// v4/v6 分成两个 set(hash:net 的 family 在 create 时固定)：<set> 走 iptables，<set>_6 走 ip6tables。

const (
	// ipsetMaxElem 单个 set 的最大元素数上限(hash:net 动态增长，此值仅为封顶，防投毒膨胀)
	ipsetMaxElem = "2097152"
	// ipsetProbeName 能力探测用的临时 set 名
	ipsetProbeName = "samwaf_probe"
	// ipsetMaxBaseNameLen set 基础名长度上限：ipset 名总长上限 31，需为 "_6"(v6) 与 "_s"(swap) 预留后缀
	ipsetMaxBaseNameLen = 24
)

// v6SetName 返回某 set 对应的 IPv6 集合名
func v6SetName(setName string) string { return setName + "_6" }

// swapSetName 返回某 set 全量重建时用的临时交换集合名
func swapSetName(setName string) string { return setName + "_s" }

// validateSetName 校验集合名合法(小写字母/数字/下划线、长度受限)，兼作防命令注入兜底
func validateSetName(setName string) error {
	if len(setName) == 0 || len(setName) > ipsetMaxBaseNameLen {
		return fmt.Errorf("ipset 集合名长度需为 1-%d: %q", ipsetMaxBaseNameLen, setName)
	}
	for _, c := range setName {
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '_' {
			return fmt.Errorf("ipset 集合名仅允许小写字母/数字/下划线: %q", setName)
		}
	}
	return nil
}

// runFirewallCmd 执行一条防火墙相关命令并返回合并输出(仅补 Stdin，不接管 Stdout/Stderr 逻辑)
func (fw *FireWallEngine) runFirewallCmd(name string, args ...string) (string, error) {
	cmd := wafexec.FixStdin(exec.Command(name, args...))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// hasIP6tables 判断系统是否具备 ip6tables(无则跳过 v6 封禁，仅处理 v4)
func hasIP6tables() bool {
	_, err := exec.LookPath("ip6tables")
	return err == nil
}

// SupportsIPSet 报告当前环境是否可用 ipset 批量封禁(带 30s 缓存，见 available.go)
func (fw *FireWallEngine) SupportsIPSet() bool {
	return cachedSupportsIPSet(fw) == nil
}

// supportsIPSet 实际探测：ipset 二进制存在 + 能创建/销毁临时 set(验证内核模块与权限)
func (fw *FireWallEngine) supportsIPSet() error {
	if _, err := exec.LookPath("ipset"); err != nil {
		msg := "当前环境未安装 ipset，无法使用大列表批量封禁，可改用 WAF 应用层黑名单。"
		if isInContainer() {
			msg += containerHint
		}
		return fmt.Errorf("%s", msg)
	}
	if out, err := fw.runFirewallCmd("ipset", "create", ipsetProbeName, "hash:net", "-exist"); err != nil {
		msg := fmt.Sprintf("ipset 不可用(可能缺内核模块或权限): %v, 输出: %s", err, strings.TrimSpace(out))
		if isInContainer() {
			msg += containerHint
		}
		return fmt.Errorf("%s", msg)
	}
	fw.runFirewallCmd("ipset", "destroy", ipsetProbeName)
	return nil
}

// EnsureIPSet 确保 v4/v6 两个集合存在，且 INPUT 上各挂了一条 match-set DROP 引用规则(幂等)
func (fw *FireWallEngine) EnsureIPSet(setName string) error {
	if err := validateSetName(setName); err != nil {
		return err
	}
	if out, err := fw.runFirewallCmd("ipset", "create", setName, "hash:net", "family", "inet", "maxelem", ipsetMaxElem, "-exist"); err != nil {
		return fmt.Errorf("创建 ipset %s 失败: %v, 输出: %s", setName, err, strings.TrimSpace(out))
	}
	fw.ensureDropRule("iptables", setName)
	// v6 尽力而为：无 ip6tables 时跳过
	if hasIP6tables() {
		if _, err := fw.runFirewallCmd("ipset", "create", v6SetName(setName), "hash:net", "family", "inet6", "maxelem", ipsetMaxElem, "-exist"); err == nil {
			fw.ensureDropRule("ip6tables", v6SetName(setName))
		}
	}
	return nil
}

// ensureDropRule 幂等挂载 `<iptablesBin> -I INPUT 1 -m set --match-set <set> src -j DROP`
func (fw *FireWallEngine) ensureDropRule(iptablesBin, setName string) {
	if _, err := fw.runFirewallCmd(iptablesBin, "-C", "INPUT", "-m", "set", "--match-set", setName, "src", "-j", "DROP"); err == nil {
		return // 已存在
	}
	fw.runFirewallCmd(iptablesBin, "-I", "INPUT", "1", "-m", "set", "--match-set", setName, "src", "-j", "DROP")
}

// RestoreIPSet 用给定 IP/CIDR 列表全量原子重建集合(v4/v6 自动分流)。
// 采用 `ipset restore` 单次 fork：create 临时交换集合→逐条 add→swap 原子替换→destroy 临时集合。
func (fw *FireWallEngine) RestoreIPSet(setName string, ips []string) error {
	if err := fw.EnsureIPSet(setName); err != nil {
		return err
	}
	v4, v6 := splitByIPVersion(ips)
	if err := fw.restoreOneSet(setName, "inet", v4); err != nil {
		return err
	}
	if hasIP6tables() {
		if err := fw.restoreOneSet(v6SetName(setName), "inet6", v6); err != nil {
			return err
		}
	}
	return nil
}

// restoreOneSet 通过 ipset restore + swap 原子重建单个集合
func (fw *FireWallEngine) restoreOneSet(setName, family string, ips []string) error {
	swp := swapSetName(setName)
	var b strings.Builder
	fmt.Fprintf(&b, "create %s hash:net family %s maxelem %s -exist\n", swp, family, ipsetMaxElem)
	fmt.Fprintf(&b, "flush %s\n", swp)
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		fmt.Fprintf(&b, "add %s %s\n", swp, ip)
	}
	fmt.Fprintf(&b, "swap %s %s\n", swp, setName)
	fmt.Fprintf(&b, "destroy %s\n", swp)
	return fw.ipsetRestore(b.String())
}

// ipsetRestore 把 restore 脚本从 stdin 灌给 `ipset restore -exist`(忽略重复/不存在，保证幂等)
func (fw *FireWallEngine) ipsetRestore(payload string) error {
	cmd := exec.Command("ipset", "restore", "-exist")
	cmd.Stdin = strings.NewReader(payload)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset restore 失败: %v, 输出: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// FlushIPSet 清空集合内容(保留集合与引用规则)
func (fw *FireWallEngine) FlushIPSet(setName string) error {
	if err := validateSetName(setName); err != nil {
		return err
	}
	fw.runFirewallCmd("ipset", "flush", setName)
	fw.runFirewallCmd("ipset", "flush", v6SetName(setName))
	return nil
}

// DestroyIPSet 先摘除 INPUT 引用规则，再销毁 v4/v6 集合(set 被引用时无法 destroy)
func (fw *FireWallEngine) DestroyIPSet(setName string) error {
	if err := validateSetName(setName); err != nil {
		return err
	}
	fw.runFirewallCmd("iptables", "-D", "INPUT", "-m", "set", "--match-set", setName, "src", "-j", "DROP")
	if hasIP6tables() {
		fw.runFirewallCmd("ip6tables", "-D", "INPUT", "-m", "set", "--match-set", v6SetName(setName), "src", "-j", "DROP")
	}
	fw.runFirewallCmd("ipset", "destroy", setName)
	fw.runFirewallCmd("ipset", "destroy", v6SetName(setName))
	return nil
}
