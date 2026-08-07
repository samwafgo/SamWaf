//go:build !linux && !windows

package wafhostguard

// checkLogCapability 非 Linux/Windows 平台(主要是 macOS)不支持登录失败日志的**自动采集**。
//
// 原因：macOS 从 10.12 起用统一日志系统(os_log)取代了 syslog，sshd 的认证失败细节
// 不再写进 /var/log/system.log，要靠 `log stream --predicate 'process == "sshd"'` 取，
// 输出格式与 syslog 完全是另一套；加之 macOS 是桌面系统、"远程登录"默认关闭，
// 极少作为公网 SSH 服务器暴露，收益撑不起一套独立的采集与解析实现。
//
// **注意措辞要准确**：不能说成"整个功能不可用"。macOS 上不能用的只是"自动检测爆破"，
// 而封禁执行(pf table)、手工封禁、封禁账本与到期解封、连接看板都是正常工作的——
// 说成全不可用会让用户直接放弃这个页面，那是误导。
func checkLogCapability() (bool, string, bool) {
	return false, "当前系统不支持自动检测远程登录爆破：macOS 的 sshd 认证日志在统一日志系统(os_log)中，" +
		"格式与 Linux 的 syslog 完全不同，暂未支持采集（自动检测目前支持 Linux 的 SSH 与 Windows 的 RDP）。" +
		"本页的【连接监控】、【手工封禁】、封禁列表与到期自动解封仍可正常使用。", false
}
