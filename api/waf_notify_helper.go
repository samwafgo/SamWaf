package api

// notifyWafHostChanged 编辑类接口统一的「新旧网站都要通知」帮助函数。
//
// 背景(issue #898)：编辑名单时可以把记录的所属网站(host_code)从 A 改到 B。
// 记录在库里已经移到 B，但引擎里 A 的内存快照(HostSafe)从来没被刷新过，
// A 站点会一直按旧名单拦截，直到重启 SamWaf。
//
// 修改成功后先通知新网站，再在 host_code 确实变化时补通知旧网站，
// 让旧网站按「移走之后的库现状」重新加载(通常就是把这条记录去掉)。
// oldHostCode 为空表示编辑前没查到记录，此时不补通知。
func notifyWafHostChanged(notify func(hostCode string), oldHostCode, newHostCode string) {
	notify(newHostCode)
	if oldHostCode != "" && oldHostCode != newHostCode {
		//老的主机编码，需要一并刷新，否则旧网站的内存名单永远是脏的
		notify(oldHostCode)
	}
}
