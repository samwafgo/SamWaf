package threatip

// Diff 计算新旧快照的差异：added=新增(new 有 old 无)，removed=移除(old 有 new 无)。
// 用于订阅每日全量快照的增量落地与引用计数维护。
func Diff(oldIPs, newIPs []string) (added []string, removed []string) {
	oldSet := toSet(oldIPs)
	newSet := toSet(newIPs)
	for ip := range newSet {
		if _, ok := oldSet[ip]; !ok {
			added = append(added, ip)
		}
	}
	for ip := range oldSet {
		if _, ok := newSet[ip]; !ok {
			removed = append(removed, ip)
		}
	}
	return added, removed
}

func toSet(ips []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if ip != "" {
			m[ip] = struct{}{}
		}
	}
	return m
}
