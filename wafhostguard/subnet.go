package wafhostguard

import (
	"SamWaf/global"
	"SamWaf/model"
	"net"
	"time"
)

// 网段聚合封禁：同一个 /24 里被封的 IP 数达到阈值时，直接封掉整段。
//
// 对僵尸网络确实有效——攻击者手上一整个 C 段的肉鸡，逐个封是打地鼠。
// 但**默认关闭**，因为误伤面太大：一个 /24 可能是整个机房、整栋写字楼的出口，
// 甚至是某运营商的 NAT 池。用户应该先在事件列表里看到"确实是同段大量来源"，
// 再自己决定要不要开。

// subnetOf 返回 IPv4 地址所属的 /24 网段(CIDR 文本)。
// 只做 IPv4：IPv6 的地址空间下"同 /64 就是同一个人"这个假设不成立，
// 一个家庭宽带用户随手就有一整个 /64，聚合封禁会把无关的人全带上。
func subnetOf(ip string) (string, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	v4 := parsed.To4()
	if v4 == nil {
		return "", false
	}
	masked := v4.Mask(net.CIDRMask(24, 32))
	return masked.String() + "/24", true
}

// ShouldAggregateSubnet 判断是否应把这次封禁升级为整段封禁。
// 返回 (网段CIDR, 是否升级)。
func ShouldAggregateSubnet(ip string, now time.Time) (string, bool) {
	if global.GCONFIG_HOST_GUARD_SUBNET_AGGREGATE != 1 {
		return "", false
	}
	cidr, ok := subnetOf(ip)
	if !ok {
		return "", false
	}
	if global.GWAF_LOCAL_DB == nil {
		return "", false
	}

	threshold := global.GCONFIG_HOST_GUARD_SUBNET_THRESHOLD
	if threshold <= 0 {
		threshold = 10
	}

	// 该网段已经被整段封过就不用再来一次
	var subnetBanned int64
	global.GWAF_LOCAL_DB.Model(&model.HostGuardBan{}).
		Where("ip = ? AND status = ?", cidr, model.HostBanStatusActive).
		Count(&subnetBanned)
	if subnetBanned > 0 {
		return cidr, false
	}

	// 统计该 /24 内当前处于封禁中的单 IP 数。
	// 用 LIKE 前缀匹配是为了走得动索引又不依赖具体数据库的网络函数；
	// 前三段固定，误匹配只可能发生在"10.1.2" 匹配到 "10.1.20.x"，
	// 所以前缀必须带上第四个点。
	prefix := cidr[:len(cidr)-len("0/24")]
	var cnt int64
	global.GWAF_LOCAL_DB.Model(&model.HostGuardBan{}).
		Where("status = ? AND is_subnet = 0 AND ip LIKE ?", model.HostBanStatusActive, prefix+"%").
		Count(&cnt)

	// +1 是把当前正要封的这个也算进去
	return cidr, cnt+1 >= threshold
}
