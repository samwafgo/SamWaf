package wafenginecore

import (
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
)

// ApplyHostHotUpdate 把管理端的站点改动同步进引擎快照。
//
// 这是「不重建代理」的轻量热更新通道（global.GWAF_CHAN_HOST）：只搬请求期真正要读的字段，
// 不整份替换 HostSafe.Host。不整份替换是有原因的——该通道的发送方并非都送来「刚从库里取出的完整记录」，
// 其中一处送的是操作前的旧快照，整份覆盖会把刚写进去的配置又抹回去。
//
// ⚠️ 新增任何**在请求期被读取**的站点字段，都必须在这里补一行。
// 漏了的症状很难查：界面改了、库里也存了、接口读回来也是新值，唯独引擎一直用旧值。
// 紧急模式就这么踩过一次——开关打开后一直不生效，重启才好，因为重启是从库里重新加载的。
func ApplyHostHotUpdate(h *wafenginmodel.HostSafe, host model.Hosts) {
	if h == nil {
		return
	}
	h.Host.GUARD_STATUS = host.GUARD_STATUS
	h.Host.EmergencyMode = host.EmergencyMode
	h.Host.EmergencyUntil = host.EmergencyUntil
}
