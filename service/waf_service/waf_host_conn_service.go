package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model/request"
	"SamWaf/model/response"
	"SamWaf/utils"
	"SamWaf/wafhostguard"
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// 远程连接看板：回答"现在谁连着我这台机器"。
//
// 与爆破防护是**两个独立子系统**——那边看日志判失败登录，这边看内核连接表。
// 之所以不用它来做爆破判定：连接表只能看出"连得频繁"，分不清登录成功还是失败，
// 拿来封禁误伤面太大。
//
// **性能是这里的主要约束**：Linux 下 gopsutil 取连接表要遍历 /proc/*/fd 建立
// inode→pid 映射，上万连接时开销可达百毫秒级。所以必须按需采集 + 短 TTL 缓存，
// 绝不能做成高频后台轮询。

type WafHostConnService struct {
	mu        sync.Mutex
	snapshot  []response.HostConnItem
	takenAt   time.Time
	collectMs int64

	procMu    sync.Mutex
	procCache map[int32]procEntry
}

type procEntry struct {
	name string
	at   time.Time
}

var WafHostConnServiceApp = &WafHostConnService{procCache: make(map[int32]procEntry)}

const (
	// procNameTTL 进程名缓存时长。PID 复用在短时间内极少发生，60 秒足够安全，
	// 又能避免每次采集都对上千个 PID 做一次系统调用。
	procNameTTL = 60 * time.Second
	// collectTimeout 单次采集超时
	collectTimeout = 10 * time.Second
	// slowCollectWarn 超过这个耗时就告警，提示用户放宽刷新间隔
	slowCollectWarn = time.Second
)

// GetList 分页查询连接
func (receiver *WafHostConnService) GetList(req request.WafHostConnSearchReq) ([]response.HostConnItem, int64, response.HostConnSummary, error) {
	summary := response.HostConnSummary{}
	if global.GCONFIG_HOST_CONN_ENABLED != 1 {
		summary.Unavailable = "远程连接看板已在系统配置中关闭"
		return nil, 0, summary, nil
	}

	all, fromCache, err := receiver.getSnapshot()
	if err != nil {
		summary.Unavailable = "采集连接表失败：" + err.Error()
		return nil, 0, summary, err
	}

	sshPorts, rdpPorts := wafhostguard.GuardPorts()
	summary = receiver.buildSummary(all, sshPorts, rdpPorts, fromCache)

	// 过滤
	filtered := make([]response.HostConnItem, 0, len(all))
	for _, item := range all {
		if req.LocalPort > 0 && item.LocalPort != req.LocalPort {
			continue
		}
		if req.State != "" && !strings.EqualFold(item.State, req.State) {
			continue
		}
		if req.RemoteIP != "" && !strings.Contains(item.RemoteIP, req.RemoteIP) {
			continue
		}
		if req.OnlyGuard == 1 && !item.IsGuard {
			continue
		}
		filtered = append(filtered, item)
	}

	total := int64(len(filtered))

	// 分页
	start := req.PageSize * (req.PageIndex - 1)
	if start < 0 || start >= len(filtered) {
		return []response.HostConnItem{}, total, summary, nil
	}
	end := start + req.PageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	page := filtered[start:end]

	// 归属地只查当前页去重后的 IP：全量查在万级连接时会把 IP 库打爆，
	// 而用户一次也只看得到一页
	locCache := make(map[string]string, len(page))
	out := make([]response.HostConnItem, len(page))
	copy(out, page)
	for i := range out {
		ip := out[i].RemoteIP
		if ip == "" {
			continue
		}
		loc, ok := locCache[ip]
		if !ok {
			loc = utils.FormatIPLocation(ip)
			locCache[ip] = loc
		}
		out[i].Location = loc
		out[i].Banned = wafhostguard.GetBanExecutor().Contains(ip)
	}

	return out, total, summary, nil
}

// GetSummary 只要汇总卡片数据
func (receiver *WafHostConnService) GetSummary() (response.HostConnSummary, error) {
	if global.GCONFIG_HOST_CONN_ENABLED != 1 {
		return response.HostConnSummary{Unavailable: "远程连接看板已在系统配置中关闭"}, nil
	}
	all, fromCache, err := receiver.getSnapshot()
	if err != nil {
		return response.HostConnSummary{Unavailable: "采集连接表失败：" + err.Error()}, err
	}
	sshPorts, rdpPorts := wafhostguard.GuardPorts()
	return receiver.buildSummary(all, sshPorts, rdpPorts, fromCache), nil
}

// getSnapshot 取连接快照，TTL 内直接复用
func (receiver *WafHostConnService) getSnapshot() ([]response.HostConnItem, bool, error) {
	ttl := time.Duration(global.GCONFIG_HOST_CONN_CACHE_SEC) * time.Second
	if ttl <= 0 {
		ttl = 3 * time.Second
	}

	receiver.mu.Lock()
	defer receiver.mu.Unlock()

	if receiver.snapshot != nil && time.Since(receiver.takenAt) < ttl {
		return receiver.snapshot, true, nil
	}

	start := time.Now()
	items, err := receiver.collect()
	if err != nil {
		return nil, false, err
	}
	elapsed := time.Since(start)

	receiver.snapshot = items
	receiver.takenAt = time.Now()
	receiver.collectMs = elapsed.Milliseconds()

	if elapsed > slowCollectWarn {
		zlog.Warn("[远程连接看板] 采集连接表耗时较长，本机连接数较多，建议调大缓存秒数或放宽刷新间隔",
			"耗时", elapsed.Round(time.Millisecond).String(), "连接数", len(items))
	}
	return items, false, nil
}

// collect 真正采集一次
func (receiver *WafHostConnService) collect() ([]response.HostConnItem, error) {
	ctx, cancel := context.WithTimeout(context.Background(), collectTimeout)
	defer cancel()

	conns, err := gnet.ConnectionsWithContext(ctx, "tcp")
	if err != nil {
		return nil, err
	}

	sshPorts, rdpPorts := wafhostguard.GuardPorts()
	guard := make(map[int]bool, len(sshPorts)+len(rdpPorts))
	for _, p := range sshPorts {
		guard[p] = true
	}
	for _, p := range rdpPorts {
		guard[p] = true
	}

	items := make([]response.HostConnItem, 0, len(conns))
	for _, c := range conns {
		item := response.HostConnItem{
			RemoteIP:   c.Raddr.IP,
			RemotePort: int(c.Raddr.Port),
			LocalIP:    c.Laddr.IP,
			LocalPort:  int(c.Laddr.Port),
			State:      c.Status,
			Pid:        c.Pid,
			IsGuard:    guard[int(c.Laddr.Port)],
		}
		if c.Pid > 0 {
			item.ProcName = receiver.procName(ctx, c.Pid)
		}
		items = append(items, item)
	}

	// 已建立的排前面，再按本机端口排序——用户最关心"谁正连着"
	sort.SliceStable(items, func(i, j int) bool {
		iEst := strings.EqualFold(items[i].State, "ESTABLISHED")
		jEst := strings.EqualFold(items[j].State, "ESTABLISHED")
		if iEst != jEst {
			return iEst
		}
		if items[i].IsGuard != items[j].IsGuard {
			return items[i].IsGuard
		}
		return items[i].LocalPort < items[j].LocalPort
	})
	return items, nil
}

// procName 取进程名，带 60 秒缓存
func (receiver *WafHostConnService) procName(ctx context.Context, pid int32) string {
	receiver.procMu.Lock()
	if e, ok := receiver.procCache[pid]; ok && time.Since(e.at) < procNameTTL {
		receiver.procMu.Unlock()
		return e.name
	}
	receiver.procMu.Unlock()

	name := ""
	if p, err := process.NewProcessWithContext(ctx, pid); err == nil {
		if n, err := p.NameWithContext(ctx); err == nil {
			name = n
		}
	}

	receiver.procMu.Lock()
	// 顺手清理过期条目，避免长期运行后 map 无限增长(PID 会一直变)
	if len(receiver.procCache) > 4096 {
		for k, v := range receiver.procCache {
			if time.Since(v.at) >= procNameTTL {
				delete(receiver.procCache, k)
			}
		}
	}
	receiver.procCache[pid] = procEntry{name: name, at: time.Now()}
	receiver.procMu.Unlock()
	return name
}

// buildSummary 汇总卡片
func (receiver *WafHostConnService) buildSummary(items []response.HostConnItem, sshPorts, rdpPorts []int, fromCache bool) response.HostConnSummary {
	sum := response.HostConnSummary{
		Total:     len(items),
		SSHPorts:  sshPorts,
		RDPPorts:  rdpPorts,
		CollectMs: receiver.collectMs,
		FromCache: fromCache,
	}

	guardLabel := make(map[int]string, len(sshPorts)+len(rdpPorts))
	for _, p := range sshPorts {
		guardLabel[p] = "SSH"
	}
	for _, p := range rdpPorts {
		guardLabel[p] = "RDP"
	}

	portCount := make(map[int]int)
	ipCount := make(map[string]int)
	for _, it := range items {
		switch {
		case strings.EqualFold(it.State, "ESTABLISHED"):
			sum.Established++
		case strings.EqualFold(it.State, "LISTEN"):
			sum.Listen++
		}
		if it.IsGuard {
			sum.GuardConns++
		}
		portCount[it.LocalPort]++
		if it.RemoteIP != "" && it.RemoteIP != "0.0.0.0" && it.RemoteIP != "::" {
			ipCount[it.RemoteIP]++
		}
	}

	for port, cnt := range portCount {
		label := guardLabel[port]
		if label == "" {
			label = "其他"
		}
		sum.TopPorts = append(sum.TopPorts, response.HostConnPortStat{
			Port:    port,
			Count:   cnt,
			IsGuard: guardLabel[port] != "",
			Label:   label,
		})
	}
	sort.Slice(sum.TopPorts, func(i, j int) bool { return sum.TopPorts[i].Count > sum.TopPorts[j].Count })
	if len(sum.TopPorts) > 10 {
		sum.TopPorts = sum.TopPorts[:10]
	}

	for ip, cnt := range ipCount {
		sum.TopIPs = append(sum.TopIPs, response.HostConnIPStat{RemoteIP: ip, Count: cnt})
	}
	sort.Slice(sum.TopIPs, func(i, j int) bool { return sum.TopIPs[i].Count > sum.TopIPs[j].Count })
	if len(sum.TopIPs) > 10 {
		sum.TopIPs = sum.TopIPs[:10]
	}
	// 只给 Top 榜查归属地，条数固定
	for i := range sum.TopIPs {
		sum.TopIPs[i].Location = utils.FormatIPLocation(sum.TopIPs[i].RemoteIP)
	}

	return sum
}

// InvalidateSnapshot 丢弃快照，强制下次重新采集(手工刷新按钮用)
func (receiver *WafHostConnService) InvalidateSnapshot() {
	receiver.mu.Lock()
	receiver.snapshot = nil
	receiver.mu.Unlock()
}
