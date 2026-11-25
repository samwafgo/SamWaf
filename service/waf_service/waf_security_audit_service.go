package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/utils"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type WafSecurityAuditService struct {
	ddnsRecent [1024]tunnelAuditRecent
}

type tunnelAuditRecent struct {
	mu          sync.Mutex
	fingerprint [sha256.Size]byte
	time        time.Time
}

var WafSecurityAuditServiceApp = new(WafSecurityAuditService)

// deniedThrottleMinutes 「未认证被拦」事件的审计节流窗口。
//
// 这是本表唯一的高频事件：一次目录扫描就是几千个未认证请求。不节流的话，
// 审计表会在几分钟内被同一条信息刷爆，真正有价值的登录/踢人/票据异常记录反而被淹没。
// 5 分钟一条足够让管理员看出「某 IP 在扫某站点」，又不会失控。
const deniedThrottleMinutes = 5

// accessNotifyThrottleMinutes 同一「事件 + IP」的通知节流窗口。
// 审计表能扛住高频写入，用户的钉钉/邮箱扛不住。
const accessNotifyThrottleMinutes = 5

// AuditEntry 是写审计的入参。用结构体而不是一长串位置参数，
// 是因为调用点分散在引擎各处，位置参数很容易在后续维护中错位。
type AuditEntry struct {
	Event       string
	AccountName string
	SessionCode string
	Host        string
	HostCode    string
	URL         string
	ClientIP    string
	Country     string
	City        string
	UserAgent   string
	Fingerprint string
	Result      int
	Message     string
	ObjectType  string
	ObjectID    string
	detail      json.RawMessage
}

// Write 落一条审计。
//
// 同步写库而非走 GQEQUE_LOG_DB 队列：除 denied 外都是低频事件（登录、踢人、票据异常），
// 同步写对热路径没有影响，却省掉了改队列消费端的一整套改动。
// denied 由 WriteDenied 做节流后再进来。
//
// 约束：Message 里绝不能出现密码、Cookie、票据明文。审计日志的可见性比业务日志更广。
func (receiver *WafSecurityAuditService) Write(e AuditEntry) {
	if global.GWAF_LOCAL_LOG_DB == nil {
		return
	}
	now := time.Now()
	bean := newSecurityAuditLog(e, now)
	global.GWAF_LOCAL_LOG_DB.Create(&bean)
	receiver.notify(bean, now)
}

func newSecurityAuditLog(e AuditEntry, now time.Time) model.SecurityAuditLog {
	day, _ := strconv.Atoi(now.Format("20060102"))
	// 归属地在这里统一补。调用点分散在引擎各处，让每处自己查一遍既啰嗦又必定漏；
	// 而这是纯内存查询，放在低频的审计写入路径上没有代价。
	if e.Country == "" && e.City == "" {
		e.Country, e.City = accessLookupLocation(e.ClientIP)
	}
	return model.SecurityAuditLog{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(now),
			UPDATE_TIME: customtype.JsonTime(now),
		},
		Category:    model.AuditEventCategory(e.Event),
		Event:       e.Event,
		AccountName: e.AccountName,
		SessionCode: e.SessionCode,
		Host:        e.Host,
		HostCode:    e.HostCode,
		URL:         truncate(e.URL, 1000),
		ClientIP:    e.ClientIP,
		Country:     e.Country,
		City:        e.City,
		UserAgent:   truncate(e.UserAgent, 500),
		Fingerprint: e.Fingerprint,
		Result:      e.Result,
		Message:     truncate(e.Message, 500),
		ObjectType:  e.ObjectType,
		ObjectID:    e.ObjectID,
		Detail:      e.detail,
		Day:         day,
	}
}

// TunnelAuditState 只接收地区策略、DDNS 绑定及其有效地址。
// 新增、删除时传 nil 表示不存在的一侧。
type TunnelAuditState struct {
	Region    *model.TunnelRegionProtection
	BindingID string
	Hostname  string
	Family    string
	Enabled   bool
	Addresses []string
}

const (
	tunnelAuditMaxRules     = 32
	tunnelAuditMaxAddresses = 64
	tunnelAuditMaxDetail    = 16 * 1024
	tunnelAuditRepeatWindow = 5 * time.Minute
	tunnelAuditConfigWait   = 2 * time.Second
	tunnelAuditRuntimeWait  = time.Second
)

type tunnelAuditSnapshot struct {
	Region    *model.TunnelRegionProtection `json:"region,omitempty"`
	BindingID string                        `json:"binding_id,omitempty"`
	Hostname  string                        `json:"hostname,omitempty"`
	Family    string                        `json:"family,omitempty"`
	Enabled   *bool                         `json:"enabled,omitempty"`
	Addresses *[]string                     `json:"addresses,omitempty"`
}

type tunnelAuditDetail struct {
	Reason    string               `json:"reason"`
	Before    *tunnelAuditSnapshot `json:"before,omitempty"`
	After     *tunnelAuditSnapshot `json:"after,omitempty"`
	Truncated bool                 `json:"truncated,omitempty"`
}

// WriteTunnelConfig 记录已提交的配置变更或已接受的主动刷新。
// actor 与 clientIP 来自管理端认证上下文，不来自操作表单。
func (receiver *WafSecurityAuditService) WriteTunnelConfig(actor, clientIP string, tunnel model.Tunnel, event, reason string, before, after *TunnelAuditState) {
	if event != model.AuditEventConfigTunnelRegion && event != model.AuditEventConfigTunnelDDNS {
		return
	}
	switch reason {
	case "add", "edit", "delete", "enable", "disable", "save":
	case "manual_refresh":
		if event != model.AuditEventConfigTunnelDDNS {
			return
		}
	default:
		return
	}
	detail := newTunnelAuditDetail(reason, before, after, event == model.AuditEventConfigTunnelRegion)
	actor, _ = tunnelAuditText(actor, 128)
	if ip, err := netip.ParseAddr(clientIP); err == nil {
		clientIP = ip.WithZone("").Unmap().String()
	} else {
		clientIP = ""
	}
	if err := writeTunnelAudit(actor, clientIP, tunnel.Id, event, model.AccessAuditOK, detail.marshal(), false); err != nil {
		zlog.Warn("隧道安全审计写入失败", "event", event)
	}
}

// WriteTunnelDDNSRuntime 是工作进程的 DDNS 状态变更回调。
func (receiver *WafSecurityAuditService) WriteTunnelDDNSRuntime(tunnel model.Tunnel, binding model.TunnelDDNSBinding, reason string, before, after []string) {
	if global.GWAF_LOCAL_LOG_DB == nil || !tunnelAuditToken(tunnel.Id, 64) || !tunnelAuditToken(binding.ID, 64) {
		return
	}
	var event string
	result := model.AccessAuditOK
	switch reason {
	case "addresses_changed":
		event = model.AuditEventConfigTunnelDDNSAddresses
	case "resolution_recovered":
		event = model.AuditEventConfigTunnelDDNSResolution
	case "resolution_error", "expired":
		event = model.AuditEventConfigTunnelDDNSResolution
		result = model.AccessAuditFail
	default:
		return
	}
	oldState := TunnelAuditState{BindingID: binding.ID, Hostname: binding.Domain, Family: binding.Family, Enabled: binding.Enabled, Addresses: before}
	newState := oldState
	newState.Addresses = after
	// 空集合也要明确留在运行时审计明细里。
	if oldState.Addresses == nil {
		oldState.Addresses = []string{}
	}
	if newState.Addresses == nil {
		newState.Addresses = []string{}
	}
	detail := newTunnelAuditDetail(reason, &oldState, &newState, false)
	if reason == "addresses_changed" && !detail.Truncated && slices.Equal(*detail.Before.Addresses, *detail.After.Addresses) {
		return
	}
	encoded := detail.marshal()
	if err := receiver.writeTunnelDDNSTransition(tunnel.Id, binding.ID, encoded, time.Now(), func() error {
		return writeTunnelAudit("system", "", tunnel.Id, event, result, encoded, true)
	}); err != nil {
		zlog.Warn("隧道安全审计写入失败", "event", event)
	}
}

func writeTunnelAudit(actor, clientIP, tunnelID, event string, result int, detail json.RawMessage, runtime bool) error {
	if !tunnelAuditToken(tunnelID, 64) {
		return errors.New("invalid tunnel audit object ID")
	}
	db := global.GWAF_LOCAL_LOG_DB
	if db == nil {
		return gorm.ErrInvalidDB
	}
	bean := newSecurityAuditLog(AuditEntry{
		Event: event, AccountName: actor, ClientIP: clientIP, Result: result,
		ObjectType: model.AuditObjectTypeTunnel, ObjectID: tunnelID,
		Message: model.AccessEventName(event), detail: detail,
	}, time.Now())
	// 仅安全审计表保存明细；数据库异常时不在运行日志回显写入参数。
	db = db.Session(&gorm.Session{Logger: logger.Discard})
	if !runtime {
		ctx, cancel := context.WithTimeout(context.Background(), tunnelAuditConfigWait)
		defer cancel()
		return db.WithContext(ctx).Create(&bean).Error
	}

	// 重试沿用主键，提交结果不明确时也只保留一条流水。
	ctx, cancel := context.WithTimeout(context.Background(), tunnelAuditRuntimeWait)
	defer cancel()
	db = db.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "id"}}, DoNothing: true})
	first, cancelFirst := context.WithTimeout(ctx, tunnelAuditRuntimeWait/2)
	err := db.WithContext(first).Create(&bean).Error
	cancelFirst()
	if err == nil || ctx.Err() != nil {
		return err
	}
	return db.WithContext(ctx).Create(&bean).Error
}

// 只合并同一绑定连续重复且已落库的状态变化，缓存不随绑定数量增长。
func (receiver *WafSecurityAuditService) writeTunnelDDNSTransition(tunnelID, bindingID string, detail []byte, now time.Time, write func() error) error {
	key := []byte(tunnelID + "\x00" + bindingID + "\x00")
	slot := sha256.Sum256(key)
	fingerprint := sha256.Sum256(append(key, detail...))
	entry := &receiver.ddnsRecent[int(binary.LittleEndian.Uint16(slot[:2]))%len(receiver.ddnsRecent)]
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.fingerprint == fingerprint && now.Sub(entry.time) < tunnelAuditRepeatWindow {
		return nil
	}
	if err := write(); err != nil {
		return err
	}
	entry.fingerprint, entry.time = fingerprint, now
	return nil
}

func newTunnelAuditDetail(reason string, before, after *TunnelAuditState, region bool) tunnelAuditDetail {
	detail := tunnelAuditDetail{Reason: reason}
	detail.Before = auditTunnelSnapshot(before, region, &detail.Truncated)
	detail.After = auditTunnelSnapshot(after, region, &detail.Truncated)
	return detail
}

func auditTunnelSnapshot(state *TunnelAuditState, region bool, truncated *bool) *tunnelAuditSnapshot {
	if state == nil {
		return nil
	}
	if region {
		if state.Region == nil {
			return nil
		}
		record := state.Region
		snapshot := &model.TunnelRegionProtection{
			Revision: record.Revision, Enabled: record.Enabled,
			Fallback: tunnelAuditPolicy(record.Fallback), Unknown: tunnelAuditPolicy(record.Unknown),
			Rules: make([]model.TunnelRegionRule, 0, min(len(record.Rules), tunnelAuditMaxRules)),
		}
		for _, rule := range record.Rules[:cap(snapshot.Rules)] {
			name, clippedName := tunnelAuditText(rule.Name, 60)
			country, operator := "", ""
			if len(rule.Country) == 2 && rule.Country[0] >= 'A' && rule.Country[0] <= 'Z' && rule.Country[1] >= 'A' && rule.Country[1] <= 'Z' {
				country = rule.Country
			}
			if rule.Operator == "eq" || rule.Operator == "ne" {
				operator = rule.Operator
			}
			snapshot.Rules = append(snapshot.Rules, model.TunnelRegionRule{
				Name: name, Country: country, Operator: operator, Action: tunnelAuditPolicy(rule.Action), Enabled: rule.Enabled,
			})
			*truncated = *truncated || clippedName
		}
		*truncated = *truncated || len(record.Rules) > len(snapshot.Rules)
		return &tunnelAuditSnapshot{Region: snapshot}
	}

	enabled := state.Enabled
	snapshot := &tunnelAuditSnapshot{Enabled: &enabled, Hostname: tunnelAuditHostname(state.Hostname)}
	if tunnelAuditToken(state.BindingID, 64) {
		snapshot.BindingID = state.BindingID
	}
	switch state.Family {
	case "ipv4", "ipv6", "both":
		snapshot.Family = state.Family
	}
	if state.Addresses != nil {
		addresses := make([]string, 0, min(len(state.Addresses), tunnelAuditMaxAddresses))
		seen := make(map[netip.Addr]struct{}, cap(addresses))
		for _, value := range state.Addresses {
			ip, err := netip.ParseAddr(value)
			if err != nil || ip.Zone() != "" {
				continue
			}
			ip = ip.Unmap()
			if _, exists := seen[ip]; exists {
				continue
			}
			if len(addresses) == tunnelAuditMaxAddresses {
				*truncated = true
				break
			}
			seen[ip] = struct{}{}
			addresses = append(addresses, ip.String())
		}
		slices.Sort(addresses)
		snapshot.Addresses = &addresses
	}
	return snapshot
}

func tunnelAuditPolicy(v string) string {
	if v == "allow" || v == "deny" {
		return v
	}
	return ""
}

func tunnelAuditToken(v string, maxBytes int) bool {
	if v == "" || len(v) > maxBytes {
		return false
	}
	for i := range v {
		b := v[i]
		if b != '-' && b != '_' && (b < '0' || b > '9') && (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') {
			return false
		}
	}
	return true
}

func tunnelAuditHostname(host string) string {
	if host == "" || len(host) > 253 || strings.Contains(host, "_") {
		return ""
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if !tunnelAuditToken(label, 63) || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
	}
	return strings.ToLower(host)
}

func tunnelAuditText(v string, maxRunes int) (string, bool) {
	var out strings.Builder
	n := 0
	for _, r := range v {
		if unicode.IsControl(r) {
			continue
		}
		if n == maxRunes {
			return out.String(), true
		}
		out.WriteRune(r)
		n++
	}
	return out.String(), false
}

func (detail tunnelAuditDetail) marshal() json.RawMessage {
	encoded, _ := json.Marshal(detail)
	if len(encoded) <= tunnelAuditMaxDetail {
		return encoded
	}
	// 保留前后策略和各自有序的规则前缀，明示省略；不按字节截断 JSON。
	detail.Truncated = true
	for _, side := range []**tunnelAuditSnapshot{&detail.Before, &detail.After} {
		if *side != nil && (*side).Region != nil {
			snapshot := **side
			region := *snapshot.Region
			region.Rules = region.Rules[:min(len(region.Rules), 8)]
			snapshot.Region = &region
			*side = &snapshot
		}
	}
	encoded, _ = json.Marshal(detail)
	return encoded
}

// accessLookupLocation 把 IP 解析成 (国家, 省市) 两段。
//
// utils.GetCountry 返回 [国家, 区域, 省份, 城市, ISP]，这里只取国家与省市：
// ISP 对访问审计没有意义，"华东"这类区域又太粗，留着只会把表格列撑宽。
func accessLookupLocation(ip string) (string, string) {
	if strings.TrimSpace(ip) == "" {
		return "", ""
	}
	parts := utils.GetCountry(ip)
	country := ""
	if len(parts) > 0 {
		country = strings.TrimSpace(parts[0])
	}
	var seg []string
	for i := 2; i < len(parts) && i <= 3; i++ {
		if v := strings.TrimSpace(parts[i]); v != "" && v != country {
			seg = append(seg, v)
		}
	}
	return country, strings.Join(seg, " ")
}

// notify 把够格的事件推进消息队列。
//
// 放在 Write 里而不是各个调用点：Write 是所有审计事件的唯一汇聚处，
// 挂在这里就不可能漏掉某个事件，将来加事件类型也只用改 AccessNotifyEvents 那张表。
//
// 两层防轰炸：
//  1. AccessNotifyEvents 白名单，高频事件（denied/login_fail）根本不在里面
//  2. 同一「事件 + IP」5 分钟只发一次 —— 票据重放、回跳地址异常这类是攻击者可以
//     无限重复触发的，白名单挡不住重复，节流才行
func (receiver *WafSecurityAuditService) notify(bean model.SecurityAuditLog, now time.Time) {
	abnormal, ok := model.AccessNotifyEvents[bean.Event]
	if !ok || global.GQEQUE_MESSAGE_DB == nil {
		return
	}
	key := enums.CACHE_ACCESS_NOTIFY + bean.Event + ":" + bean.ClientIP
	if global.GCACHE_WAFCACHE.IsKeyExist(key) {
		return
	}
	global.GCACHE_WAFCACHE.SetWithTTl(key, "1", accessNotifyThrottleMinutes*time.Minute)

	location := strings.TrimSpace(bean.Country + " " + bean.City)
	serverName := global.GWAF_CUSTOM_SERVER_NAME
	if serverName == "" {
		serverName = "未命名服务器"
	}
	global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.AccessMessageInfo{
		BaseMessageInfo: innerbean.BaseMessageInfo{
			OperaType: "统一访问认证",
			Server:    serverName,
		},
		Event:       bean.Event,
		EventName:   model.AccessEventName(bean.Event),
		AccountName: bean.AccountName,
		Host:        bean.Host,
		Url:         bean.URL,
		Ip:          bean.ClientIP,
		Location:    location,
		Message:     bean.Message,
		Time:        now.Format("2006-01-02 15:04:05"),
		Abnormal:    abnormal,
	})
}

// WriteThrottled 节流写入：同 IP + 同域名 + 同事件类型在窗口内只记一条。
//
// 用于攻击者可以无限重复触发的事件（未认证被拦、锁定期内继续尝试登录）。
// 不节流的话，一次目录扫描或一轮爆破就能把审计表刷爆，
// 真正有价值的登录/踢人/票据异常记录反而被淹没，同时放大同步写库的压力。
func (receiver *WafSecurityAuditService) WriteThrottled(e AuditEntry) {
	key := enums.CACHE_ACCESS_AUDIT + e.Event + ":" + e.ClientIP + ":" + e.Host
	if global.GCACHE_WAFCACHE.IsKeyExist(key) {
		return
	}
	global.GCACHE_WAFCACHE.SetWithTTl(key, "1", deniedThrottleMinutes*time.Minute)
	receiver.Write(e)
}

// WriteDenied 记一条「未认证被拦」（本表唯一的高频事件），带节流。
func (receiver *WafSecurityAuditService) WriteDenied(e AuditEntry) {
	e.Event = model.AccessEventDenied
	e.Result = model.AccessAuditFail
	receiver.WriteThrottled(e)
}

func (receiver *WafSecurityAuditService) GetListApi(req request.WafAccessAuditSearchReq) ([]model.SecurityAuditLog, int64, error) {
	var list []model.SecurityAuditLog
	var total int64 = 0

	db := global.GWAF_LOCAL_LOG_DB.Model(&model.SecurityAuditLog{}).
		Where("user_code = ? and tenant_id = ?", global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
	if strings.TrimSpace(req.Category) != "" {
		db = db.Where("category = ?", strings.TrimSpace(req.Category))
	}
	if strings.TrimSpace(req.Event) != "" {
		db = db.Where("event = ?", strings.TrimSpace(req.Event))
	}
	if objectType := strings.TrimSpace(req.ObjectType); objectType != "" {
		db = db.Where("object_type = ?", objectType)
	}
	if objectID := strings.TrimSpace(req.ObjectID); objectID != "" {
		db = db.Where("object_id = ?", objectID)
	}
	if strings.TrimSpace(req.AccountName) != "" {
		db = db.Where("account_name like ?", "%"+strings.TrimSpace(req.AccountName)+"%")
	}
	if strings.TrimSpace(req.ClientIP) != "" {
		db = db.Where("client_ip like ?", "%"+strings.TrimSpace(req.ClientIP)+"%")
	}
	if strings.TrimSpace(req.Host) != "" {
		db = db.Where("host like ?", "%"+strings.TrimSpace(req.Host)+"%")
	}
	if req.StartDay > 0 {
		db = db.Where("day >= ?", req.StartDay)
	}
	if req.EndDay > 0 {
		db = db.Where("day <= ?", req.EndDay)
	}
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := db.Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).
		Order("create_time desc").Find(&list).Error; err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// CleanExpired 按保留天数清理，由定时任务调用。
func (receiver *WafSecurityAuditService) CleanExpired(keepDays int) int64 {
	if keepDays <= 0 {
		keepDays = 90
	}
	cutoffDay, _ := strconv.Atoi(time.Now().AddDate(0, 0, -keepDays).Format("20060102"))
	r := global.GWAF_LOCAL_LOG_DB.Where("day < ?", cutoffDay).Delete(&model.SecurityAuditLog{})
	return r.RowsAffected
}
