package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/utils"
	"strconv"
	"strings"
	"time"
)

type WafSecurityAuditService struct{}

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
	day, _ := strconv.Atoi(now.Format("20060102"))
	// 归属地在这里统一补。调用点分散在引擎各处，让每处自己查一遍既啰嗦又必定漏；
	// 而这是纯内存查询，放在低频的审计写入路径上没有代价。
	if e.Country == "" && e.City == "" {
		e.Country, e.City = accessLookupLocation(e.ClientIP)
	}
	bean := model.SecurityAuditLog{
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
		Day:         day,
	}
	global.GWAF_LOCAL_LOG_DB.Create(&bean)

	receiver.notify(bean, now)
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
