package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafenginecore/accessgate"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

type WafAccessSessionService struct{}

var WafAccessSessionServiceApp = new(WafAccessSessionService)

// AccessState 是校验通过后交给引擎的最小身份信息。
// 刻意不带密码、密钥、Cookie 明文——它会被塞进缓存，也可能被写进请求头透传给后端。
//
// Host / ClientIP / Fingerprint 这三个是「令牌签发时绑定的条件」。
// 它们必须进缓存：缓存命中时同样要重新比对一遍，否则 ValidateToken 的
// 快路径会绕过慢路径上的绑定校验——那等于让"域名绑定""IP 绑定""设备绑定"
// 三个安全开关在缓存有效期内全部失效。
type AccessState struct {
	SessionCode string `json:"session_code"`
	AccountCode string `json:"account_code"`
	AccountName string `json:"account_name"`
	ExpireUnix  int64  `json:"expire_unix"`
	Host        string `json:"host"`
	ClientIP    string `json:"client_ip"`
	Fingerprint string `json:"fingerprint"`
}

// matchBindings 校验令牌的绑定条件。慢路径(回库)与快路径(缓存命中)都必须走它，
// 保证两条路径的判定完全一致。
func (s *AccessState) matchBindings(host, clientIP, fingerprint string, cfg *accessgate.Config) bool {
	// 令牌只在签发它的那个域名上有效。缺了这一条，从 a.com 拿到的 Cookie
	// 就能在 b.com 上用——跨域 SSO 的每域独立令牌设计也就失去意义了。
	if !strings.EqualFold(s.Host, host) {
		return false
	}
	if cfg.BindIP && s.ClientIP != "" && s.ClientIP != clientIP {
		return false
	}
	if cfg.BindFingerprint && s.Fingerprint != "" && s.Fingerprint != fingerprint {
		return false
	}
	return true
}

// touchIntervalMinutes 最后活跃时间的更新节流间隔。
// 每请求写一次库会把 last_active_time 变成整个 WAF 最热的写入点，
// 节流到 5 分钟对空闲超时判定的精度影响可以忽略。
const touchIntervalMinutes = 5

// HashAccessCode 把 Cookie/票据明文摘成入库与缓存用的键。
//
// 明文永远不落库：数据库被拖走时，攻击者拿到的 sha256 无法直接当 Cookie 用。
// 同时这个摘要正好可以当缓存键的后缀，于是管理端在完全不知道明文的前提下，
// 也能精确驱逐某个会话的缓存条目（见 kickCache）。
func HashAccessCode(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// genAccessSecret 生成 32 字节的高熵随机串（64 位十六进制）。
// 用 crypto/rand，不用 uuid：uuid 的可预测位太多，不适合当会话凭据。
func genAccessSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// ─────────────────────────── 签发 ───────────────────────────

// CreateSession 建立中心会话，返回要写进 Cookie 的明文。
//
// 现在只会传 scope=sso（登录只发生在认证中心），会话服务所有站点，BindHost 留空。
// scope=local 是老方案留下的，只服务 bindHost 一个域名，仅用于兼容升级前建的存量会话。
func (receiver *WafAccessSessionService) CreateSession(acct model.AccessAccount, scope, bindHost,
	clientIP, fingerprint, userAgent string, cfg *accessgate.Config) (string, model.AccessSession, error) {

	plain, err := genAccessSecret()
	if err != nil {
		return "", model.AccessSession{}, err
	}
	now := time.Now()
	// 归属地在建会话时定格。会话页要能一眼看出「这个人是从哪儿登进来的」，
	// 事后再查已经晚了——IP 库更新或用户换网络后，同一个 IP 的解析结果可能已经变了。
	country, city := accessLookupLocation(clientIP)
	bean := model.AccessSession{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(now),
			UPDATE_TIME: customtype.JsonTime(now),
		},
		Country:        country,
		City:           city,
		SessionCode:    HashAccessCode(plain),
		AccountCode:    acct.Id,
		AccountName:    acct.AccountName,
		Scope:          scope,
		BindHost:       strings.ToLower(bindHost),
		ClientIP:       clientIP,
		Fingerprint:    fingerprint,
		UserAgent:      truncate(userAgent, 500),
		Status:         model.AccessStatusValid,
		LoginTime:      customtype.JsonTime(now),
		LastActiveTime: customtype.JsonTime(now),
		ExpireTime:     customtype.JsonTime(now.Add(cfg.SessionTTL)),
	}
	if err := global.GWAF_LOCAL_DB.Create(&bean).Error; err != nil {
		return "", model.AccessSession{}, err
	}
	return plain, bean, nil
}

// IssueToken 为某个业务域名签发子令牌，返回要写进该域名 Cookie 的明文。
//
// 过期时间取 min(会话过期, now+TokenTTL)：子令牌绝不能活得比它所属的中心会话久，
// 否则「注销中心会话」就无法真正让所有站点下线。
func (receiver *WafAccessSessionService) IssueToken(sess model.AccessSession, host, hostCode,
	clientIP, fingerprint string, cfg *accessgate.Config) (string, error) {

	plain, err := genAccessSecret()
	if err != nil {
		return "", err
	}
	now := time.Now()
	expire := now.Add(cfg.TokenTTL)
	if sessExpire := time.Time(sess.ExpireTime); !sessExpire.IsZero() && sessExpire.Before(expire) {
		expire = sessExpire
	}
	bean := model.AccessToken{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(now),
			UPDATE_TIME: customtype.JsonTime(now),
		},
		TokenCode:      HashAccessCode(plain),
		SessionCode:    sess.SessionCode,
		AccountName:    sess.AccountName,
		Host:           strings.ToLower(host),
		HostCode:       hostCode,
		ClientIP:       clientIP,
		Fingerprint:    fingerprint,
		Status:         model.AccessStatusValid,
		LastActiveTime: customtype.JsonTime(now),
		ExpireTime:     customtype.JsonTime(expire),
	}
	if err := global.GWAF_LOCAL_DB.Create(&bean).Error; err != nil {
		return "", err
	}
	return plain, nil
}

// ─────────────────────────── 校验（引擎热路径） ───────────────────────────

// ValidateToken 校验业务域子令牌。校验不通过返回 nil。
//
// 三级读取：负向缓存 → 正向缓存 → 数据库。
// 负向缓存的意义常被忽略：用户换设备后旧 Cookie 还会被浏览器发很久，
// 没有它，每个废弃 Cookie 的请求都会打一次库。
//
// 正向缓存 TTL 有 60 秒硬上限，这同时就是「管理端踢下线」的最坏生效延迟——
// 内存缓存 + 优雅升级期间双 Worker 并存时，精确驱逐只能清掉本进程的缓存，
// 另一个进程要等 TTL 到期才会回库发现会话已撤销。不要为了性能把这个上限调大。
func (receiver *WafAccessSessionService) ValidateToken(plain, host, clientIP, fingerprint string,
	cfg *accessgate.Config) *AccessState {

	if plain == "" {
		return nil
	}
	code := HashAccessCode(plain)

	if global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_ACCESS_BAD + code) {
		return nil
	}
	var cached AccessState
	if err := global.GCACHE_WAFCACHE.GetAs(enums.CACHE_ACCESS_TOKEN+code, &cached); err == nil &&
		cached.SessionCode != "" && cached.ExpireUnix > time.Now().Unix() {
		// 缓存命中也必须重新比对绑定条件。缓存键只有 token_code，
		// 若在这里直接返回，攻击者只要先在自己有权的域名上刷一次缓存，
		// 60 秒内就能拿同一个 Cookie 访问任意其它站点。
		if !cached.matchBindings(host, clientIP, fingerprint, cfg) {
			return nil
		}
		return &cached
	}

	var token model.AccessToken
	if err := global.GWAF_LOCAL_DB.Where("token_code = ? and status = ?",
		code, model.AccessStatusValid).First(&token).Error; err != nil {
		receiver.markBad(code)
		return nil
	}
	now := time.Now()
	if time.Time(token.ExpireTime).Before(now) {
		receiver.markBad(code)
		return nil
	}

	// 子令牌有效不代表能放行：它所属的中心会话可能已被踢下线。
	// 这一步 JOIN 校验就是「一处登出、处处失效」得以成立的地方。
	sess := receiver.loadValidSession(token.SessionCode, cfg)
	if sess == nil {
		receiver.markBad(code)
		return nil
	}

	st := &AccessState{
		SessionCode: sess.SessionCode,
		AccountCode: sess.AccountCode,
		AccountName: sess.AccountName,
		ExpireUnix:  time.Time(token.ExpireTime).Unix(),
		Host:        token.Host,
		ClientIP:    token.ClientIP,
		Fingerprint: token.Fingerprint,
	}
	// 先写缓存再判绑定：令牌本身是有效的，缓存的是"这个令牌的签发条件"，
	// 与本次请求是否满足这些条件无关。反过来做会导致合法用户的令牌
	// 因为一次跨域探测就无法进入缓存，每请求都打库。
	global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_ACCESS_TOKEN+code, *st, cfg.CachePositiveTTL)
	if !st.matchBindings(host, clientIP, fingerprint, cfg) {
		return nil
	}
	receiver.touchToken(token, now)
	return st
}

// ValidateSSOSession 校验中心会话 Cookie（认证中心域名上使用）。
func (receiver *WafAccessSessionService) ValidateSSOSession(plain, host, clientIP, fingerprint string,
	cfg *accessgate.Config) *model.AccessSession {

	if plain == "" {
		return nil
	}
	code := HashAccessCode(plain)
	sess := receiver.loadValidSession(code, cfg)
	if sess == nil {
		return nil
	}
	// 老的 local 会话只服务它绑定的那个域名（现在不再签发，见 CreateSession）
	if sess.Scope == model.AccessScopeLocal && sess.BindHost != "" &&
		!strings.EqualFold(sess.BindHost, host) {
		return nil
	}
	if cfg.BindIP && sess.ClientIP != "" && sess.ClientIP != clientIP {
		return nil
	}
	if cfg.BindFingerprint && sess.Fingerprint != "" && sess.Fingerprint != fingerprint {
		return nil
	}
	receiver.touchSession(*sess, time.Now())
	return sess
}

// loadValidSession 取一个仍然有效的会话（含空闲超时判定）。
func (receiver *WafAccessSessionService) loadValidSession(sessionCode string, cfg *accessgate.Config) *model.AccessSession {
	if sessionCode == "" {
		return nil
	}
	var cachedSess model.AccessSession
	if err := global.GCACHE_WAFCACHE.GetAs(enums.CACHE_ACCESS_SESSION+sessionCode, &cachedSess); err == nil &&
		cachedSess.SessionCode != "" && time.Time(cachedSess.ExpireTime).After(time.Now()) {
		return &cachedSess
	}
	var sess model.AccessSession
	if err := global.GWAF_LOCAL_DB.Where("session_code = ? and status = ?",
		sessionCode, model.AccessStatusValid).First(&sess).Error; err != nil {
		return nil
	}
	now := time.Now()
	if time.Time(sess.ExpireTime).Before(now) {
		return nil
	}
	if cfg.IdleTimeout > 0 {
		last := time.Time(sess.LastActiveTime)
		if !last.IsZero() && now.Sub(last) > cfg.IdleTimeout {
			// 空闲太久，顺手落库标记，避免它一直被反复查出来
			receiver.revokeSessionRows(sess.SessionCode, model.AccessRevokeByExpire)
			return nil
		}
	}
	global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_ACCESS_SESSION+sessionCode, sess, cfg.CachePositiveTTL)
	return &sess
}

// markBad 记一条负向缓存。
//
// TTL 取 model.AccessDefaultCachePosTTL（正向缓存的上限值）而不是更短的值，
// 是为了压掉一个竞态：校验侧可能先从库里读到"有效"，此时管理员完成了踢下线
// （落库 + 驱逐缓存），校验侧才把已经过时的状态写回正向缓存。
// 负向缓存的检查排在正向缓存之前，两者 TTL 相同时，残留窗口收敛到
// 「读库 → 写缓存」之间那点耗时（微秒级），工程上等同于不存在。
// 注意不是严格为零：负向缓存从踢下线那一刻开始计时，被写回的正向条目略晚一点，
// 所以理论上仍有一个等于该耗时的尾巴。
func (receiver *WafAccessSessionService) markBad(code string) {
	global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_ACCESS_BAD+code, "1",
		time.Duration(model.AccessDefaultCachePosTTL)*time.Second)
}

// touchToken / touchSession 节流更新最后活跃时间。
func (receiver *WafAccessSessionService) touchToken(token model.AccessToken, now time.Time) {
	last := time.Time(token.LastActiveTime)
	if !last.IsZero() && now.Sub(last) < touchIntervalMinutes*time.Minute {
		return
	}
	global.GWAF_LOCAL_DB.Model(&model.AccessToken{}).Where("token_code = ?", token.TokenCode).
		Updates(map[string]interface{}{"last_active_time": customtype.JsonTime(now)})
}

func (receiver *WafAccessSessionService) touchSession(sess model.AccessSession, now time.Time) {
	last := time.Time(sess.LastActiveTime)
	if !last.IsZero() && now.Sub(last) < touchIntervalMinutes*time.Minute {
		return
	}
	global.GWAF_LOCAL_DB.Model(&model.AccessSession{}).Where("session_code = ?", sess.SessionCode).
		Updates(map[string]interface{}{"last_active_time": customtype.JsonTime(now)})
	// 会话行变了，缓存里的副本作废，否则空闲超时会按旧的活跃时间算
	global.GCACHE_WAFCACHE.Remove(enums.CACHE_ACCESS_SESSION + sess.SessionCode)
}

// ─────────────────────────── 撤销 ───────────────────────────

// RevokeSession 注销一个中心会话及其全部子令牌。
//
// 先落库、再驱逐缓存，顺序不能反：反过来会有一个「缓存已清、库里还有效」的窗口，
// 期间任何一次请求都会把旧状态重新写回缓存，踢下线就失效了。
func (receiver *WafAccessSessionService) RevokeSession(sessionCode, reason string) error {
	if sessionCode == "" {
		return errors.New("会话标识为空")
	}
	tokenCodes := receiver.revokeSessionRows(sessionCode, reason)
	receiver.kickCache(sessionCode, tokenCodes)
	return nil
}

// revokeSessionRows 只做落库部分，返回被撤销的子令牌 code 列表。
func (receiver *WafAccessSessionService) revokeSessionRows(sessionCode, reason string) []string {
	now := customtype.JsonTime(time.Now())
	var tokens []model.AccessToken
	global.GWAF_LOCAL_DB.Where("session_code = ?", sessionCode).Find(&tokens)

	global.GWAF_LOCAL_DB.Model(&model.AccessSession{}).Where("session_code = ?", sessionCode).
		Updates(map[string]interface{}{
			"status": model.AccessStatusRevoked, "revoke_reason": reason, "update_time": now,
		})
	global.GWAF_LOCAL_DB.Model(&model.AccessToken{}).Where("session_code = ?", sessionCode).
		Updates(map[string]interface{}{"status": model.AccessStatusRevoked, "update_time": now})

	codes := make([]string, 0, len(tokens))
	for _, t := range tokens {
		codes = append(codes, t.TokenCode)
	}
	return codes
}

// kickCache 精确驱逐缓存条目。
//
// 之所以做得到「不知道 Cookie 明文也能驱逐」，是因为入库存的 token_code/session_code
// 本身就是明文的 sha256，而缓存键正是用它作后缀的。
//
// 内存缓存下这只对当前进程生效；优雅升级期间另一个 Worker 要等正向缓存 TTL(≤60s)
// 到期回库才会发现会话已撤销。用 Redis 缓存时则是全进程立即生效。
func (receiver *WafAccessSessionService) kickCache(sessionCode string, tokenCodes []string) {
	if sessionCode != "" {
		global.GCACHE_WAFCACHE.Remove(enums.CACHE_ACCESS_SESSION + sessionCode)
	}
	for _, c := range tokenCodes {
		global.GCACHE_WAFCACHE.Remove(enums.CACHE_ACCESS_TOKEN + c)
		receiver.markBad(c)
	}
}

// RevokeToken 只注销某个业务域上的子令牌（用户在单个站点点了退出）。
func (receiver *WafAccessSessionService) RevokeToken(plain string) {
	if plain == "" {
		return
	}
	code := HashAccessCode(plain)
	global.GWAF_LOCAL_DB.Model(&model.AccessToken{}).Where("token_code = ?", code).
		Updates(map[string]interface{}{
			"status": model.AccessStatusRevoked, "update_time": customtype.JsonTime(time.Now()),
		})
	global.GCACHE_WAFCACHE.Remove(enums.CACHE_ACCESS_TOKEN + code)
	receiver.markBad(code)
}

// RevokeByAccount 踢掉某个账号的全部会话（禁用/删除账号、管理员批量踢人时用）。
func (receiver *WafAccessSessionService) RevokeByAccount(accountCode, reason string) int {
	if accountCode == "" {
		return 0
	}
	var sessions []model.AccessSession
	global.GWAF_LOCAL_DB.Where("account_code = ? and status = ?",
		accountCode, model.AccessStatusValid).Find(&sessions)
	for _, s := range sessions {
		_ = receiver.RevokeSession(s.SessionCode, reason)
	}
	return len(sessions)
}

// RevokeByHostCode 撤销某个站点上的全部子令牌（站点被删除时用）。
//
// 只动子令牌、不动中心会话：站点没了不代表这个人该被登出，他在其它站点上的
// 访问应当继续有效。这正是「中心会话 + 每域子令牌」两层结构存在的意义。
func (receiver *WafAccessSessionService) RevokeByHostCode(hostCode string) int {
	if strings.TrimSpace(hostCode) == "" {
		return 0
	}
	var tokens []model.AccessToken
	global.GWAF_LOCAL_DB.Where("host_code = ? and status = ?",
		hostCode, model.AccessStatusValid).Find(&tokens)
	if len(tokens) == 0 {
		return 0
	}
	global.GWAF_LOCAL_DB.Model(&model.AccessToken{}).Where("host_code = ?", hostCode).
		Updates(map[string]interface{}{
			"status": model.AccessStatusRevoked, "update_time": customtype.JsonTime(time.Now()),
		})
	for _, t := range tokens {
		global.GCACHE_WAFCACHE.Remove(enums.CACHE_ACCESS_TOKEN + t.TokenCode)
		receiver.markBad(t.TokenCode)
	}
	return len(tokens)
}

// ─────────────────────────── 管理端查询 ───────────────────────────

func (receiver *WafAccessSessionService) GetListApi(req request.WafAccessSessionSearchReq) ([]model.AccessSession, int64, error) {
	var list []model.AccessSession
	var total int64 = 0

	db := global.GWAF_LOCAL_DB.Model(&model.AccessSession{}).
		Where("user_code = ? and tenant_id = ?", global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
	if strings.TrimSpace(req.AccountName) != "" {
		db = db.Where("account_name like ?", "%"+strings.TrimSpace(req.AccountName)+"%")
	}
	if strings.TrimSpace(req.ClientIP) != "" {
		db = db.Where("client_ip like ?", "%"+strings.TrimSpace(req.ClientIP)+"%")
	}
	// Status 用指针：不传=全部，传 0 也要能查到已注销的会话。
	// 若用 int 零值判定，用户就永远查不到已注销会话。
	if req.Status != nil {
		db = db.Where("status = ?", *req.Status)
	}
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := db.Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).
		Order("login_time desc").Find(&list).Error; err != nil {
		return nil, 0, err
	}
	// 补上「这个会话在哪几个站点上有活令牌」。
	// 只给数量的话，管理员看到"3"还得再去别处查是哪三个才能判断影响面；
	// 域名本身就在 access_token 行里，顺手带出来就是了。
	for i := range list {
		var hosts []string
		global.GWAF_LOCAL_DB.Model(&model.AccessToken{}).
			Where("session_code = ? and status = ?", list[i].SessionCode, model.AccessStatusValid).
			Order("last_active_time desc").Pluck("host", &hosts)
		list[i].TokenHosts = hosts
		list[i].TokenCount = len(hosts)
	}
	return list, total, nil
}

// KickApi 管理端踢下线。按会话主键定位，再用查出来的 session_code 撤销——
// 不直接信任前端传来的 session_code，避免越权踢掉别的租户的会话。
func (receiver *WafAccessSessionService) KickApi(req request.WafAccessSessionKickReq) error {
	var sess model.AccessSession
	if err := global.GWAF_LOCAL_DB.Where("id = ? and user_code = ? and tenant_id = ?",
		req.Id, global.GWAF_USER_CODE, global.GWAF_TENANT_ID).First(&sess).Error; err != nil {
		return errors.New("会话不存在")
	}
	return receiver.RevokeSession(sess.SessionCode, model.AccessRevokeByAdmin)
}

// KickByAccountApi 按账号批量踢。同样先按主键把账号查出来再取它的 Id。
func (receiver *WafAccessSessionService) KickByAccountApi(req request.WafAccessSessionKickByAccountReq) (int, error) {
	var acct model.AccessAccount
	if err := global.GWAF_LOCAL_DB.Where("id = ? and user_code = ? and tenant_id = ?",
		req.AccountId, global.GWAF_USER_CODE, global.GWAF_TENANT_ID).First(&acct).Error; err != nil {
		return 0, errors.New("账号不存在")
	}
	return receiver.RevokeByAccount(acct.Id, model.AccessRevokeByAdmin), nil
}

// KickAllApi 踢掉本租户全部在线会话（配置改错、疑似泄露时的应急手段）。
func (receiver *WafAccessSessionService) KickAllApi() int {
	var sessions []model.AccessSession
	global.GWAF_LOCAL_DB.Where("user_code = ? and tenant_id = ? and status = ?",
		global.GWAF_USER_CODE, global.GWAF_TENANT_ID, model.AccessStatusValid).Find(&sessions)
	for _, s := range sessions {
		_ = receiver.RevokeSession(s.SessionCode, model.AccessRevokeByAdmin)
	}
	return len(sessions)
}

// ─────────────────────────── 清理 ───────────────────────────

// CleanExpired 由定时任务调用：标记过期行 → 删除票据 → 删除长期无用的历史行。
// 返回各步影响的行数，供任务日志记录。
func (receiver *WafAccessSessionService) CleanExpired(keepDays int) (expiredSession, expiredToken, delTicket, delOld int64) {
	now := time.Now()
	nowJSON := customtype.JsonTime(now)

	r1 := global.GWAF_LOCAL_DB.Model(&model.AccessSession{}).
		Where("status = ? and expire_time < ?", model.AccessStatusValid, nowJSON).
		Updates(map[string]interface{}{"status": model.AccessStatusRevoked,
			"revoke_reason": model.AccessRevokeByExpire, "update_time": nowJSON})
	r2 := global.GWAF_LOCAL_DB.Model(&model.AccessToken{}).
		Where("status = ? and expire_time < ?", model.AccessStatusValid, nowJSON).
		Updates(map[string]interface{}{"status": model.AccessStatusRevoked, "update_time": nowJSON})

	// 票据只活 60 秒，多留 10 分钟足够排查问题，之后直接删
	r3 := global.GWAF_LOCAL_DB.Where("expire_time < ?",
		customtype.JsonTime(now.Add(-10*time.Minute))).Delete(&model.AccessTicket{})

	if keepDays <= 0 {
		keepDays = 7
	}
	cutoff := customtype.JsonTime(now.AddDate(0, 0, -keepDays))
	r4 := global.GWAF_LOCAL_DB.Where("status = ? and update_time < ?",
		model.AccessStatusRevoked, cutoff).Delete(&model.AccessToken{})
	global.GWAF_LOCAL_DB.Where("status = ? and update_time < ?",
		model.AccessStatusRevoked, cutoff).Delete(&model.AccessSession{})

	return r1.RowsAffected, r2.RowsAffected, r3.RowsAffected, r4.RowsAffected
}

// truncate 按字节裁剪，避免超长 UA 撑爆列宽。
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
