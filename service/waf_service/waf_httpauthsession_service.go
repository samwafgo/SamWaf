package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

type WafHttpAuthSessionService struct{}

var WafHttpAuthSessionServiceApp = new(WafHttpAuthSessionService)

const (
	// httpAuthCachePosTTL 会话校验通过的正向缓存时长，同时也是「管理端踢下线」的最坏生效延迟。
	// 库才是真相源，缓存只为省掉每请求一次查询，别为了性能把它调大。
	httpAuthCachePosTTL = 60 * time.Second

	// httpAuthTouchInterval last_active 的写库节流窗口。
	// 不节流的话，每个静态资源请求都会写一次库；对空闲超时判定的精度影响可以忽略。
	httpAuthTouchInterval = 60 * time.Second

	// httpAuthKickCooldown Basic 模式被踢后的强制重认证冷却期。
	//
	// HTTP Basic 没有登出机制：浏览器把凭证缓存起来每个请求原样重发，服务端返回 401
	// 只会让它拿同一份凭证自动重试，用户看不到弹窗。唯一可靠的手段是更换
	// WWW-Authenticate 的 realm——浏览器按 realm 缓存凭证，realm 变了才会重新提示。
	//
	// 所以 Basic 模式的「踢下线」在协议层面只能做到「强制重新输入一次密码」：
	// 冷却期内一律用新 realm 挑战，冷却期过后凭同一账号密码可以重新登录。
	// 要让某个用户彻底进不来，只能删除或改掉他的账号（那时 checkCredentials 直接不过）。
	// Custom 模式没有这个限制，踢下线是干净的一次性失效。
	httpAuthKickCooldown = 60 * time.Second
)

// HashHttpAuthToken 把 Cookie 明文摘成入库与缓存用的键。
// 明文永远不落库：库被拖走也拿不到能直接使用的 Cookie；同时这个摘要正好当缓存键后缀，
// 管理端在不知道明文的前提下就能精确驱逐某条会话的缓存。
func HashHttpAuthToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// BasicSessionCode 是 Basic 模式的会话身份。
//
// Basic 没有令牌可言——浏览器每个请求原样重发凭证，服务端能识别的最小单位就是
// 「哪个用户从哪个 IP 来」，所以用这三元组的摘要当会话标识。
func BasicSessionCode(hostCode, userName, clientIP string) string {
	sum := sha256.Sum256([]byte(hostCode + "|" + userName + "|" + clientIP))
	return hex.EncodeToString(sum[:])
}

// genHttpAuthToken 生成 32 字节高熵随机串。用 crypto/rand 而不是 uuid：
// uuid 的可预测位太多，不适合当会话凭据。
func genHttpAuthToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func httpAuthSessionCacheKey(hostCode, tokenCode string) string {
	return enums.CACHE_HTTPAUTH_SESSION + hostCode + ":" + tokenCode
}

// ─────────────────────────── 签发 ───────────────────────────

// CreateCustomSession 建立一条 custom 模式会话，返回要写进 Cookie 的明文。
func (receiver *WafHttpAuthSessionService) CreateCustomSession(host model.Hosts, userName, clientIP,
	userAgent string, cfg model.HttpAuthConfig) (string, model.HttpAuthSession, error) {

	plain, err := genHttpAuthToken()
	if err != nil {
		return "", model.HttpAuthSession{}, err
	}
	bean := receiver.newSession(host, model.HttpAuthTypeCustom, HashHttpAuthToken(plain),
		userName, clientIP, userAgent, cfg)
	if err := global.GWAF_LOCAL_DB.Create(&bean).Error; err != nil {
		return "", model.HttpAuthSession{}, err
	}
	receiver.cacheSession(bean)
	return plain, bean, nil
}

// newSession 组装一条会话行。归属地在建会话时定格：会话页要能一眼看出「这人从哪儿登进来的」，
// 事后再查已经晚了——IP 库更新或用户换网络后，同一个 IP 的解析结果可能已经变了。
func (receiver *WafHttpAuthSessionService) newSession(host model.Hosts, authType, tokenCode,
	userName, clientIP, userAgent string, cfg model.HttpAuthConfig) model.HttpAuthSession {

	now := time.Now()
	country, city := accessLookupLocation(clientIP)
	return model.HttpAuthSession{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(now),
			UPDATE_TIME: customtype.JsonTime(now),
		},
		HostCode:       host.Code,
		Host:           host.Host,
		TokenCode:      tokenCode,
		AuthType:       authType,
		UserName:       userName,
		ClientIP:       clientIP,
		Country:        country,
		City:           city,
		UserAgent:      truncate(userAgent, 500),
		Status:         model.HttpAuthStatusValid,
		LoginTime:      customtype.JsonTime(now),
		LastActiveTime: customtype.JsonTime(now),
		ExpireTime:     customtype.JsonTime(now.Add(time.Duration(cfg.SessionTTL) * time.Minute)),
	}
}

// ─────────────────────────── 校验 ───────────────────────────

// ValidateCustom 校验 custom 模式的 Cookie 明文。第二个返回值为 false 表示要下发登录页。
func (receiver *WafHttpAuthSessionService) ValidateCustom(hostCode, plain, clientIP string,
	cfg model.HttpAuthConfig) (*model.HttpAuthSession, bool) {

	if strings.TrimSpace(plain) == "" {
		return nil, false
	}
	tokenCode := HashHttpAuthToken(plain)
	// 负向缓存：挡住拿废弃 Cookie 反复打库的请求
	if global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_HTTPAUTH_BAD + tokenCode) {
		return nil, false
	}
	sess := receiver.loadSession(hostCode, tokenCode)
	if sess == nil {
		receiver.markBadToken(tokenCode)
		return nil, false
	}
	now := time.Now()
	ok, dead := receiver.alive(sess, clientIP, cfg, now)
	if !ok {
		// 只有会话真的死了才写负向缓存。换 IP 被拒是"这一次请求"的判断而不是会话状态：
		// 记进负向缓存的话，移动网络切一下基站，回到原网络后还要再被挡 60 秒。
		if dead {
			// 顺手把库里的状态改对。到期由清理任务兜底，但空闲超时只有校验这一刻算得出来，
			// 不落库的话管理端会一直把一个早就掉线的人显示成「在线」。
			if sess.Status == model.HttpAuthStatusValid {
				receiver.revokeRow(sess, model.HttpAuthRevokeByExpire)
			} else {
				receiver.markBadToken(tokenCode)
				global.GCACHE_WAFCACHE.Remove(httpAuthSessionCacheKey(hostCode, tokenCode))
			}
		}
		return nil, false
	}
	receiver.touch(sess, now)
	return sess, true
}

// BasicAuthResult 是 Basic 模式一次认证的判定结果。
type BasicAuthResult struct {
	Session *model.HttpAuthSession
	// Challenge 为 true 表示要用 RealmNonce 换一个 realm 发 401，强制浏览器重新弹窗。
	Challenge bool
	// RealmNonce 只在 Challenge 时有值。
	RealmNonce string
	// Expired 区分「到期」与「被踢」，供审计记录用。
	Expired bool
	// Created 表示本次是新建/复活了会话行，即一次真正的登录。
	// Basic 模式每个请求都带凭证，只有这个标志能区分「刚登录」与「登录后的第 200 个请求」，
	// 否则审计表会被同一个人的一次访问刷出成百上千条「登录成功」。
	Created bool
}

// TouchBasicSession 是 Basic 模式每次凭证校验通过后的会话记账。
//
// 与 custom 的区别在于这里没有令牌：会话行按 (站点+用户+IP) 唯一，不存在就建、
// 存在就刷新活跃时间；被踢或到期时返回 Challenge，由调用方换 realm 发 401。
func (receiver *WafHttpAuthSessionService) TouchBasicSession(host model.Hosts, userName, clientIP,
	userAgent string, cfg model.HttpAuthConfig) BasicAuthResult {

	tokenCode := BasicSessionCode(host.Code, userName, clientIP)

	// 冷却期内一律挑战，不看会话行状态：这段时间就是留给用户重新输入密码的。
	//
	// 以「键还在不在」决定挑不挑战，而不是以「值读没读出来」：换 Redis 后端时取回的
	// 可能不是 string，类型断言失败就当没被踢，踢下线会静默失效。读不出来就现生成一个
	// 新 nonce——realm 变了才是挑战生效的关键，nonce 具体是什么并不重要。
	//
	// 缓存后端读不到（故障）时按"未被踢"处理：走到这里凭证已经校验通过，
	// 而反过来一律挑战会在故障期间让所有访客反复弹框——冷却期 nonce 自己也写不进缓存，
	// realm 每次都变，等于无限重认证。会话是否到期另有数据库兜底，不依赖这个键。
	kickKey := enums.CACHE_HTTPAUTH_KICK + tokenCode
	kicked, kickErr := global.GCACHE_WAFCACHE.ExistsE(kickKey)
	if kickErr != nil {
		zlog.Debug("[网站密码访问] 踢下线标记读取失败，本次按未被踢处理 err:" + kickErr.Error())
	}
	if kicked {
		nonce, _ := global.GCACHE_WAFCACHE.Get(kickKey).(string)
		if nonce == "" {
			nonce = receiver.startKickCooldown(tokenCode)
		}
		return BasicAuthResult{Challenge: true, RealmNonce: nonce}
	}

	now := time.Now()
	sess := receiver.loadSession(host.Code, tokenCode)
	if sess == nil {
		bean := receiver.newSession(host, model.HttpAuthTypeAuthorization, tokenCode,
			userName, clientIP, userAgent, cfg)
		if err := global.GWAF_LOCAL_DB.Create(&bean).Error; err != nil {
			// 记账失败不能连累访问：凭证本身已经校验通过了
			return BasicAuthResult{Session: &bean}
		}
		receiver.cacheSession(bean)
		return BasicAuthResult{Session: &bean, Created: true}
	}

	// 到期：换 realm 挑战一次，同时开冷却，避免同一次页面加载的几十个请求反复走这段
	if time.Now().After(time.Time(sess.ExpireTime)) && sess.Status == model.HttpAuthStatusValid {
		receiver.revokeRow(sess, model.HttpAuthRevokeByExpire)
		nonce := receiver.startKickCooldown(tokenCode)
		return BasicAuthResult{Challenge: true, RealmNonce: nonce, Expired: true}
	}

	// 状态为已失效且冷却期已过 —— 说明这是踢下线之后的重新登录，凭证刚刚校验通过，放行并复活该行
	if sess.Status != model.HttpAuthStatusValid {
		receiver.reactivate(sess, cfg, now)
		return BasicAuthResult{Session: sess, Created: true}
	}

	receiver.touch(sess, now)
	return BasicAuthResult{Session: sess}
}

// loadSession 先查缓存再回落数据库，未命中不缓存空值（负向缓存另有 CACHE_HTTPAUTH_BAD）。
// 回落查库这一步是重启后会话仍然有效的关键。
// 缓存读取失败（后端故障）与未命中在这里同样处理：都回落查库，所以缓存抖动不会让访客掉线。
func (receiver *WafHttpAuthSessionService) loadSession(hostCode, tokenCode string) *model.HttpAuthSession {
	key := httpAuthSessionCacheKey(hostCode, tokenCode)
	var cached model.HttpAuthSession
	if err := global.GCACHE_WAFCACHE.GetAs(key, &cached); err == nil && cached.TokenCode == tokenCode {
		return &cached
	}
	var bean model.HttpAuthSession
	err := global.GWAF_LOCAL_DB.Where("host_code = ? and token_code = ?", hostCode, tokenCode).
		First(&bean).Error
	if err != nil || bean.Id == "" {
		return nil
	}
	receiver.cacheSession(bean)
	return &bean
}

func (receiver *WafHttpAuthSessionService) cacheSession(bean model.HttpAuthSession) {
	global.GCACHE_WAFCACHE.SetWithTTl(httpAuthSessionCacheKey(bean.HostCode, bean.TokenCode),
		bean, httpAuthCachePosTTL)
}

func (receiver *WafHttpAuthSessionService) markBadToken(tokenCode string) {
	global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_HTTPAUTH_BAD+tokenCode, "1", httpAuthCachePosTTL)
}

// alive 判定一条会话在此刻是否还能放行。
//
// 第二个返回值 dead 区分「会话已经死了」与「只是这次不让过」：
// 前者（撤销/到期/空闲超时）是不可逆的终态，可以写负向缓存少打几次库；
// 后者（换 IP 被拒）换个请求就可能重新成立，写进负向缓存等于连累合法请求。
func (receiver *WafHttpAuthSessionService) alive(sess *model.HttpAuthSession, clientIP string,
	cfg model.HttpAuthConfig, now time.Time) (ok bool, dead bool) {

	if sess.Status != model.HttpAuthStatusValid {
		return false, true
	}
	if now.After(time.Time(sess.ExpireTime)) {
		return false, true
	}
	if cfg.IdleTimeout > 0 {
		last := time.Time(sess.LastActiveTime)
		if !last.IsZero() && now.Sub(last) > time.Duration(cfg.IdleTimeout)*time.Minute {
			return false, true
		}
	}
	if cfg.BindIP == 1 && sess.ClientIP != "" && sess.ClientIP != clientIP {
		return false, false
	}
	return true, false
}

// touch 节流刷新最后活跃时间。库行变了缓存副本就作废，否则空闲超时会按旧的活跃时间算。
func (receiver *WafHttpAuthSessionService) touch(sess *model.HttpAuthSession, now time.Time) {
	last := time.Time(sess.LastActiveTime)
	if !last.IsZero() && now.Sub(last) < httpAuthTouchInterval {
		return
	}
	global.GWAF_LOCAL_DB.Model(&model.HttpAuthSession{}).Where("id = ?", sess.Id).
		Updates(map[string]interface{}{
			"last_active_time": customtype.JsonTime(now), "update_time": customtype.JsonTime(now),
		})
	sess.LastActiveTime = customtype.JsonTime(now)
	global.GCACHE_WAFCACHE.Remove(httpAuthSessionCacheKey(sess.HostCode, sess.TokenCode))
}

// reactivate 把一条已失效的 Basic 会话行按「重新登录」复位，避免同一 (站点+用户+IP) 反复建行。
func (receiver *WafHttpAuthSessionService) reactivate(sess *model.HttpAuthSession,
	cfg model.HttpAuthConfig, now time.Time) {

	expire := customtype.JsonTime(now.Add(time.Duration(cfg.SessionTTL) * time.Minute))
	global.GWAF_LOCAL_DB.Model(&model.HttpAuthSession{}).Where("id = ?", sess.Id).
		Updates(map[string]interface{}{
			"status": model.HttpAuthStatusValid, "revoke_reason": "",
			"login_time": customtype.JsonTime(now), "last_active_time": customtype.JsonTime(now),
			"expire_time": expire, "update_time": customtype.JsonTime(now),
		})
	sess.Status = model.HttpAuthStatusValid
	sess.RevokeReason = ""
	sess.LoginTime = customtype.JsonTime(now)
	sess.LastActiveTime = customtype.JsonTime(now)
	sess.ExpireTime = expire
	receiver.cacheSession(*sess)
}

// startKickCooldown 开一段强制重认证冷却，返回要塞进 realm 的 nonce。
func (receiver *WafHttpAuthSessionService) startKickCooldown(tokenCode string) string {
	nonce := uuid.GenUUID()
	if len(nonce) > 8 {
		nonce = nonce[:8]
	}
	global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_HTTPAUTH_KICK+tokenCode, nonce, httpAuthKickCooldown)
	return nonce
}

// ─────────────────────────── 撤销 ───────────────────────────

// revokeRow 只落库 + 驱逐缓存，不管冷却期。
//
// 先落库、再驱逐缓存，顺序不能反：反过来会有一个「缓存已清、库里还有效」的窗口，
// 期间任何一次请求都会把旧状态重新写回缓存，踢下线就失效了。
func (receiver *WafHttpAuthSessionService) revokeRow(sess *model.HttpAuthSession, reason string) {
	now := customtype.JsonTime(time.Now())
	global.GWAF_LOCAL_DB.Model(&model.HttpAuthSession{}).Where("id = ?", sess.Id).
		Updates(map[string]interface{}{
			"status": model.HttpAuthStatusRevoked, "revoke_reason": reason, "update_time": now,
		})
	sess.Status = model.HttpAuthStatusRevoked
	sess.RevokeReason = reason
	receiver.kickCache(sess.HostCode, sess.TokenCode, sess.AuthType)
}

// kickCache 精确驱逐缓存条目。做得到「不知道 Cookie 明文也能驱逐」，是因为入库存的
// token_code 本身就是明文的 sha256，而缓存键正是用它作后缀的。
//
// Basic 会话额外开一段冷却：它没有令牌可作废，只能靠换 realm 强制浏览器重新弹窗。
func (receiver *WafHttpAuthSessionService) kickCache(hostCode, tokenCode, authType string) {
	global.GCACHE_WAFCACHE.Remove(httpAuthSessionCacheKey(hostCode, tokenCode))
	if authType == model.HttpAuthTypeAuthorization {
		receiver.startKickCooldown(tokenCode)
	} else {
		receiver.markBadToken(tokenCode)
	}
}

// revokeWhere 按条件批量撤销，返回受影响条数。命中的行要逐条驱逐缓存，
// 只更库不清缓存的话，最长还有一个正向缓存 TTL 的时间里旧状态仍然放行。
func (receiver *WafHttpAuthSessionService) revokeWhere(reason string, query string, args ...interface{}) int {
	var list []model.HttpAuthSession
	global.GWAF_LOCAL_DB.Where(query, args...).Where("status = ?", model.HttpAuthStatusValid).Find(&list)
	if len(list) == 0 {
		return 0
	}
	now := customtype.JsonTime(time.Now())
	ids := make([]string, 0, len(list))
	for _, s := range list {
		ids = append(ids, s.Id)
	}
	global.GWAF_LOCAL_DB.Model(&model.HttpAuthSession{}).Where("id in ?", ids).
		Updates(map[string]interface{}{
			"status": model.HttpAuthStatusRevoked, "revoke_reason": reason, "update_time": now,
		})
	for _, s := range list {
		receiver.kickCache(s.HostCode, s.TokenCode, s.AuthType)
	}
	return len(list)
}

// RevokeByUser 账号被删除或改密时调用：该账号在本站点的全部会话立即失效。
func (receiver *WafHttpAuthSessionService) RevokeByUser(hostCode, userName, reason string) int {
	if hostCode == "" || userName == "" {
		return 0
	}
	return receiver.revokeWhere(reason, "host_code = ? and user_name = ?", hostCode, userName)
}

// RevokeByHostCode 站点被删除或关闭密码访问时调用。
func (receiver *WafHttpAuthSessionService) RevokeByHostCode(hostCode, reason string) int {
	if hostCode == "" {
		return 0
	}
	return receiver.revokeWhere(reason, "host_code = ?", hostCode)
}

// ─────────────────────────── 管理端 ───────────────────────────

func (receiver *WafHttpAuthSessionService) GetListApi(req request.WafHttpAuthSessionSearchReq) ([]model.HttpAuthSession, int64, error) {
	var list []model.HttpAuthSession
	var total int64 = 0

	if strings.TrimSpace(req.HostCode) == "" {
		return nil, 0, errors.New("站点编码不能为空")
	}
	db := global.GWAF_LOCAL_DB.Model(&model.HttpAuthSession{}).
		Where("user_code = ? and tenant_id = ? and host_code = ?",
			global.GWAF_USER_CODE, global.GWAF_TENANT_ID, strings.TrimSpace(req.HostCode))
	if v := strings.TrimSpace(req.UserName); v != "" {
		db = db.Where("user_name like ?", "%"+v+"%")
	}
	if v := strings.TrimSpace(req.ClientIP); v != "" {
		db = db.Where("client_ip like ?", "%"+v+"%")
	}
	// 状态用指针：不传 = 全部，传 0 = 只看已失效。普通 int 的零值会让「全部」永远查不出有效会话。
	if req.Status != nil {
		db = db.Where("status = ?", *req.Status)
	}
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := db.Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).
		Order("last_active_time desc").Find(&list).Error; err != nil {
		return nil, 0, err
	}
	now := time.Now()
	for i := range list {
		if list[i].Status == model.HttpAuthStatusValid {
			if remain := int64(time.Time(list[i].ExpireTime).Sub(now).Seconds()); remain > 0 {
				list[i].RemainSeconds = remain
			}
		}
	}
	return list, total, nil
}

// KickApi 踢掉一条会话。按主键把行取出来再拿它的 token_code 去撤销，
// 不接受调用方直接传 token_code——那等于让管理端接口成为「凭摘要操作任意会话」的入口。
func (receiver *WafHttpAuthSessionService) KickApi(req request.WafHttpAuthSessionKickReq) error {
	if strings.TrimSpace(req.Id) == "" {
		return errors.New("会话标识不能为空")
	}
	var bean model.HttpAuthSession
	err := global.GWAF_LOCAL_DB.Where("id = ? and user_code = ? and tenant_id = ?",
		strings.TrimSpace(req.Id), global.GWAF_USER_CODE, global.GWAF_TENANT_ID).First(&bean).Error
	if err != nil || bean.Id == "" {
		return errors.New("会话不存在")
	}
	if bean.Status != model.HttpAuthStatusValid {
		return nil
	}
	receiver.revokeRow(&bean, model.HttpAuthRevokeByAdmin)
	WafSecurityAuditServiceApp.Write(AuditEntry{
		Event:       model.HttpAuthEventKick,
		AccountName: bean.UserName,
		SessionCode: bean.TokenCode,
		Host:        bean.Host,
		HostCode:    bean.HostCode,
		ClientIP:    bean.ClientIP,
		Country:     bean.Country,
		City:        bean.City,
		Result:      model.AccessAuditOK,
		Message:     "管理端踢下线，用户 " + bean.UserName,
	})
	return nil
}

// KickByUserApi 踢掉某个用户在本站点的全部会话。
func (receiver *WafHttpAuthSessionService) KickByUserApi(req request.WafHttpAuthSessionKickByUserReq) (int, error) {
	if strings.TrimSpace(req.HostCode) == "" || strings.TrimSpace(req.UserName) == "" {
		return 0, errors.New("站点编码与用户名不能为空")
	}
	n := receiver.RevokeByUser(strings.TrimSpace(req.HostCode), strings.TrimSpace(req.UserName),
		model.HttpAuthRevokeByAdmin)
	if n > 0 {
		WafSecurityAuditServiceApp.Write(AuditEntry{
			Event:       model.HttpAuthEventKick,
			AccountName: strings.TrimSpace(req.UserName),
			HostCode:    strings.TrimSpace(req.HostCode),
			Result:      model.AccessAuditOK,
			Message:     "管理端按用户踢下线，共 " + strconv.Itoa(n) + " 条会话",
		})
	}
	return n, nil
}

// KickAllApi 踢掉本站点全部会话。
func (receiver *WafHttpAuthSessionService) KickAllApi(req request.WafHttpAuthSessionKickAllReq) (int, error) {
	if strings.TrimSpace(req.HostCode) == "" {
		return 0, errors.New("站点编码不能为空")
	}
	n := receiver.RevokeByHostCode(strings.TrimSpace(req.HostCode), model.HttpAuthRevokeByAdmin)
	if n > 0 {
		WafSecurityAuditServiceApp.Write(AuditEntry{
			Event:    model.HttpAuthEventKick,
			HostCode: strings.TrimSpace(req.HostCode),
			Result:   model.AccessAuditOK,
			Message:  "管理端清空本站点会话，共 " + strconv.Itoa(n) + " 条",
		})
	}
	return n, nil
}

// ─────────────────────────── 清理 ───────────────────────────

// CleanExpired 由定时任务调用：先把到期的有效会话标记失效，再删掉超过保留期的历史行。
// 返回 (本次标记到期数, 删除历史行数)。
func (receiver *WafHttpAuthSessionService) CleanExpired(keepDays int) (int64, int64) {
	if keepDays <= 0 {
		keepDays = 30
	}
	now := time.Now()
	r1 := global.GWAF_LOCAL_DB.Model(&model.HttpAuthSession{}).
		Where("status = ? and expire_time < ?", model.HttpAuthStatusValid, now).
		Updates(map[string]interface{}{
			"status": model.HttpAuthStatusRevoked, "revoke_reason": model.HttpAuthRevokeByExpire,
			"update_time": customtype.JsonTime(now),
		})
	// 到期行的缓存不逐条驱逐：正向缓存 TTL 只有 60 秒，而且 alive() 本来就会独立判过期，
	// 缓存里留着的副本不会让一条已过期的会话继续放行。
	r2 := global.GWAF_LOCAL_DB.Where("status = ? and update_time < ?",
		model.HttpAuthStatusRevoked, now.AddDate(0, 0, -keepDays)).Delete(&model.HttpAuthSession{})
	return r1.RowsAffected, r2.RowsAffected
}
