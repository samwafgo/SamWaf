package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/model/response"
	"SamWaf/wafenginecore/accessgate"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type WafAccessConfigService struct{}

var WafAccessConfigServiceApp = new(WafAccessConfigService)

// pathPrefixPattern 自服务路径前缀的合法字符集。
// 收紧到这个范围是为了让它能安全地参与字符串比较与 URL 拼接，
// 不用担心大小写、转义、路径穿越这些问题。
var pathPrefixPattern = regexp.MustCompile(`^/[a-z0-9_\-/]{2,63}$`)

// GetConfig 读取全局配置；没有行就返回默认值（不落库）。
// 「读的时候不建行」是刻意的：用户没进过配置页，库里就不该多出一行没人管的记录。
func (receiver *WafAccessConfigService) GetConfig() model.AccessConfig {
	var bean model.AccessConfig
	if err := global.GWAF_LOCAL_DB.Where("user_code = ? and tenant_id = ?",
		global.GWAF_USER_CODE, global.GWAF_TENANT_ID).First(&bean).Error; err != nil {
		return model.DefaultAccessConfig()
	}
	bean.FillDefaults()
	return bean
}

// GetDetailApi 给管理端用：把密钥类字段换成「是否已设置」的布尔量。
// 密钥本身有 json:"-"，这里再补两个标志位，前端才能区分「没配」和「配了但不回显」。
func (receiver *WafAccessConfigService) GetDetailApi() model.AccessConfig {
	bean := receiver.GetConfig()
	bean.HasHmacSecret = strings.TrimSpace(bean.HmacSecret) != ""
	bean.HasServiceToken = strings.TrimSpace(bean.ServiceTokenHashes) != ""
	return bean
}

// SaveApi 保存全局配置并立即发布运行时快照。
func (receiver *WafAccessConfigService) SaveApi(req request.WafAccessConfigSaveReq) error {
	center, centerHost, err := normalizeCenterOrigin(req.CenterOrigin)
	if err != nil {
		return err
	}
	// 认证中心域名是必填项：整个功能就是"先跳到它登录一次，然后处处通行"，没有它就无处可跳。
	// 与之配套，认证中心所在的站点被禁止删除、也禁止改掉域名（见 DelHostApi / ModifyApi），
	// 这样"配置里指着一个不存在的认证中心"这种状态就没有正常途径能产生。
	if centerHost == "" {
		return errors.New("请指定认证中心域名，它是统一认证的入口")
	}
	// 认证中心必须是已经配置过的站点。请求进不到引擎（ServeHTTP 找不到 host 直接 403），
	// 跳过去就是一个 403 死循环——与其让用户线上踩，不如保存时就拦住。
	if !receiver.isCenterHostConfigured(centerHost) {
		return errors.New("认证中心域名必须先在【网站维护】里配置为一个站点：" + centerHost)
	}

	prefix := accessgate.NormalizePathPrefix(req.PathPrefix)
	if !pathPrefixPattern.MatchString(prefix) {
		return errors.New("路径前缀只能包含小写字母、数字、下划线、短横线，长度 3-64，且以 / 开头")
	}
	// 与 ACME 校验路径重叠会让证书续期全线失败，且这个故障要等到续期那天才暴露。
	if strings.HasPrefix(prefix, "/.well-known") ||
		strings.HasPrefix(global.GSSL_HTTP_CHANGLE_PATH, prefix) {
		return errors.New("路径前缀不能与证书校验路径 /.well-known/acme-challenge/ 重叠")
	}

	cookiePrefix := strings.ToLower(strings.TrimSpace(req.CookiePrefix))
	if cookiePrefix == "" {
		cookiePrefix = model.AccessDefaultCookiePrefix
	}
	if !regexp.MustCompile(`^[a-z0-9_\-]{2,32}$`).MatchString(cookiePrefix) {
		return errors.New("Cookie 前缀只能包含小写字母、数字、下划线、短横线，长度 2-32")
	}

	old := receiver.GetConfig()
	now := customtype.JsonTime(time.Now())

	bean := old
	bean.CenterOrigin = center
	bean.PathPrefix = prefix
	bean.CookiePrefix = cookiePrefix
	bean.SessionTTLMinutes = req.SessionTTLMinutes
	bean.TokenTTLMinutes = req.TokenTTLMinutes
	bean.TicketTTLSeconds = req.TicketTTLSeconds
	bean.IdleTimeoutMinutes = req.IdleTimeoutMinutes
	bean.BindIP = boolInt(req.BindIP)
	bean.BindFingerprint = boolInt(req.BindFingerprint)
	bean.RequireOtp = boolInt(req.RequireOtp)
	bean.MaxFailCount = req.MaxFailCount
	bean.LockMinutes = req.LockMinutes
	bean.GlobalExcludePaths = req.GlobalExcludePaths
	bean.BypassIPGroupCode = strings.TrimSpace(req.BypassIPGroupCode)
	bean.ServiceTokenHeader = strings.TrimSpace(req.ServiceTokenHeader)
	bean.UnauthAction = req.UnauthAction
	bean.PassIdentityHeader = boolInt(req.PassIdentityHeader)
	bean.ForceSecureCookie = boolInt(req.ForceSecureCookie)
	bean.CachePositiveTTLSec = req.CachePositiveTTLSec
	bean.UPDATE_TIME = now

	// 服务令牌：空串=不动（前端不回显密文，提交时自然是空的），"-"=清空。
	// 若不这么设计，用户每次改别的字段都会把令牌清掉。
	switch strings.TrimSpace(req.ServiceTokens) {
	case "":
	case "-":
		bean.ServiceTokenHashes = ""
	default:
		bean.ServiceTokenHashes = hashServiceTokens(req.ServiceTokens)
	}

	// HMAC 密钥首次保存时自动生成，之后保持不变（轮换走单独的接口，
	// 因为轮换会让所有在途的 rq 失效，是个有副作用的动作，不该混在普通保存里）。
	if strings.TrimSpace(bean.HmacSecret) == "" {
		enc, err := receiver.newEncryptedSecret()
		if err != nil {
			return err
		}
		bean.HmacSecret = enc
	}

	bean.FillDefaults()

	if bean.Id == "" {
		bean.Id = uuid.GenUUID()
		bean.BaseOrm = baseorm.BaseOrm{
			Id: bean.Id, USER_CODE: global.GWAF_USER_CODE, Tenant_ID: global.GWAF_TENANT_ID,
			CREATE_TIME: now, UPDATE_TIME: now,
		}
		if err := global.GWAF_LOCAL_DB.Create(&bean).Error; err != nil {
			return err
		}
	} else {
		if err := global.GWAF_LOCAL_DB.Save(&bean).Error; err != nil {
			return err
		}
	}

	receiver.PublishConfig()
	return nil
}

// RegenerateSecretApi 轮换 rq 签名密钥。
// 副作用是所有在途的认证跳转会失效（用户重跳一次即可），已登录会话不受影响。
func (receiver *WafAccessConfigService) RegenerateSecretApi() error {
	bean := receiver.GetConfig()
	enc, err := receiver.newEncryptedSecret()
	if err != nil {
		return err
	}
	now := customtype.JsonTime(time.Now())
	if bean.Id == "" {
		bean.BaseOrm = baseorm.BaseOrm{
			Id: uuid.GenUUID(), USER_CODE: global.GWAF_USER_CODE, Tenant_ID: global.GWAF_TENANT_ID,
			CREATE_TIME: now, UPDATE_TIME: now,
		}
		bean.HmacSecret = enc
		if err := global.GWAF_LOCAL_DB.Create(&bean).Error; err != nil {
			return err
		}
	} else if err := global.GWAF_LOCAL_DB.Model(&model.AccessConfig{}).Where("id = ?", bean.Id).
		Updates(map[string]interface{}{"hmac_secret": enc, "update_time": now}).Error; err != nil {
		return err
	}
	receiver.PublishConfig()
	return nil
}

// PublishConfig 把库里的配置编译成运行时快照并原子发布。
//
// 必须在 StartWaf() 之前同步调用一次（见 cmd/samwaf/main.go）。理由与 IP 组一致：
// 访问控制晚生效就是一段裸奔窗口，而这个功能的全部意义就是不让人裸奔。
func (receiver *WafAccessConfigService) PublishConfig() {
	bean := receiver.GetConfig()

	secret := decryptAccessSecret(bean.HmacSecret)
	if secret == "" {
		// 拿不到密钥就无法给回跳请求签名。此时宁可让跨域 SSO 走不通（用户会看到跳转失败），
		// 也绝不能退化成"不验签"——那等于把开放重定向的大门直接敞开。
		zlog.Warn("统一访问认证：签名密钥为空或解密失败，跨域跳转将不可用")
	}

	_, centerHost, _ := normalizeCenterOrigin(bean.CenterOrigin)
	// 认证中心站点被删除有专门的拦截（见 DelHostApi），改域名也拦（见 ModifyApi），
	// 所以这里基本走不到。真走到了就清空——让引擎按"没有认证中心"处理并告警放行，
	// 总好过让全站跳到一个必然 403 的地址。
	if centerHost != "" && !receiver.isCenterHostConfigured(centerHost) {
		zlog.Warn("统一访问认证：认证中心域名已不在网站列表中，访问控制将不生效",
			"center_host", centerHost)
		bean.CenterOrigin = ""
		centerHost = ""
	}

	cfg := &accessgate.Config{
		ForceDisable: global.GCONFIG_ACCESS_FORCE_DISABLE,
		GlobalEnable: global.GCONFIG_ACCESS_ENABLE == 1,

		CenterOrigin: bean.CenterOrigin,
		CenterHost:   centerHost,

		PathPrefix:      accessgate.NormalizePathPrefix(bean.PathPrefix),
		CookiePrefix:    bean.CookiePrefix,
		CookieSSOName:   bean.CookiePrefix + "_sso",
		CookieTokenName: bean.CookiePrefix + "_tk",
		HmacSecret:      []byte(secret),

		SessionTTL:  time.Duration(bean.SessionTTLMinutes) * time.Minute,
		TokenTTL:    time.Duration(bean.TokenTTLMinutes) * time.Minute,
		TicketTTL:   time.Duration(bean.TicketTTLSeconds) * time.Second,
		IdleTimeout: time.Duration(bean.IdleTimeoutMinutes) * time.Minute,

		BindIP:          bean.BindIP == 1,
		BindFingerprint: bean.BindFingerprint == 1,
		RequireOtp:      bean.RequireOtp == 1,
		MaxFailCount:    bean.MaxFailCount,
		LockDuration:    time.Duration(bean.LockMinutes) * time.Minute,

		GlobalExcludePaths: accessgate.BuildExcludePaths(bean.GlobalExcludePaths),
		BypassIPGroupCode:  bean.BypassIPGroupCode,
		ServiceTokenHeader: bean.ServiceTokenHeader,
		ServiceTokenHashes: splitLines(bean.ServiceTokenHashes),

		UnauthAction:       bean.UnauthAction,
		PassIdentityHeader: bean.PassIdentityHeader == 1,
		ForceSecureCookie:  bean.ForceSecureCookie == 1,
		CachePositiveTTL:   time.Duration(bean.CachePositiveTTLSec) * time.Second,
	}
	accessgate.SetConfig(cfg)
}

// IsHostUsedAsCenter 判断某个站点是不是当前的认证中心，返回 (是否, 认证中心域名)。
//
// 判定放在「站点这一侧」而不是复用 isCenterHostConfigured：后者回答的是
// "这个域名还有站点在托管吗"，遍历全表；这里要回答的是"删掉这一个站点会不会
// 让认证中心失去托管"，只能拿这个站点自己的域名去比。泛域名站点也算数——
// *.example.com 就是 sso.example.com 的托管方。
func (receiver *WafAccessConfigService) IsHostUsedAsCenter(host model.Hosts) (bool, string) {
	bean := receiver.GetConfig()
	_, centerHost, _ := normalizeCenterOrigin(bean.CenterOrigin)
	if centerHost == "" {
		return false, ""
	}
	pure := centerHost
	if idx := strings.LastIndex(pure, ":"); idx > 0 {
		pure = pure[:idx]
	}
	pure = strings.ToLower(pure)

	domains := append([]string{host.Host}, splitLines(host.BindMoreHost)...)
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if d == pure || d == "*" {
			return true, centerHost
		}
		if strings.HasPrefix(d, "*.") && strings.HasSuffix(pure, d[1:]) {
			return true, centerHost
		}
	}
	return false, ""
}

// SyncAfterHostChanged 站点变动后重新对齐认证中心配置。
//
// 正常路径上认证中心站点删不掉也改不了域名，所以这里是最后一道兜底（比如
// 直接改库、或者将来新增了别的改站点入口）。库里的值必须一起清掉：留着的话
// 配置页仍显示一个早已不存在的地址，用户看不出为什么统一认证不生效；
// 而且哪天有人恰好新建了同名站点，一个被遗忘的配置会突然自己复活。
func (receiver *WafAccessConfigService) SyncAfterHostChanged() {
	bean := receiver.GetConfig()
	if bean.Id != "" && strings.TrimSpace(bean.CenterOrigin) != "" {
		_, centerHost, _ := normalizeCenterOrigin(bean.CenterOrigin)
		if centerHost != "" && !receiver.isCenterHostConfigured(centerHost) {
			zlog.Warn("统一访问认证：认证中心站点已失效，已清空认证中心配置；在重新指定之前访问控制不会生效",
				"center_host", centerHost)
			global.GWAF_LOCAL_DB.Model(&model.AccessConfig{}).Where("id = ?", bean.Id).
				Updates(map[string]interface{}{
					"center_origin": "", "update_time": customtype.JsonTime(time.Now()),
				})
		}
	}
	receiver.PublishConfig()
}

// GetCenterHostOptionsApi 列出可以直接拿来当认证中心的站点地址。
//
// 排除三类：
//   - 全局网站：它是"所有未匹配域名"的兜底，不是一个真实可访问的地址
//   - 泛域名(*、*.a.com)：跳转地址必须是具体的一个域名，通配符没法直接用
//   - 未启动的站点：跳过去连不上
//
// 绑定的多域名也一并列出，它们同样能命中这个站点。
func (receiver *WafAccessConfigService) GetCenterHostOptionsApi() []response.AccessCenterHostOption {
	var hosts []model.Hosts
	global.GWAF_LOCAL_DB.Where("user_code = ? and tenant_id = ?",
		global.GWAF_USER_CODE, global.GWAF_TENANT_ID).Find(&hosts)

	out := make([]response.AccessCenterHostOption, 0, len(hosts))
	seen := map[string]bool{}
	for _, h := range hosts {
		if h.GLOBAL_HOST == 1 || h.START_STATUS != 0 {
			continue
		}
		note := strings.TrimSpace(h.Nickname)
		if note == "" {
			note = strings.TrimSpace(h.REMARKS)
		}
		domains := append([]string{h.Host}, splitLines(h.BindMoreHost)...)
		for _, d := range domains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" || strings.Contains(d, "*") {
				continue
			}
			origin := buildOrigin(d, h.Port, h.Ssl == 1)
			if seen[origin] {
				continue
			}
			seen[origin] = true
			label := origin
			if note != "" {
				label = origin + "（" + note + "）"
			}
			out = append(out, response.AccessCenterHostOption{
				Origin: origin, Label: label, HostCode: h.Code,
			})
		}
	}
	return out
}

// buildOrigin 拼出 scheme://host[:port]，默认端口省略——这样生成的地址和用户
// 在浏览器地址栏里看到的完全一致，回头做域名比对时也不会因为 ":443" 的有无而错位。
func buildOrigin(domain string, port int, ssl bool) string {
	scheme := "http"
	def := 80
	if ssl {
		scheme, def = "https", 443
	}
	if port == def || port == 0 {
		return scheme + "://" + domain
	}
	return scheme + "://" + domain + ":" + strconv.Itoa(port)
}

// ─────────────────────────── 内部 ───────────────────────────

func (receiver *WafAccessConfigService) newEncryptedSecret() (string, error) {
	plain, err := genAccessSecret()
	if err != nil {
		return "", errors.New("生成签名密钥失败")
	}
	return encryptAccessSecret(plain)
}

// isCenterHostConfigured 检查域名是否已被配置成某个站点。
// 主域名、多域名绑定、泛域名三种情况都要认，否则用户用泛域名做认证中心会被误拦。
func (receiver *WafAccessConfigService) isCenterHostConfigured(centerHost string) bool {
	pure := centerHost
	if idx := strings.LastIndex(pure, ":"); idx > 0 {
		pure = pure[:idx]
	}
	var hosts []model.Hosts
	global.GWAF_LOCAL_DB.Where("user_code = ? and tenant_id = ?",
		global.GWAF_USER_CODE, global.GWAF_TENANT_ID).Find(&hosts)
	for _, h := range hosts {
		if strings.EqualFold(h.Host, pure) || h.Host == "*" {
			return true
		}
		// 泛域名 *.example.com 匹配 sso.example.com
		if strings.HasPrefix(h.Host, "*.") &&
			strings.HasSuffix(strings.ToLower(pure), strings.ToLower(h.Host[1:])) {
			return true
		}
		for _, more := range splitLines(h.BindMoreHost) {
			if strings.EqualFold(more, pure) {
				return true
			}
		}
	}
	return false
}

// normalizeCenterOrigin 校验并归一化认证中心地址，返回 (origin, host[:port], err)。
// 空串在这里不报错（PublishConfig 读老数据时也会调它），必填校验在 SaveApi 里做。
func normalizeCenterOrigin(raw string) (string, string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", "", errors.New("认证中心地址格式不正确")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", errors.New("认证中心地址必须以 http:// 或 https:// 开头")
	}
	if u.Host == "" {
		return "", "", errors.New("认证中心地址缺少域名")
	}
	if u.User != nil {
		return "", "", errors.New("认证中心地址不能包含用户名密码")
	}
	host := strings.ToLower(u.Host)
	// 只保留 scheme://host，路径/查询串一律丢弃：拼接跳转地址时会自己加路径，
	// 留着只会拼出 https://sso.com/foo/samwaf_access/authorize 这种坏地址。
	return scheme + "://" + host, host, nil
}

// hashServiceTokens 把明文服务令牌逐行摘成 sha256。明文绝不落库。
func hashServiceTokens(raw string) string {
	var out []string
	for _, line := range splitLines(raw) {
		sum := sha256.Sum256([]byte(line))
		out = append(out, hex.EncodeToString(sum[:]))
	}
	return strings.Join(out, "\n")
}

// splitLines 按换行/逗号切分并去空白与空行。
func splitLines(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	replaced := strings.NewReplacer("\r\n", "\n", "\r", "\n", ",", "\n").Replace(raw)
	var out []string
	for _, line := range strings.Split(replaced, "\n") {
		item := strings.TrimSpace(line)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func boolInt(v int) int {
	if v == 1 {
		return 1
	}
	return 0
}
