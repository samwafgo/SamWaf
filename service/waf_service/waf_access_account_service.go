package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/utils"
	"SamWaf/wafsec"
	"errors"
	"strings"
	"time"
)

type WafAccessAccountService struct{}

var WafAccessAccountServiceApp = new(WafAccessAccountService)

// dummyBcryptHash 是一个固定的、永远不会被任何真实密码匹配上的 bcrypt 摘要。
//
// 用途：账号不存在时也跑一次 BcryptVerify，让「用户名存在」与「用户名不存在」
// 两条路径的耗时基本一致。缺了它，攻击者只要测量响应时间就能枚举出有效用户名——
// bcrypt 要几十毫秒，而「查不到直接返回」是微秒级，差异肉眼可辨。
const dummyBcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

const accessTimeLayout = "2006-01-02 15:04:05"

// ─────────────────────────── 引擎侧：凭据校验 ───────────────────────────

// VerifyCredential 校验用户名密码，通过则返回账号。
//
// 无论账号是否存在都会执行一次等价耗时的 bcrypt 比较（见 dummyBcryptHash），
// 且失败原因对外统一成一句话，不区分「用户不存在」与「密码错误」。
func (receiver *WafAccessAccountService) VerifyCredential(accountName, password string) (*model.AccessAccount, error) {
	name := strings.TrimSpace(accountName)
	var acct model.AccessAccount
	found := true
	if name == "" {
		found = false
	} else if err := global.GWAF_LOCAL_DB.Where("account_name = ? and user_code = ? and tenant_id = ?",
		name, global.GWAF_USER_CODE, global.GWAF_TENANT_ID).First(&acct).Error; err != nil {
		found = false
	}

	stored := dummyBcryptHash
	if found && acct.Password != "" {
		stored = acct.Password
	}
	ok := utils.BcryptVerify(stored, password)

	if !found || !ok {
		return nil, errors.New("用户名或密码错误")
	}
	if acct.Status != model.AccessAccountStatusEnable {
		return nil, errors.New("账号已禁用")
	}
	if expire := time.Time(acct.ExpireTime); !expire.IsZero() && expire.Before(time.Now()) {
		return nil, errors.New("账号已过有效期")
	}
	return &acct, nil
}

// IsHostAllowed 判断账号是否被授权访问某个站点。
//
// AllowHostCodes 为空表示「全部站点」——这是默认值，也是绝大多数自用场景想要的。
// 只有显式填了列表才做限制，避免用户建完账号发现哪儿都进不去。
func (receiver *WafAccessAccountService) IsHostAllowed(acct *model.AccessAccount, hostCode string) bool {
	if acct == nil {
		return false
	}
	raw := strings.TrimSpace(acct.AllowHostCodes)
	if raw == "" {
		return true
	}
	replaced := strings.NewReplacer("\r\n", "\n", "\r", "\n", ",", "\n").Replace(raw)
	for _, line := range strings.Split(replaced, "\n") {
		if strings.TrimSpace(line) == hostCode {
			return true
		}
	}
	return false
}

// NeedOtp 判断这次登录是否要走二次验证。
//
// 优先级：账号级设置 > 站点级设置 > 全局设置。三层里任何一层说"豁免"都不再往上看，
// 这样用户既能给某个高危站点单独开 OTP，也能给某个自动化账号单独豁免。
// 未绑定 TOTP 的账号一律不要求（否则会把人锁死在登录页）。
func (receiver *WafAccessAccountService) NeedOtp(acct *model.AccessAccount, hostRequireOtp int, globalRequireOtp bool) bool {
	if acct == nil || acct.OtpBound != 1 || acct.OtpSecret == "" {
		return false
	}
	switch acct.ForceOtp {
	case model.AccessOtpForce:
		return true
	case model.AccessOtpExempt:
		return false
	}
	switch hostRequireOtp {
	case model.AccessOtpForce:
		return true
	case model.AccessOtpExempt:
		return false
	}
	return globalRequireOtp
}

// VerifyOtp 校验动态码。密钥在库里是 wafsec 加密的，这里解密后再比对。
func (receiver *WafAccessAccountService) VerifyOtp(acct *model.AccessAccount, code string) bool {
	if acct == nil || acct.OtpSecret == "" {
		return false
	}
	secret := decryptAccessSecret(acct.OtpSecret)
	if secret == "" {
		return false
	}
	return utils.ValidateOtpCode(strings.TrimSpace(code), secret)
}

// CheckStillUsable 复查账号此刻是否仍可用（启用中、未过期）。
//
// 存在的意义是那些「校验凭据」与「真正发放令牌」之间隔了一段时间的流程：
// OTP 两步登录中间隔着最多 5 分钟，跨域 SSO 换票时更是完全没有再看过账号。
// 管理员在这些窗口里禁用账号，如果不复查就会被绕过。
func (receiver *WafAccessAccountService) CheckStillUsable(accountCode string) (*model.AccessAccount, error) {
	var acct model.AccessAccount
	if err := global.GWAF_LOCAL_DB.Where("id = ? and user_code = ? and tenant_id = ?",
		accountCode, global.GWAF_USER_CODE, global.GWAF_TENANT_ID).First(&acct).Error; err != nil {
		return nil, errors.New("账号不存在")
	}
	if acct.Status != model.AccessAccountStatusEnable {
		return nil, errors.New("账号已禁用")
	}
	if expire := time.Time(acct.ExpireTime); !expire.IsZero() && expire.Before(time.Now()) {
		return nil, errors.New("账号已过有效期")
	}
	return &acct, nil
}

// MarkLogin 记一次成功登录（异步性无所谓，登录本身就是低频事件）。
func (receiver *WafAccessAccountService) MarkLogin(accountId, clientIP string) {
	now := customtype.JsonTime(time.Now())
	global.GWAF_LOCAL_DB.Model(&model.AccessAccount{}).Where("id = ?", accountId).
		Updates(map[string]interface{}{
			"last_login_time": now, "last_login_ip": clientIP, "update_time": now,
		})
}

// ─────────────────────────── 管理端：CRUD ───────────────────────────

func (receiver *WafAccessAccountService) AddApi(req request.WafAccessAccountAddReq) (model.AccessAccount, error) {
	name := strings.TrimSpace(req.AccountName)
	if name == "" {
		return model.AccessAccount{}, errors.New("登录名不能为空")
	}
	if err := receiver.checkNameFree(name, ""); err != nil {
		return model.AccessAccount{}, err
	}
	// 访客账号与管理员账号共用同一套口令复杂度策略：这些账号是公网可达的登录入口，
	// 没有理由比管理端宽松。
	if ok, msg := utils.ValidatePasswordComplexity(req.Password, utils.BuildPolicyFromConfig()); !ok {
		return model.AccessAccount{}, errors.New(msg)
	}
	hash, err := utils.BcryptHash(req.Password)
	if err != nil {
		return model.AccessAccount{}, errors.New("密码加密失败")
	}
	expire, err := parseAccessTime(req.ExpireTime)
	if err != nil {
		return model.AccessAccount{}, err
	}
	now := time.Now()
	bean := model.AccessAccount{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(now),
			UPDATE_TIME: customtype.JsonTime(now),
		},
		AccountName:    name,
		Password:       hash,
		NickName:       strings.TrimSpace(req.NickName),
		Status:         normalizeStatus(req.Status),
		ForceOtp:       normalizeOtpMode(req.ForceOtp),
		AllowHostCodes: req.AllowHostCodes,
		ExpireTime:     customtype.JsonTime(expire),
		PwdUpdateTime:  customtype.JsonTime(now),
		Remarks:        req.Remarks,
	}
	if err := global.GWAF_LOCAL_DB.Create(&bean).Error; err != nil {
		return model.AccessAccount{}, err
	}
	return bean, nil
}

func (receiver *WafAccessAccountService) ModifyApi(req request.WafAccessAccountEditReq) error {
	bean, err := receiver.mustLoad(req.Id)
	if err != nil {
		return err
	}
	expire, err := parseAccessTime(req.ExpireTime)
	if err != nil {
		return err
	}
	status := normalizeStatus(req.Status)
	updates := map[string]interface{}{
		"nick_name":        strings.TrimSpace(req.NickName),
		"status":           status,
		"force_otp":        normalizeOtpMode(req.ForceOtp),
		"allow_host_codes": req.AllowHostCodes,
		"expire_time":      customtype.JsonTime(expire),
		"remarks":          req.Remarks,
		"update_time":      customtype.JsonTime(time.Now()),
	}
	if err := global.GWAF_LOCAL_DB.Model(&model.AccessAccount{}).Where("id = ?", bean.Id).
		Updates(updates).Error; err != nil {
		return err
	}
	// 下面三种改动都必须立刻把该账号已有的在线会话踢掉，否则改动只挡新登录，
	// 已经登进去的人还能一直用到会话自然过期（子令牌默认 12 小时）：
	//   - 禁用账号
	//   - 把有效期改到过去
	//   - 收回站点授权 —— 令牌校验只做「令牌有效 + 域名匹配 + 会话有效」的判定，
	//     从不回查账号的授权列表，所以不撤销的话管理员点了"保存"也拦不住任何人。
	//     这三个动作在管理员眼里是同一类止血操作，语义上必须一致。
	authChanged := strings.TrimSpace(req.AllowHostCodes) != strings.TrimSpace(bean.AllowHostCodes)
	if status != model.AccessAccountStatusEnable ||
		(!expire.IsZero() && expire.Before(time.Now())) || authChanged {
		WafAccessSessionServiceApp.RevokeByAccount(bean.Id, model.AccessRevokeByAccount)
	}
	return nil
}

func (receiver *WafAccessAccountService) ResetPwdApi(req request.WafAccessAccountResetPwdReq) error {
	bean, err := receiver.mustLoad(req.Id)
	if err != nil {
		return err
	}
	if ok, msg := utils.ValidatePasswordComplexity(req.Password, utils.BuildPolicyFromConfig()); !ok {
		return errors.New(msg)
	}
	hash, err := utils.BcryptHash(req.Password)
	if err != nil {
		return errors.New("密码加密失败")
	}
	now := customtype.JsonTime(time.Now())
	if err := global.GWAF_LOCAL_DB.Model(&model.AccessAccount{}).Where("id = ?", bean.Id).
		Updates(map[string]interface{}{
			"password": hash, "pwd_update_time": now, "update_time": now,
		}).Error; err != nil {
		return err
	}
	// 改密即踢下线：这是"密码疑似泄露"时管理员最直觉的止血动作，
	// 如果改完密码旧会话还能用，那这个动作就是无效的。
	WafAccessSessionServiceApp.RevokeByAccount(bean.Id, model.AccessRevokeByAccount)
	return nil
}

func (receiver *WafAccessAccountService) DelApi(id string) error {
	bean, err := receiver.mustLoad(id)
	if err != nil {
		return err
	}
	// 先踢会话再删账号：顺序反了会留下"账号没了但会话还在"的孤儿会话，
	// 而校验时是按 session 走的，那些会话会一直有效到自然过期。
	WafAccessSessionServiceApp.RevokeByAccount(bean.Id, model.AccessRevokeByAccount)
	return global.GWAF_LOCAL_DB.Where("id = ?", bean.Id).Delete(&model.AccessAccount{}).Error
}

func (receiver *WafAccessAccountService) GetDetailApi(id string) (model.AccessAccount, error) {
	bean, err := receiver.mustLoad(id)
	if err != nil {
		return model.AccessAccount{}, err
	}
	return *bean, nil
}

func (receiver *WafAccessAccountService) GetListApi(req request.WafAccessAccountSearchReq) ([]model.AccessAccount, int64, error) {
	var list []model.AccessAccount
	var total int64 = 0
	db := global.GWAF_LOCAL_DB.Model(&model.AccessAccount{}).
		Where("user_code = ? and tenant_id = ?", global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
	if strings.TrimSpace(req.AccountName) != "" {
		db = db.Where("account_name like ?", "%"+strings.TrimSpace(req.AccountName)+"%")
	}
	if req.Status != nil {
		db = db.Where("status = ?", *req.Status)
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

// RemoveHostCode 站点被删除后，把它从所有账号的授权列表里摘掉，返回受影响账号数。
//
// 这里有一个不能想当然的地方：AllowHostCodes 为空表示「全部站点」。
// 如果某个账号原本只被授权访问这一个站点，摘掉后列表就空了——直接落库等于把一个
// 受限账号一次性提权成"全站可访问"，方向完全反了。所以这种账号会被顺手禁用并踢下线，
// 由管理员重新指定站点后再启用。宁可多一次人工确认，也不能悄悄放权。
func (receiver *WafAccessAccountService) RemoveHostCode(hostCode string) int {
	code := strings.TrimSpace(hostCode)
	if code == "" {
		return 0
	}
	var list []model.AccessAccount
	global.GWAF_LOCAL_DB.Where("user_code = ? and tenant_id = ? and allow_host_codes <> ''",
		global.GWAF_USER_CODE, global.GWAF_TENANT_ID).Find(&list)

	affected := 0
	for _, acct := range list {
		kept := make([]string, 0, 4)
		hit := false
		for _, item := range splitLines(acct.AllowHostCodes) {
			if item == code {
				hit = true
				continue
			}
			kept = append(kept, item)
		}
		if !hit {
			continue
		}
		affected++
		now := customtype.JsonTime(time.Now())
		updates := map[string]interface{}{
			"allow_host_codes": strings.Join(kept, "\n"),
			"update_time":      now,
		}
		if len(kept) == 0 {
			updates["status"] = model.AccessAccountStatusDisable
			zlog.Warn("统一访问认证：账号唯一授权的站点已被删除，已自动禁用该账号",
				"account", acct.AccountName)
		}
		global.GWAF_LOCAL_DB.Model(&model.AccessAccount{}).Where("id = ?", acct.Id).Updates(updates)
		// 授权范围变了就得立刻断连：令牌校验只看「令牌有效 + 域名匹配 + 会话有效」，
		// 从不回查授权列表，不撤销的话已登录的人还能一直用到令牌自然过期。
		WafAccessSessionServiceApp.RevokeByAccount(acct.Id, model.AccessRevokeByAccount)
	}
	return affected
}

// ─────────────────────────── 管理端：OTP 绑定 ───────────────────────────

// OtpInitApi 生成一对新的 TOTP 密钥与二维码 URL。
// 此时还不落库——必须等用户用验证器扫码并输入一次正确的动态码（OtpBindApi）才算绑定成功，
// 否则会出现"库里记着已绑定、用户手机上却没有"的死锁状态。
func (receiver *WafAccessAccountService) OtpInitApi(id string) (secret string, url string, err error) {
	bean, err := receiver.mustLoad(id)
	if err != nil {
		return "", "", err
	}
	return utils.GenOtpSecret(bean.AccountName, "SamWaf-Access")
}

func (receiver *WafAccessAccountService) OtpBindApi(req request.WafAccessAccountOtpBindReq) error {
	bean, err := receiver.mustLoad(req.Id)
	if err != nil {
		return err
	}
	if !utils.ValidateOtpCode(strings.TrimSpace(req.Code), req.Secret) {
		return errors.New("动态验证码不正确，请确认时间同步后重试")
	}
	enc, err := encryptAccessSecret(req.Secret)
	if err != nil {
		return errors.New("密钥加密失败")
	}
	return global.GWAF_LOCAL_DB.Model(&model.AccessAccount{}).Where("id = ?", bean.Id).
		Updates(map[string]interface{}{
			"otp_secret": enc, "otp_bound": 1, "update_time": customtype.JsonTime(time.Now()),
		}).Error
}

func (receiver *WafAccessAccountService) OtpUnbindApi(id string) error {
	bean, err := receiver.mustLoad(id)
	if err != nil {
		return err
	}
	return global.GWAF_LOCAL_DB.Model(&model.AccessAccount{}).Where("id = ?", bean.Id).
		Updates(map[string]interface{}{
			"otp_secret": "", "otp_bound": 0, "update_time": customtype.JsonTime(time.Now()),
		}).Error
}

// ─────────────────────────── 内部 ───────────────────────────

// mustLoad 按主键加载并校验租户归属。
//
// 所有按 id 操作的接口都必须先走这里，再用查出来的记录做后续动作——
// 不能直接把前端传来的 id 拼进 UPDATE/DELETE 的 where 里，否则跨租户越权。
func (receiver *WafAccessAccountService) mustLoad(id string) (*model.AccessAccount, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("账号标识不能为空")
	}
	var bean model.AccessAccount
	if err := global.GWAF_LOCAL_DB.Where("id = ? and user_code = ? and tenant_id = ?",
		id, global.GWAF_USER_CODE, global.GWAF_TENANT_ID).First(&bean).Error; err != nil {
		return nil, errors.New("账号不存在")
	}
	return &bean, nil
}

func (receiver *WafAccessAccountService) checkNameFree(name, excludeId string) error {
	var cnt int64
	db := global.GWAF_LOCAL_DB.Model(&model.AccessAccount{}).
		Where("account_name = ? and user_code = ? and tenant_id = ?",
			name, global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
	if excludeId != "" {
		db = db.Where("id <> ?", excludeId)
	}
	db.Count(&cnt)
	if cnt > 0 {
		return errors.New("登录名已存在")
	}
	return nil
}

func normalizeStatus(s int) int {
	if s == model.AccessAccountStatusEnable {
		return model.AccessAccountStatusEnable
	}
	return model.AccessAccountStatusDisable
}

func normalizeOtpMode(m int) int {
	switch m {
	case model.AccessOtpForce, model.AccessOtpExempt:
		return m
	default:
		return model.AccessOtpInherit
	}
}

// parseAccessTime 解析前端传来的时间字符串，空串表示"不设置"（零值 = 永不过期）。
func parseAccessTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.ParseInLocation(accessTimeLayout, s, time.Local)
	if err != nil {
		return time.Time{}, errors.New("时间格式不正确，应为 yyyy-MM-dd HH:mm:ss")
	}
	return t, nil
}

// encryptAccessSecret / decryptAccessSecret 走与 CDN 凭证一致的 wafsec AES 通道
// （见 waf_cdn_ip_service.go 的 encCred/decCred）。TOTP 密钥、rq 签名密钥都用它，
// 保证这些东西在库里是密文，且 API 层永远不回显。
func encryptAccessSecret(plain string) (string, error) {
	if strings.TrimSpace(plain) == "" {
		return "", nil
	}
	c, err := wafsec.AesEncrypt([]byte(plain), global.GWAF_COMMUNICATION_KEY)
	if err != nil {
		zlog.Error("统一访问认证密钥加密失败", err.Error())
		return "", errors.New("加密失败")
	}
	return c, nil
}

func decryptAccessSecret(enc string) string {
	if strings.TrimSpace(enc) == "" {
		return ""
	}
	b, err := wafsec.AesDecrypt(enc, global.GWAF_COMMUNICATION_KEY)
	if err != nil {
		zlog.Error("统一访问认证密钥解密失败", err.Error())
		return ""
	}
	return string(b)
}
