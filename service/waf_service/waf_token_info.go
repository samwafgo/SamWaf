package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"errors"
	"time"
)

type WafTokenInfoService struct{}

var WafTokenInfoServiceApp = new(WafTokenInfoService)

func (receiver *WafTokenInfoService) AddApi(loginAccount string, AccessToken string, LoginIp string) *model.TokenInfo {

	var bean = &model.TokenInfo{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		LoginAccount: loginAccount,
		AccessToken:  AccessToken,
		LoginIp:      LoginIp,
		LoginType:    "web", // 默认为web类型
	}
	if err := global.GWAF_LOCAL_DB.Create(bean).Error; err != nil {
		return nil
	}
	// 直接返回刚插入的记录，不再重查（重查可能命中同账号的其它旧行，见 AddApiWithFingerprintAndType 注释）
	return bean
}

// AddApiWithFingerprint 添加带指纹的token信息
func (receiver *WafTokenInfoService) AddApiWithFingerprint(loginAccount string, AccessToken string, LoginIp string, deviceFingerprint string) *model.TokenInfo {

	var bean = &model.TokenInfo{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		LoginAccount:      loginAccount,
		AccessToken:       AccessToken,
		LoginIp:           LoginIp,
		DeviceFingerprint: deviceFingerprint,
		LoginType:         "web", // 默认为web类型
	}
	if err := global.GWAF_LOCAL_DB.Create(bean).Error; err != nil {
		return nil
	}
	// 直接返回刚插入的记录，不再重查（重查可能命中同账号的其它旧行，见 AddApiWithFingerprintAndType 注释）
	return bean
}

// AddApiWithFingerprintAndType 添加带指纹和登录类型的token信息。
//
// 这里刻意**返回刚插入的这条记录本身**，而不是插入后再查一次库：
// 旧写法用 GetInfoByLoginAccountAndType 重查（Limit(1) 且无 ORDER BY），
// 只要库里还残留同账号同类型的行，返回的就可能是另一条旧记录；
// 而登录接口是"用本地生成的令牌写缓存、用重查结果下发给前端"，两者一旦不是同一个令牌，
// 前端就会拿着一个缓存里根本不存在的令牌，之后每个请求都被判「令牌过期」→ 跳登录 → 死循环，
// 且服务端一行日志都没有（issue #938）。
// 同时 Create 的错误必须返回给调用方：插入失败时旧写法返回零值结构体，
// 登录接口照样回「登录成功」但 access_token 是空串，同样是无日志的死循环。
func (receiver *WafTokenInfoService) AddApiWithFingerprintAndType(loginAccount string, AccessToken string, LoginIp string, deviceFingerprint string, loginType string, role string) (*model.TokenInfo, error) {

	var bean = &model.TokenInfo{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		LoginAccount:      loginAccount,
		AccessToken:       AccessToken,
		LoginIp:           LoginIp,
		DeviceFingerprint: deviceFingerprint,
		LoginType:         loginType,
		Role:              enums.NormalizeRole(role),
	}
	if err := global.GWAF_LOCAL_DB.Create(bean).Error; err != nil {
		return nil, err
	}
	return bean, nil
}

func (receiver *WafTokenInfoService) CheckIsExistByLoginAccountApi(loginAccount string) error {
	return global.GWAF_LOCAL_DB.First(&model.TokenInfo{}, "login_account = ? ", loginAccount).Error
}
func (receiver *WafTokenInfoService) ModifyApi(loginAccount string, AccessToken string, LoginIp string) error {
	var bean model.Account
	global.GWAF_LOCAL_DB.Where("login_account = ? ,access_token = ? ", loginAccount, AccessToken).Find(&bean)
	if bean.Id == "" {
		return errors.New("当前数据不存在")
	}
	beanMap := map[string]interface{}{
		"login_ip":    LoginIp,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.Account{}).Where("login_account = ? ,access_token = ? ", loginAccount, AccessToken).Updates(beanMap).Error

	return err
}

/*
*
通过登录account获取账号信息
*/
func (receiver *WafTokenInfoService) GetInfoByLoginAccount(loginAccount string) model.TokenInfo {
	var bean model.TokenInfo
	global.GWAF_LOCAL_DB.Where("login_account=? ", loginAccount).Limit(1).Find(&bean)
	return bean
}

// GetAllTokenInfoByLoginAccount 通过登录account获取账号信息
func (receiver *WafTokenInfoService) GetAllTokenInfoByLoginAccount(loginAccount string) []model.TokenInfo {
	var bean []model.TokenInfo
	global.GWAF_LOCAL_DB.Where("login_account=? ", loginAccount).Find(&bean)
	return bean
}

// GetInfoByLoginAccountAndType 通过登录account和类型获取账号信息
func (receiver *WafTokenInfoService) GetInfoByLoginAccountAndType(loginAccount string, loginType string) model.TokenInfo {
	var bean model.TokenInfo
	global.GWAF_LOCAL_DB.Where("login_account=? AND login_type=? ", loginAccount, loginType).Limit(1).Find(&bean)
	return bean
}

// GetAllTokenInfoByLoginAccountAndType 通过登录account和类型获取所有账号信息
func (receiver *WafTokenInfoService) GetAllTokenInfoByLoginAccountAndType(loginAccount string, loginType string) []model.TokenInfo {
	var bean []model.TokenInfo
	global.GWAF_LOCAL_DB.Where("login_account=? AND login_type=? ", loginAccount, loginType).Find(&bean)
	return bean
}

/*
*
获取一个可用的token TODO 将来应该是一个
*/
func (receiver *WafTokenInfoService) GetOneAvailableInfo() model.TokenInfo {
	var bean model.TokenInfo
	global.GWAF_LOCAL_DB.Limit(1).Find(&bean)
	return bean
}

/*
*
通过登录access_token获取账号信息
*/
func (receiver *WafTokenInfoService) GetInfoByAccessToken(accessToken string) model.TokenInfo {
	var bean model.TokenInfo
	global.GWAF_LOCAL_DB.Where("access_token=? ", accessToken).Find(&bean)
	return bean
}

/*
*
删除状态
*/
func (receiver *WafTokenInfoService) DelApi(loginAccount string, AccessToken string) error {
	var bean model.TokenInfo
	err := global.GWAF_LOCAL_DB.Where("login_account = ? and access_token = ? ", loginAccount, AccessToken).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("login_account = ? and access_token = ? ", loginAccount, AccessToken).Delete(model.TokenInfo{}).Error
	return err
}

/*
*
通过账号删除所有关联状态
*/
func (receiver *WafTokenInfoService) DelApiByAccount(loginAccount string) error {
	var bean model.TokenInfo
	err := global.GWAF_LOCAL_DB.Where("login_account = ?", loginAccount).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("login_account = ?", loginAccount).Delete(model.TokenInfo{}).Error
	return err
}

/*
*
通过账号和登录类型删除关联状态
*/
func (receiver *WafTokenInfoService) DelApiByAccountAndType(loginAccount string, loginType string) error {
	var bean model.TokenInfo
	err := global.GWAF_LOCAL_DB.Where("login_account = ? AND login_type = ?", loginAccount, loginType).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("login_account = ? AND login_type = ?", loginAccount, loginType).Delete(model.TokenInfo{}).Error
	return err
}

/*
* 检测所有的token是否过期，没有过期就重新加载到cache
 */
func (receiver *WafTokenInfoService) ReloadAllValidTokensToCache() error {
	var tokens []model.TokenInfo
	// 获取所有token信息
	err := global.GWAF_LOCAL_DB.Find(&tokens).Error
	if err != nil {
		return err
	}

	// 当前时间
	now := time.Now()

	// 遍历所有token
	for _, token := range tokens {
		// 检查token是否过期
		// 假设token的过期时间存储在UPDATE_TIME字段中，并且有一个固定的过期时间
		expireTime := time.Time(token.UPDATE_TIME).Add(time.Duration(global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES) * time.Minute)

		// 如果token没有过期，则重新加载到缓存中
		if expireTime.After(now) {
			// 将token信息存入缓存
			// 用 SetWithTTlRenewTime：管理端热重启(WatchRestartSignal)会在进程存活的情况下再次走到这里，
			// 此时缓存里的 key 还在，SetWithTTl 会沿用原 createTime，等于把已经续过期的令牌拉回
			// "登录时刻 + TTL"，把在线会话凭空缩短甚至当场判死。
			global.GCACHE_WAFCACHE.SetWithTTlRenewTime(
				enums.CACHE_TOKEN+token.AccessToken,
				token,
				time.Duration(global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES)*time.Minute,
			)
		}
	}

	return nil
}

// 根据数据库中的特定token信息重新加载到缓存
func (receiver *WafTokenInfoService) ReloadSpecificTokenToCache(tokenId string) error {
	var token model.TokenInfo
	// 根据ID获取token信息
	err := global.GWAF_LOCAL_DB.Where("id = ?", tokenId).First(&token).Error
	if err != nil {
		return err
	}

	// 当前时间
	now := time.Now()

	// 检查token是否过期
	expireTime := time.Time(token.UPDATE_TIME).Add(time.Duration(global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES) * time.Minute)

	// 如果token没有过期，则重新加载到缓存中
	if expireTime.After(now) {
		// 将token信息存入缓存（同上，必须 RenewTime，避免沿用原 createTime 把会话缩短）
		global.GCACHE_WAFCACHE.SetWithTTlRenewTime(
			enums.CACHE_TOKEN+token.AccessToken,
			token,
			time.Duration(global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES)*time.Minute,
		)
		return nil
	}

	return errors.New("token已过期")
}
