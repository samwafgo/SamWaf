package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"errors"
	uuid "github.com/satori/go.uuid"
	"time"
)

type WafTokenInfoService struct{}

var WafTokenInfoServiceApp = new(WafTokenInfoService)

func (receiver *WafTokenInfoService) AddApi(loginAccount string, AccessToken string, LoginIp string) *model.TokenInfo {

	var bean = &model.TokenInfo{
		Id:             uuid.NewV4().String(),
		UserCode:       global.GWAF_USER_CODE,
		TenantId:       global.GWAF_TENANT_ID,
		LoginAccount:   loginAccount,
		AccessToken:    AccessToken,
		LoginIp:        LoginIp,
		CreateTime:     time.Now(),
		LastUpdateTime: time.Now(),
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return bean
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
		"login_ip":         LoginIp,
		"last_update_time": time.Now(),
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
