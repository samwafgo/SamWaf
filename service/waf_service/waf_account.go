package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/utils"
	"errors"
	uuid "github.com/satori/go.uuid"
	"gorm.io/gorm"
	"time"
)

type WafAccountService struct{}

var WafAccountServiceApp = new(WafAccountService)

func (receiver *WafAccountService) AddApi(req request.WafAccountAddReq) error {
	var bean = &model.Account{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		LoginAccount:  req.LoginAccount,
		Role:          req.Role,
		LoginPassword: utils.Md5String(req.LoginPassword + global.GWAF_DEFAULT_ACCOUNT_SALT),
		Status:        req.Status,
		Remarks:       req.Remarks,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafAccountService) CheckIsExistApi(req request.WafAccountAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.Account{}, "login_account = ? ", req.LoginAccount).Error
}
func (receiver *WafAccountService) ModifyApi(req request.WafAccountEditReq) error {
	var bean model.Account
	global.GWAF_LOCAL_DB.Where("login_account = ?", req.LoginAccount).Find(&bean)
	if bean.Id != "" && bean.LoginAccount != req.LoginAccount {
		return errors.New("当前数据已经存在")
	}
	beanMap := map[string]interface{}{
		"LoginAccount": req.LoginAccount,
		"Status":       req.Status,
		"Remarks":      req.Remarks,
		"UPDATE_TIME":  customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.Account{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}
func (receiver *WafAccountService) ResetPwdApi(req request.WafAccountResetPwdReq) error {

	var superAccount model.Account
	global.GWAF_LOCAL_DB.Where("login_account = ?", global.GWAF_DEFAULT_ACCOUNT).Find(&superAccount)
	if superAccount.LoginPassword != utils.Md5String(req.LoginSuperPassword+global.GWAF_DEFAULT_ACCOUNT_SALT) {
		return errors.New("超级管理员密码不正确")
	}

	var bean model.Account
	err := global.GWAF_LOCAL_DB.Where("login_account = ?", req.LoginAccount).Find(&bean).Error
	if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
		return errors.New("帐号信息不存在")
	}
	beanMap := map[string]interface{}{
		"LoginAccount":  req.LoginAccount,
		"LoginPassword": utils.Md5String(req.LoginNewPassword + global.GWAF_DEFAULT_ACCOUNT_SALT),
		"UPDATE_TIME":   customtype.JsonTime(time.Now()),
	}
	err = global.GWAF_LOCAL_DB.Model(model.Account{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}
func (receiver *WafAccountService) GetDetailApi(req request.WafAccountDetailReq) model.Account {
	var bean model.Account
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafAccountService) GetInfoByLoginApi(req request.WafLoginReq) model.Account {
	var bean model.Account
	global.GWAF_LOCAL_DB.Where("login_account=? ", req.LoginAccount).Find(&bean)
	return bean
}

/*
*
通过登录account获取账号信息
*/
func (receiver *WafAccountService) GetInfoByLoginAccount(loginAccount string) model.Account {
	var bean model.Account
	global.GWAF_LOCAL_DB.Where("login_account=? ", loginAccount).Find(&bean)
	return bean
}

/*
*
 */
func (receiver *WafAccountService) IsExistDefaultAccount() bool {
	var total int64 = 0

	err := global.GWAF_LOCAL_DB.Model(&model.Account{}).Where("login_account=? and login_password =?", global.GWAF_DEFAULT_ACCOUNT, utils.Md5String(global.GWAF_DEFAULT_ACCOUNT_PWD+global.GWAF_DEFAULT_ACCOUNT_SALT)).Count(&total).Error
	if err == nil {
		if total > 0 {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}
func (receiver *WafAccountService) GetDetailByIdApi(id string) model.Account {
	var bean model.Account
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafAccountService) GetListApi(req request.WafAccountSearchReq) ([]model.Account, int64, error) {
	var bean []model.Account
	var total int64 = 0
	global.GWAF_LOCAL_DB.Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&bean)
	global.GWAF_LOCAL_DB.Model(&model.Account{}).Count(&total)
	return bean, total, nil
}
func (receiver *WafAccountService) DelApi(req request.WafAccountDelReq) error {
	var bean model.Account
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.Account{}).Error
	return err
}

// 获取系统所有账号数量
func (receiver *WafAccountService) GetAccountCountApi() (int64, error) {
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.Account{}).Count(&total)
	return total, nil
}
