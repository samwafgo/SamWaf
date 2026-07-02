package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/utils"
	"errors"
	"fmt"
	"time"
)

const pwdTimeLayout = "2006-01-02 15:04:05"

type WafAccountService struct{}

var WafAccountServiceApp = new(WafAccountService)

// pwdHash 计算口令指纹(md5+盐)
func (receiver *WafAccountService) pwdHash(plain string) string {
	return utils.Md5String(plain + global.GWAF_DEFAULT_ACCOUNT_SALT)
}

// ValidateNewPassword 校验新口令：复杂度 + 历史防重用
func (receiver *WafAccountService) ValidateNewPassword(loginAccount, newPlain string) error {
	if ok, msg := utils.ValidatePasswordComplexity(newPlain, utils.BuildPolicyFromConfig()); !ok {
		return errors.New(msg)
	}
	historyCount := int(global.GCONFIG_PWD_HISTORY_COUNT)
	if historyCount > 0 {
		newHash := receiver.pwdHash(newPlain)
		var histories []model.AccountPwdHistory
		global.GWAF_LOCAL_DB.Where("login_account = ?", loginAccount).Order("CREATE_TIME desc").Limit(historyCount).Find(&histories)
		hashes := make([]string, 0, len(histories))
		for _, h := range histories {
			hashes = append(hashes, h.PasswordHash)
		}
		if utils.IsPasswordReused(newHash, hashes) {
			return fmt.Errorf("新密码不能与最近 %d 次使用过的密码相同", historyCount)
		}
	}
	return nil
}

// recordPwdHistory 记录口令指纹并裁剪到最近 N 条
func (receiver *WafAccountService) recordPwdHistory(loginAccount, hash string) {
	historyCount := int(global.GCONFIG_PWD_HISTORY_COUNT)
	if historyCount <= 0 {
		return
	}
	global.GWAF_LOCAL_DB.Create(&model.AccountPwdHistory{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		LoginAccount: loginAccount,
		PasswordHash: hash,
	})
	var histories []model.AccountPwdHistory
	global.GWAF_LOCAL_DB.Where("login_account = ?", loginAccount).Order("CREATE_TIME desc").Find(&histories)
	if len(histories) > historyCount {
		for _, h := range histories[historyCount:] {
			global.GWAF_LOCAL_DB.Where("id = ?", h.Id).Delete(model.AccountPwdHistory{})
		}
	}
}

// AddApi 管理员新建账号：强制角色合法 + 口令复杂度校验，新建账号默认需首登改密
func (receiver *WafAccountService) AddApi(req request.WafAccountAddReq) error {
	if !enums.IsValidRole(req.Role) {
		return errors.New("请指定合法的账号角色")
	}
	if err := receiver.ValidateNewPassword(req.LoginAccount, req.LoginPassword); err != nil {
		return err
	}
	return receiver.createAccount(req.LoginAccount, req.Role, req.LoginPassword, req.Status, req.Remarks, global.GCONFIG_PWD_FORCE_CHANGE_DEFAULT == 1)
}

// InitDefaultAccount 系统引导创建默认管理员（不做复杂度校验，避免严格策略下引导被锁死）
func (receiver *WafAccountService) InitDefaultAccount() error {
	return receiver.createAccount(global.GWAF_DEFAULT_ACCOUNT, enums.ROLE_SUPER_ADMIN, global.GWAF_DEFAULT_ACCOUNT_PWD, 0, "密码生成", global.GCONFIG_PWD_FORCE_CHANGE_DEFAULT == 1)
}

// createAccount 内部统一建账逻辑
func (receiver *WafAccountService) createAccount(loginAccount, role, plainPwd string, status int, remarks string, needChange bool) error {
	hash := receiver.pwdHash(plainPwd)
	needChangeFlag := 0
	if needChange {
		needChangeFlag = 1
	}
	var bean = &model.Account{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		LoginAccount:       loginAccount,
		Role:               role,
		LoginPassword:      hash,
		Status:             status,
		NeedChangePassword: needChangeFlag,
		PwdUpdateTime:      time.Now().Format(pwdTimeLayout),
		Remarks:            remarks,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	receiver.recordPwdHistory(loginAccount, hash)
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
	// 角色留空则不修改；非空必须合法
	if req.Role != "" {
		if !enums.IsValidRole(req.Role) {
			return errors.New("请指定合法的账号角色")
		}
		beanMap["Role"] = req.Role
	}
	err := global.GWAF_LOCAL_DB.Model(model.Account{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}

// ChangeMyPasswordApi 当前登录账号自助改密：校验旧密码、复杂度、历史防重用，成功后清除强制改密标记
func (receiver *WafAccountService) ChangeMyPasswordApi(loginAccount, oldPlain, newPlain string) error {
	var bean model.Account
	err := global.GWAF_LOCAL_DB.Where("login_account = ?", loginAccount).First(&bean).Error
	if err != nil {
		return errors.New("帐号信息不存在")
	}
	if bean.LoginPassword != receiver.pwdHash(oldPlain) {
		return errors.New("旧密码不正确")
	}
	if bean.LoginPassword == receiver.pwdHash(newPlain) {
		return errors.New("新旧密码相同")
	}
	if err = receiver.ValidateNewPassword(loginAccount, newPlain); err != nil {
		return err
	}
	newHash := receiver.pwdHash(newPlain)
	beanMap := map[string]interface{}{
		"LoginPassword":      newHash,
		"NeedChangePassword": 0,
		"PwdUpdateTime":      time.Now().Format(pwdTimeLayout),
		"UPDATE_TIME":        customtype.JsonTime(time.Now()),
	}
	if err = global.GWAF_LOCAL_DB.Model(model.Account{}).Where("id = ?", bean.Id).Updates(beanMap).Error; err != nil {
		return err
	}
	receiver.recordPwdHistory(loginAccount, newHash)
	return nil
}
func (receiver *WafAccountService) ResetPwdApi(req request.WafAccountResetPwdReq) error {

	var superAccount model.Account
	global.GWAF_LOCAL_DB.Where("`role` = ?", enums.ROLE_SUPER_ADMIN).First(&superAccount)
	if superAccount.LoginPassword != receiver.pwdHash(req.LoginSuperPassword) {
		return errors.New("超级管理员密码不正确")
	}

	var bean model.Account
	global.GWAF_LOCAL_DB.Where("login_account = ?", req.LoginAccount).Find(&bean)
	if bean.Id == "" {
		return errors.New("帐号信息不存在")
	}

	if bean.LoginPassword == receiver.pwdHash(req.LoginNewPassword) {
		return errors.New("新旧密码相同")
	}

	// 复杂度 + 历史防重用校验
	if err := receiver.ValidateNewPassword(req.LoginAccount, req.LoginNewPassword); err != nil {
		return err
	}

	newHash := receiver.pwdHash(req.LoginNewPassword)
	beanMap := map[string]interface{}{
		"LoginPassword":      newHash,
		"NeedChangePassword": 1, // 管理员重置后，目标账号下次登录需强制改密
		"PwdUpdateTime":      time.Now().Format(pwdTimeLayout),
		"UPDATE_TIME":        customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.Account{}).Where("id = ?", bean.Id).Updates(beanMap).Error
	if err != nil {
		return err
	}
	receiver.recordPwdHistory(req.LoginAccount, newHash)
	return nil
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
	var list []model.Account
	var total int64 = 0

	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""
	if len(req.LoginAccount) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " login_account=? "
	}
	//where字段赋值
	if len(req.LoginAccount) > 0 {
		whereValues = append(whereValues, req.LoginAccount)
	}

	global.GWAF_LOCAL_DB.Model(&model.Account{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.Account{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafAccountService) DelApi(req request.WafAccountDelReq) error {
	var bean model.Account
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	} else {
		var total int64
		global.GWAF_LOCAL_DB.Model(&model.Account{}).Count(&total)
		if total <= 1 {
			return errors.New("系统中只剩一个账号，不能删除")
		}
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
