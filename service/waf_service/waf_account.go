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
	"SamWaf/utils"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const pwdTimeLayout = "2006-01-02 15:04:05"

type WafAccountService struct{}

var WafAccountServiceApp = new(WafAccountService)

// pwdHash 计算口令哈希（bcrypt，内含随机 per-password 盐）
func (receiver *WafAccountService) pwdHash(plain string) (string, error) {
	return utils.BcryptHash(plain)
}

// VerifyPassword 校验明文口令是否匹配存储哈希：bcrypt 走 bcrypt；存量裸 MD5 走旧算法(透明升级期间兼容)。
func (receiver *WafAccountService) VerifyPassword(stored, plain string) bool {
	if utils.IsBcryptHash(stored) {
		return utils.BcryptVerify(stored, plain)
	}
	return stored != "" && stored == utils.Md5String(plain+global.GWAF_DEFAULT_ACCOUNT_SALT)
}

// UpgradePasswordHash 透明升级：命中旧 MD5 的账户，登录成功后用 bcrypt 重算落库
// （同一口令，不改 PwdUpdateTime、不记历史）。
func (receiver *WafAccountService) UpgradePasswordHash(loginAccount, plain string) {
	newHash, err := receiver.pwdHash(plain)
	if err != nil || newHash == "" {
		return
	}
	global.GWAF_LOCAL_DB.Model(model.Account{}).Where("login_account = ?", loginAccount).Update("LoginPassword", newHash)
}

// ValidateNewPassword 校验新口令：复杂度 + 历史防重用
func (receiver *WafAccountService) ValidateNewPassword(loginAccount, newPlain string) error {
	if ok, msg := utils.ValidatePasswordComplexity(newPlain, utils.BuildPolicyFromConfig()); !ok {
		return errors.New(msg)
	}
	historyCount := int(global.GCONFIG_PWD_HISTORY_COUNT)
	if historyCount > 0 {
		var histories []model.AccountPwdHistory
		global.GWAF_LOCAL_DB.Where("login_account = ?", loginAccount).Order("CREATE_TIME desc").Limit(historyCount).Find(&histories)
		for _, h := range histories {
			// bcrypt 非确定性，不能按等值比较；逐条校验明文是否命中历史哈希(同时兼容存量 MD5)
			if receiver.VerifyPassword(h.PasswordHash, newPlain) {
				return fmt.Errorf("新密码不能与最近 %d 次使用过的密码相同", historyCount)
			}
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

// InitDefaultAccount 系统引导创建默认管理员（全新安装）。
// 安全加固：不再使用固定默认口令 admin868，改为生成强随机初始口令，写入 data/ 供用户查看，并强制首登改密。
func (receiver *WafAccountService) InitDefaultAccount() error {
	plainPwd, err := utils.GenerateRandomPassword(16)
	if err != nil || plainPwd == "" {
		// 极端兜底：随机生成失败时退回旧默认口令，但仍强制改密
		plainPwd = global.GWAF_DEFAULT_ACCOUNT_PWD
	}
	// 强制首登改密（needChange=true），不做复杂度校验避免严格策略下引导被锁死
	if e := receiver.createAccount(global.GWAF_DEFAULT_ACCOUNT, enums.ROLE_SUPER_ADMIN, plainPwd, 0, "系统初始化生成", true); e != nil {
		return e
	}
	receiver.writeInitialPasswordFile(global.GWAF_DEFAULT_ACCOUNT, plainPwd)
	return nil
}

// writeInitialPasswordFile 全新安装时把随机初始口令写入 data/ 供用户查看，并打印日志提示。
func (receiver *WafAccountService) writeInitialPasswordFile(account, plainPwd string) {
	dir := "data"
	if err := os.MkdirAll(dir, 0700); err != nil {
		zlog.Error("创建 data 目录失败", err)
		return
	}
	fp := filepath.Join(dir, "initial_password.txt")
	content := fmt.Sprintf("SamWaf 初始管理员账号: %s\n初始随机口令: %s\n生成时间: %s\n请立即登录并修改密码，登录后本文件可删除。\n",
		account, plainPwd, time.Now().Format(pwdTimeLayout))
	if err := os.WriteFile(fp, []byte(content), 0600); err != nil {
		zlog.Error("写入初始口令文件失败", err)
		return
	}
	zlog.Info(fmt.Sprintf("首次安装已生成随机管理员初始口令，请查看文件: %s 并在登录后立即修改", fp))
}

// createAccount 内部统一建账逻辑
func (receiver *WafAccountService) createAccount(loginAccount, role, plainPwd string, status int, remarks string, needChange bool) error {
	hash, err := receiver.pwdHash(plainPwd)
	if err != nil {
		return err
	}
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
	if !receiver.VerifyPassword(bean.LoginPassword, oldPlain) {
		return errors.New("旧密码不正确")
	}
	if receiver.VerifyPassword(bean.LoginPassword, newPlain) {
		return errors.New("新旧密码相同")
	}
	if err = receiver.ValidateNewPassword(loginAccount, newPlain); err != nil {
		return err
	}
	newHash, err := receiver.pwdHash(newPlain)
	if err != nil {
		return err
	}
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
	if !receiver.VerifyPassword(superAccount.LoginPassword, req.LoginSuperPassword) {
		return errors.New("超级管理员密码不正确")
	}

	var bean model.Account
	global.GWAF_LOCAL_DB.Where("login_account = ?", req.LoginAccount).Find(&bean)
	if bean.Id == "" {
		return errors.New("帐号信息不存在")
	}

	if receiver.VerifyPassword(bean.LoginPassword, req.LoginNewPassword) {
		return errors.New("新旧密码相同")
	}

	// 复杂度 + 历史防重用校验
	if err := receiver.ValidateNewPassword(req.LoginAccount, req.LoginNewPassword); err != nil {
		return err
	}

	newHash, err := receiver.pwdHash(req.LoginNewPassword)
	if err != nil {
		return err
	}
	beanMap := map[string]interface{}{
		"LoginPassword":      newHash,
		"NeedChangePassword": 1, // 管理员重置后，目标账号下次登录需强制改密
		"PwdUpdateTime":      time.Now().Format(pwdTimeLayout),
		"UPDATE_TIME":        customtype.JsonTime(time.Now()),
	}
	err = global.GWAF_LOCAL_DB.Model(model.Account{}).Where("id = ?", bean.Id).Updates(beanMap).Error
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
