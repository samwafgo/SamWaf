package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/utils"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	ErrSessionInvalid = errors.New("管理会话已失效")
	ErrSessionBackend = errors.New("会话存储暂时不可用")
	accountSessionMu  sync.Mutex
)

func accountSessionScope(db *gorm.DB) *gorm.DB {
	return db.Where("tenant_id = ? AND user_code = ?", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
}

func sessionDBError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrSessionBackend, err)
}

func (receiver *WafAccountService) GetLoginAccount(login string) (model.Account, error) {
	var account model.Account
	err := accountSessionScope(global.GWAF_LOCAL_DB).Where("login_account = ?", login).First(&account).Error
	return account, err
}

// ValidateSession 在一次查询中核对持久会话与当前账号。
func (receiver *WafTokenInfoService) ValidateSession(cached model.TokenInfo, accessToken string) (model.Account, error) {
	var account model.Account
	if cached.Id == "" || cached.LoginAccount == "" || cached.AccessToken != accessToken || cached.Tenant_ID != global.GWAF_TENANT_ID || cached.USER_CODE != global.GWAF_USER_CODE {
		return account, ErrSessionInvalid
	}
	var session model.TokenInfo
	err := accountSessionScope(global.GWAF_LOCAL_DB).Where("login_account = ? AND id = ?", cached.LoginAccount, cached.Id).First(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return account, ErrSessionInvalid
	}
	if err != nil {
		return account, sessionDBError(err)
	}
	if session.AccessToken == "" || subtle.ConstantTimeCompare([]byte(session.AccessToken), []byte(accessToken)) != 1 {
		return account, ErrSessionInvalid
	}
	err = accountSessionScope(global.GWAF_LOCAL_DB).Where("login_account = ?", cached.LoginAccount).First(&account).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return account, ErrSessionInvalid
	}
	if err != nil {
		return account, sessionDBError(err)
	}
	// 角色按归一值判断：仅语义等价的写法变化不改变既有权限，保留会话。
	if enums.NormalizeRole(account.Role) != enums.NormalizeRole(cached.Role) {
		return account, ErrSessionInvalid
	}
	return account, nil
}

// IssueSession 原子替换同类型会话，并核对登录校验时的账号快照。
func (receiver *WafTokenInfoService) IssueSession(expected model.Account, accessToken, ip, fingerprint, loginType, plainPassword string) (*model.TokenInfo, error) {
	// 存量非 bcrypt 口令的透明升级哈希在持锁前算好，避免长耗时哈希放大全局串行窗口。
	var upgradedHash string
	if !utils.IsBcryptHash(expected.LoginPassword) {
		hash, err := utils.BcryptHash(plainPassword)
		if err != nil {
			return nil, err
		}
		upgradedHash = hash
	}
	accountSessionMu.Lock()
	defer accountSessionMu.Unlock()
	var token *model.TokenInfo
	err := accountSessionTransaction(func(tx *gorm.DB) error {
		var current model.Account
		err := accountSessionScope(tx).Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", expected.Id).First(&current).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrSessionInvalid
		}
		if err != nil {
			return sessionDBError(err)
		}
		if current.LoginAccount != expected.LoginAccount || current.LoginPassword != expected.LoginPassword || current.Role != expected.Role || current.Status != expected.Status || current.NeedChangePassword != expected.NeedChangePassword || current.PwdUpdateTime != expected.PwdUpdateTime {
			return ErrSessionInvalid
		}
		if upgradedHash != "" {
			if err = accountSessionScope(tx.Model(&model.Account{})).Where("id = ?", current.Id).Update("login_password", upgradedHash).Error; err != nil {
				return sessionDBError(err)
			}
		}
		if err = accountSessionScope(tx).Where("login_account = ? AND login_type = ?", current.LoginAccount, loginType).Delete(&model.TokenInfo{}).Error; err != nil {
			return sessionDBError(err)
		}
		now := customtype.JsonTime(time.Now())
		token = &model.TokenInfo{BaseOrm: baseorm.BaseOrm{Id: uuid.GenUUID(), Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE, CREATE_TIME: now, UPDATE_TIME: now}, LoginAccount: current.LoginAccount, AccessToken: accessToken, LoginIp: ip, DeviceFingerprint: fingerprint, LoginType: loginType, Role: enums.NormalizeRole(current.Role)}
		return sessionDBError(tx.Create(token).Error)
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func accountSessionTransaction(fn func(*gorm.DB) error) error {
	tx := global.GWAF_LOCAL_DB.Begin()
	if tx.Error != nil {
		return sessionDBError(tx.Error)
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return sessionDBError(tx.Commit().Error)
}

func revokeAccountSessions(tx *gorm.DB, login string) error {
	return sessionDBError(accountSessionScope(tx).Where("login_account = ?", login).Delete(&model.TokenInfo{}).Error)
}
