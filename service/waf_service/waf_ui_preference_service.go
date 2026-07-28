package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"encoding/json"
	"errors"
	"time"
)

type WafUIPreferenceService struct{}

var WafUIPreferenceServiceApp = new(WafUIPreferenceService)

// 允许保存的偏好名白名单：防止已登录账号任意造名无限建行
var allowedPrefNames = map[string]bool{
	"visit_log_columns": true, //访问日志列配置
}

// 单条偏好内容上限 32KB
const maxPrefJsonLen = 32 * 1024

// checkPrefName 校验偏好名是否在白名单内
func (receiver *WafUIPreferenceService) checkPrefName(prefName string) error {
	if !allowedPrefNames[prefName] {
		return errors.New("不支持的偏好名称")
	}
	return nil
}

// GetApi 获取指定账号的偏好，未存过时返回零值（Id 为空），由调用方按默认值处理
func (receiver *WafUIPreferenceService) GetApi(loginAccount string, prefName string) (model.UIPreference, error) {
	var bean model.UIPreference
	if err := receiver.checkPrefName(prefName); err != nil {
		return bean, err
	}
	global.GWAF_LOCAL_DB.Where("user_code=? and tenant_id=? and login_account=? and pref_name=?",
		global.GWAF_USER_CODE, global.GWAF_TENANT_ID, loginAccount, prefName).Find(&bean)
	return bean, nil
}

// SaveApi 保存（不存在则新增，存在则更新）指定账号的偏好
func (receiver *WafUIPreferenceService) SaveApi(loginAccount string, req request.WafUIPreferenceSaveReq) error {
	if err := receiver.checkPrefName(req.PrefName); err != nil {
		return err
	}
	if len(req.PrefJson) > maxPrefJsonLen {
		return errors.New("偏好内容超出长度限制")
	}
	// 必须是合法 JSON，避免存入垃圾数据
	var probe interface{}
	if err := json.Unmarshal([]byte(req.PrefJson), &probe); err != nil {
		return errors.New("偏好内容不是合法的JSON")
	}

	// 先查后写不是原子的：同一账号多标签页首次进页面会并发写，
	// 新增撞唯一索引 uni_ui_pref 时重查一次改走更新，避免偶发"保存失败"
	if err := receiver.upsert(loginAccount, req); err != nil {
		return receiver.updateExisting(loginAccount, req)
	}
	return nil
}

func (receiver *WafUIPreferenceService) upsert(loginAccount string, req request.WafUIPreferenceSaveReq) error {
	var bean model.UIPreference
	global.GWAF_LOCAL_DB.Where("user_code=? and tenant_id=? and login_account=? and pref_name=?",
		global.GWAF_USER_CODE, global.GWAF_TENANT_ID, loginAccount, req.PrefName).Find(&bean)

	if bean.Id == "" {
		var newBean = &model.UIPreference{
			BaseOrm: baseorm.BaseOrm{
				Id:          uuid.GenUUID(),
				USER_CODE:   global.GWAF_USER_CODE,
				Tenant_ID:   global.GWAF_TENANT_ID,
				CREATE_TIME: customtype.JsonTime(time.Now()),
				UPDATE_TIME: customtype.JsonTime(time.Now()),
			},
			LoginAccount: loginAccount,
			PrefName:     req.PrefName,
			PrefJson:     req.PrefJson,
		}
		return global.GWAF_LOCAL_DB.Create(newBean).Error
	}

	return global.GWAF_LOCAL_DB.Model(model.UIPreference{}).Where("id = ?", bean.Id).Updates(map[string]interface{}{
		"PrefJson":    req.PrefJson,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}).Error
}

// updateExisting 按唯一键直接更新（新增撞唯一索引后的兜底；若索引缺失导致存在多行，这里会全部更新为同一内容，最终一致）
func (receiver *WafUIPreferenceService) updateExisting(loginAccount string, req request.WafUIPreferenceSaveReq) error {
	return global.GWAF_LOCAL_DB.Model(model.UIPreference{}).
		Where("user_code=? and tenant_id=? and login_account=? and pref_name=?",
			global.GWAF_USER_CODE, global.GWAF_TENANT_ID, loginAccount, req.PrefName).
		Updates(map[string]interface{}{
			"PrefJson":    req.PrefJson,
			"UPDATE_TIME": customtype.JsonTime(time.Now()),
		}).Error
}
