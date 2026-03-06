package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

type WafOPlatformKeyService struct{}

var WafOPlatformKeyServiceApp = new(WafOPlatformKeyService)

// genRandomHex 生成随机十六进制字符串
func genRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// maskApiKey 对 API Key 做脱敏，保留前6位和后4位，中间替换为 ****
func maskApiKey(key string) string {
	if len(key) <= 10 {
		return key
	}
	return key[:6] + "****" + key[len(key)-4:]
}

func (receiver *WafOPlatformKeyService) AddApi(req request.WafOPlatformKeyAddReq) (string, string, error) {
	apiKey := "sk-" + genRandomHex(16)
	id := uuid.GenUUID()
	var bean = &model.OPlatformKey{
		BaseOrm: baseorm.BaseOrm{
			Id:          id,
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		KeyName:     req.KeyName,
		ApiKey:      apiKey,
		Status:      1,
		Remark:      req.Remark,
		RateLimit:   req.RateLimit,
		IPWhitelist: req.IPWhitelist,
		ExpireTime:  req.ExpireTime,
		CallCount:   0,
	}
	err := global.GWAF_LOCAL_DB.Create(bean).Error
	return id, apiKey, err
}

func (receiver *WafOPlatformKeyService) ModifyApi(req request.WafOPlatformKeyEditReq) error {
	editMap := map[string]interface{}{
		"KeyName":     req.KeyName,
		"Status":      req.Status,
		"Remark":      req.Remark,
		"RateLimit":   req.RateLimit,
		"IPWhitelist": req.IPWhitelist,
		"ExpireTime":  req.ExpireTime,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	return global.GWAF_LOCAL_DB.Model(model.OPlatformKey{}).Where("id = ?", req.Id).Updates(editMap).Error
}

func (receiver *WafOPlatformKeyService) DelApi(req request.WafOPlatformKeyDelReq) error {
	var bean model.OPlatformKey
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	return global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.OPlatformKey{}).Error
}

func (receiver *WafOPlatformKeyService) GetDetailApi(req request.WafOPlatformKeyDetailReq) model.OPlatformKey {
	var bean model.OPlatformKey
	global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Find(&bean)
	bean.ApiKey = maskApiKey(bean.ApiKey)
	return bean
}

func (receiver *WafOPlatformKeyService) GetListApi(req request.WafOPlatformKeySearchReq) ([]model.OPlatformKey, int64, error) {
	var list []model.OPlatformKey
	var total int64 = 0

	whereField := ""
	var whereValues []interface{}
	if len(req.KeyName) > 0 {
		whereField = "key_name like ?"
		whereValues = append(whereValues, "%"+req.KeyName+"%")
	}

	global.GWAF_LOCAL_DB.Model(&model.OPlatformKey{}).Where(whereField, whereValues...).
		Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.OPlatformKey{}).Where(whereField, whereValues...).Count(&total)

	for i := range list {
		list[i].ApiKey = maskApiKey(list[i].ApiKey)
	}
	return list, total, nil
}

// ResetApiKey 重置 API Key，旧 Key 立即失效
func (receiver *WafOPlatformKeyService) ResetApiKey(req request.WafOPlatformKeyResetSecretReq) (string, error) {
	var bean model.OPlatformKey
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return "", errors.New("Key不存在")
	}
	newApiKey := "sk-" + genRandomHex(16)
	err = global.GWAF_LOCAL_DB.Model(model.OPlatformKey{}).Where("id = ?", req.Id).Updates(map[string]interface{}{
		"ApiKey":      newApiKey,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}).Error
	return newApiKey, err
}

// GetByApiKey 通过 ApiKey 字符串获取 Key 记录
func (receiver *WafOPlatformKeyService) GetByApiKey(apiKey string) (model.OPlatformKey, error) {
	var bean model.OPlatformKey
	err := global.GWAF_LOCAL_DB.Where("api_key = ?", apiKey).First(&bean).Error
	return bean, err
}

// IncrCallCount 增加调用次数并更新最后使用时间（异步调用）
func (receiver *WafOPlatformKeyService) IncrCallCount(id string) {
	now := time.Now()
	global.GWAF_LOCAL_DB.Exec(
		"UPDATE o_platform_keys SET call_count = call_count + 1, last_use_time = ?, update_time = ? WHERE id = ?",
		now.Format("2006-01-02 15:04:05"), customtype.JsonTime(now), id,
	)
}
