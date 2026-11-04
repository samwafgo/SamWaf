package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafsec"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// localOnlyKeyRecordID 是本机命令行 Key 的固定记录标识，避免首次创建竞争产生多份。
const localOnlyKeyRecordID = "cli-local-key"

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
		LocalOnly:   0,
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
	bean.ApiKey = maskStoredApiKey(bean)
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
		list[i].ApiKey = maskStoredApiKey(list[i])
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
	newApiKey, err := newLocalAPIKey()
	if err != nil {
		return "", err
	}
	stored := newApiKey
	if bean.LocalOnly == 1 {
		stored, err = wafsec.DataEncrypt(newApiKey)
		if err != nil {
			return "", err
		}
	}
	err = global.GWAF_LOCAL_DB.Model(model.OPlatformKey{}).Where("id = ?", req.Id).Updates(map[string]interface{}{
		"ApiKey":      stored,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}).Error
	return newApiKey, err
}

// GetByApiKey 通过 ApiKey 字符串获取 Key 记录
func (receiver *WafOPlatformKeyService) GetByApiKey(apiKey string) (model.OPlatformKey, error) {
	var bean model.OPlatformKey
	db := global.GWAF_LOCAL_DB.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)})
	err := db.Where("api_key = ?", apiKey).First(&bean).Error
	if err == nil && (bean.LocalOnly != 1 || !wafsec.IsDataKeyCiphertext(bean.ApiKey)) {
		return bean, nil
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return model.OPlatformKey{}, err
	}
	var keys []model.OPlatformKey
	if err := db.Where("local_only = ?", 1).Find(&keys).Error; err != nil {
		return model.OPlatformKey{}, err
	}
	for _, candidate := range keys {
		if !wafsec.IsDataKeyCiphertext(candidate.ApiKey) {
			continue
		}
		plain, err := wafsec.DataDecrypt(candidate.ApiKey, nil)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(plain), []byte(apiKey)) == 1 {
			candidate.ApiKey = plain
			return candidate, nil
		}
	}
	return model.OPlatformKey{}, gorm.ErrRecordNotFound
}

// IncrCallCount 增加调用次数并更新最后使用时间（异步调用）
func (receiver *WafOPlatformKeyService) IncrCallCount(id string) {
	now := time.Now()
	global.GWAF_LOCAL_DB.Exec(
		"UPDATE o_platform_keys SET call_count = call_count + 1, last_use_time = ?, update_time = ? WHERE id = ?",
		now.Format("2006-01-02 15:04:05"), customtype.JsonTime(now), id,
	)
}

func maskStoredApiKey(bean model.OPlatformKey) string {
	if bean.LocalOnly == 1 && wafsec.IsDataKeyCiphertext(bean.ApiKey) {
		plain, err := wafsec.DataDecrypt(bean.ApiKey, nil)
		if err != nil {
			return "****"
		}
		if len(plain) <= 10 {
			return "****"
		}
		return maskApiKey(plain)
	}
	return maskApiKey(bean.ApiKey)
}

func newLocalAPIKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sk-" + hex.EncodeToString(b), nil
}

// EnsureLocalOnlyKey 创建或复用本机命令行 Key，并恢复启用状态。
func (receiver *WafOPlatformKeyService) EnsureLocalOnlyKey(rotate bool) (apiKey string, action string, err error) {
	err = global.GWAF_LOCAL_DB.Transaction(func(tx *gorm.DB) error {
		var bean model.OPlatformKey
		findErr := tx.Where("local_only = ?", 1).Order("create_time asc").First(&bean).Error
		if errors.Is(findErr, gorm.ErrRecordNotFound) {
			findErr = tx.Where("id = ?", localOnlyKeyRecordID).First(&bean).Error
		}
		if errors.Is(findErr, gorm.ErrRecordNotFound) {
			plain, err := newLocalAPIKey()
			if err != nil {
				return err
			}
			encrypted, err := wafsec.DataEncrypt(plain)
			if err != nil {
				return err
			}
			now := customtype.JsonTime(time.Now())
			bean = model.OPlatformKey{
				BaseOrm: baseorm.BaseOrm{Id: localOnlyKeyRecordID, USER_CODE: global.GWAF_USER_CODE, Tenant_ID: global.GWAF_TENANT_ID, CREATE_TIME: now, UPDATE_TIME: now},
				KeyName: "本机命令行(CLI)", Remark: "由 apikey init 创建，仅限本机回环地址调用",
				ApiKey: encrypted, LocalOnly: 1, Status: 1, RateLimit: 0,
			}
			// 并发初始化只能有一个写入成功；冲突后读取已有记录并复用原事务流程。
			result := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "id"}}, DoNothing: true}).Create(&bean)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected == 1 {
				apiKey, action = plain, "created"
				return nil
			}
			if err := tx.Where("id = ?", localOnlyKeyRecordID).First(&bean).Error; err != nil {
				return err
			}
			plain, err = wafsec.DataDecrypt(bean.ApiKey, nil)
			if err != nil {
				if !rotate {
					return errors.New("本机 Key 解密失败，请检查数据密钥或使用 --rotate")
				}
				plain, err = newLocalAPIKey()
				if err != nil {
					return err
				}
				action = "rotated"
			}
			updates := map[string]interface{}{"Status": 1, "UPDATE_TIME": customtype.JsonTime(time.Now())}
			if action == "rotated" {
				encrypted, err := wafsec.DataEncrypt(plain)
				if err != nil {
					return err
				}
				updates["ApiKey"] = encrypted
			}
			if bean.ExpireTime != "" {
				expiration, err := time.Parse("2006-01-02 15:04:05", bean.ExpireTime)
				if err != nil || time.Now().After(expiration) {
					updates["ExpireTime"] = ""
				}
			}
			if err := tx.Model(&model.OPlatformKey{}).Where("id = ?", bean.Id).Updates(updates).Error; err != nil {
				return err
			}
			apiKey = plain
			return nil
		}
		if findErr != nil {
			return findErr
		}
		plain := bean.ApiKey
		if wafsec.IsDataKeyCiphertext(plain) {
			var err error
			plain, err = wafsec.DataDecrypt(plain, nil)
			if err != nil && !rotate {
				return errors.New("本机 Key 解密失败，请检查数据密钥或使用 --rotate")
			}
		}
		action = "reused"
		if rotate || plain == "" {
			var err error
			plain, err = newLocalAPIKey()
			if err != nil {
				return err
			}
			action = "rotated"
		}
		updates := map[string]interface{}{"Status": 1, "UPDATE_TIME": customtype.JsonTime(time.Now())}
		if rotate || !wafsec.IsDataKeyCiphertext(bean.ApiKey) || bean.ApiKey == "" {
			encrypted, err := wafsec.DataEncrypt(plain)
			if err != nil {
				return err
			}
			updates["ApiKey"] = encrypted
		}
		if bean.ExpireTime != "" {
			expiration, err := time.Parse("2006-01-02 15:04:05", bean.ExpireTime)
			if err != nil || time.Now().After(expiration) {
				updates["ExpireTime"] = ""
			}
		}
		if err := tx.Model(&model.OPlatformKey{}).Where("id = ?", bean.Id).Updates(updates).Error; err != nil {
			return err
		}
		apiKey = plain
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return apiKey, action, nil
}
