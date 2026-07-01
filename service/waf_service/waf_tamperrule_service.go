package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"errors"
	"strings"
	"time"
)

type WafTamperRuleService struct{}

var WafTamperRuleServiceApp = new(WafTamperRuleService)

// validateUrl 受保护 URL 必须是精确路径：非空、以 / 开头、不含通配符与 query
func validateTamperUrl(url string) error {
	url = strings.TrimSpace(url)
	if url == "" {
		return errors.New("受保护URL不能为空")
	}
	if !strings.HasPrefix(url, "/") {
		return errors.New("受保护URL需以 / 开头的精确路径，例如 /index.html")
	}
	if strings.Contains(url, "*") {
		return errors.New("受保护URL不支持通配符，请填写精确路径")
	}
	if strings.ContainsAny(url, "?#") {
		return errors.New("受保护URL不能包含参数(?)或锚点(#)")
	}
	return nil
}

func (receiver *WafTamperRuleService) AddApi(req request.WafTamperRuleAddReq) error {
	if err := validateTamperUrl(req.Url); err != nil {
		return err
	}
	var bean = &model.TamperRule{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode:       req.HostCode,
		Url:            strings.TrimSpace(req.Url),
		RuleName:       req.RuleName,
		IsEnable:       req.IsEnable,
		IgnoreQuery:    req.IgnoreQuery,
		BaselineStatus: 0, // 待学习
		Remarks:        req.Remarks,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafTamperRuleService) CheckIsExistApi(req request.WafTamperRuleAddReq) int {
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.TamperRule{}).Where("host_code=? and url=?", req.HostCode, strings.TrimSpace(req.Url)).Count(&total)
	return int(total)
}

func (receiver *WafTamperRuleService) ModifyApi(req request.WafTamperRuleEditReq) error {
	if err := validateTamperUrl(req.Url); err != nil {
		return err
	}
	// 同站点同 URL 唯一（排除自身）
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.TamperRule{}).Where("host_code=? and url=? and id<>?", req.HostCode, strings.TrimSpace(req.Url), req.Id).Count(&total)
	if total > 0 {
		return errors.New("同站点下该URL的防篡改规则已存在")
	}

	// 若 URL 变化则基线作废，需重新学习
	var old model.TamperRule
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&old)

	beanMap := map[string]interface{}{
		"HostCode":    req.HostCode,
		"Url":         strings.TrimSpace(req.Url),
		"RuleName":    req.RuleName,
		"IsEnable":    req.IsEnable,
		"IgnoreQuery": req.IgnoreQuery,
		"Remarks":     req.Remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	if old.Id != "" && old.Url != strings.TrimSpace(req.Url) {
		beanMap["BaselineStatus"] = 0
		beanMap["BaselineHash"] = ""
		beanMap["BaselineContent"] = []byte{}
		beanMap["BaselineMsg"] = "URL已变更，待重新学习"
	}
	err := global.GWAF_LOCAL_DB.Model(model.TamperRule{}).Where("id = ?", req.Id).Updates(beanMap).Error
	return err
}

// RelearnApi 触发重新学习：清空基线状态，下次访问该 URL 时重新捕获
func (receiver *WafTamperRuleService) RelearnApi(req request.WafTamperRuleRelearnReq) error {
	beanMap := map[string]interface{}{
		"BaselineStatus":  0,
		"BaselineHash":    "",
		"BaselineContent": []byte{},
		"ContentSize":     0,
		"BaselineMsg":     "已标记重新学习",
		"UPDATE_TIME":     customtype.JsonTime(time.Now()),
	}
	return global.GWAF_LOCAL_DB.Model(model.TamperRule{}).Where("id = ?", req.Id).Updates(beanMap).Error
}

func (receiver *WafTamperRuleService) GetDetailApi(req request.WafTamperRuleDetailReq) model.TamperRule {
	var bean model.TamperRule
	// 列表/详情不带大 blob，避免加载慢
	global.GWAF_LOCAL_DB.Omit("baseline_content").Where("id=?", req.Id).Find(&bean)
	return bean
}

func (receiver *WafTamperRuleService) GetDetailByIdApi(id string) model.TamperRule {
	var bean model.TamperRule
	global.GWAF_LOCAL_DB.Omit("baseline_content").Where("id=?", id).Find(&bean)
	return bean
}

// GetBaselineApi 按需取基线正文（含 blob），供“查看基线”弹窗
func (receiver *WafTamperRuleService) GetBaselineApi(id string) model.TamperRule {
	var bean model.TamperRule
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}

func (receiver *WafTamperRuleService) GetListApi(req request.WafTamperRuleSearchReq) ([]model.TamperRule, int64, error) {
	var list []model.TamperRule
	var total int64 = 0

	var whereField = ""
	var whereValues []interface{}
	if len(req.HostCode) > 0 {
		whereField = " host_code=? "
		whereValues = append(whereValues, req.HostCode)
	}

	// Omit baseline_content：列表绝不携带大 blob
	global.GWAF_LOCAL_DB.Model(&model.TamperRule{}).Omit("baseline_content").Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Order("create_time desc").Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.TamperRule{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}

func (receiver *WafTamperRuleService) DelApi(req request.WafTamperRuleDelReq) error {
	var bean model.TamperRule
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.TamperRule{}).Error
	return err
}
