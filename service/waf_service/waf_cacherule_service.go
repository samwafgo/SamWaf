package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"errors"
	"time"
)

type WafCacheRuleService struct{}

var WafCacheRuleServiceApp = new(WafCacheRuleService)

func (receiver *WafCacheRuleService) AddApi(req request.WafCacheRuleAddReq) error {
	var bean = &model.CacheRule{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},

		HostCode:      req.HostCode,
		RuleName:      req.RuleName,
		RuleType:      req.RuleType,
		RuleContent:   req.RuleContent,
		ParamType:     req.ParamType,
		CacheTime:     req.CacheTime,
		Priority:      req.Priority,
		RequestMethod: req.RequestMethod,
		Remarks:       req.Remarks,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafCacheRuleService) CheckIsExistApi(req request.WafCacheRuleAddReq) int {
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.HostCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " host_code=? "
	}

	if len(req.RuleName) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " rule_name=? "
	}

	//where字段赋值

	if len(req.HostCode) > 0 {
		if len(whereField) > 0 {
			whereValues = append(whereValues, req.HostCode)
		}
	}

	if len(req.RuleName) > 0 {
		if len(whereField) > 0 {
			whereValues = append(whereValues, req.RuleName)
		}
	}

	global.GWAF_LOCAL_DB.Model(&model.CacheRule{}).Where(whereField, whereValues...).Count(&total)
	return int(total)
}

func (receiver *WafCacheRuleService) ModifyApi(req request.WafCacheRuleEditReq) error {
	// 根据唯一字段生成查询条件（只有在UniFields不为空时才进行存在性检查）

	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.HostCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " host_code=? "
	}

	if len(req.RuleName) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " rule_name=? "
	}

	//where字段赋值

	if len(req.HostCode) > 0 {
		whereValues = append(whereValues, req.HostCode)
	}

	if len(req.RuleName) > 0 {
		whereValues = append(whereValues, req.RuleName)
	}

	global.GWAF_LOCAL_DB.Model(&model.CacheRule{}).Where(whereField, whereValues...).Count(&total)
	// 查询是否已存在记录
	var bean model.CacheRule
	global.GWAF_LOCAL_DB.Model(&model.CacheRule{}).Where(whereField, whereValues...).Limit(1).Find(&bean)

	if int(total) > 0 && bean.Id != "" && bean.Id != req.Id {
		return errors.New("当前记录已经存在")
	}

	beanMap := map[string]interface{}{

		"HostCode":      req.HostCode,
		"RuleName":      req.RuleName,
		"RuleType":      req.RuleType,
		"RuleContent":   req.RuleContent,
		"ParamType":     req.ParamType,
		"CacheTime":     req.CacheTime,
		"Priority":      req.Priority,
		"RequestMethod": req.RequestMethod,
		"Remarks":       req.Remarks,
		"UPDATE_TIME":   customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.CacheRule{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}
func (receiver *WafCacheRuleService) GetDetailApi(req request.WafCacheRuleDetailReq) model.CacheRule {
	var bean model.CacheRule
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafCacheRuleService) GetDetailByIdApi(id string) model.CacheRule {
	var bean model.CacheRule
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafCacheRuleService) GetListApi(req request.WafCacheRuleSearchReq) ([]model.CacheRule, int64, error) {
	var list []model.CacheRule
	var total int64 = 0

	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""
	if len(req.HostCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " host_code=? "
	}
	//where字段赋值
	if len(req.HostCode) > 0 {
		whereValues = append(whereValues, req.HostCode)
	}

	global.GWAF_LOCAL_DB.Model(&model.CacheRule{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.CacheRule{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafCacheRuleService) DelApi(req request.WafCacheRuleDelReq) error {
	var bean model.CacheRule
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.CacheRule{}).Error
	return err
}
