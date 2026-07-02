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

type WafHostPathRuleService struct{}

var WafHostPathRuleServiceApp = new(WafHostPathRuleService)

func (s *WafHostPathRuleService) AddApi(req request.WafHostPathRuleAddReq) error {
	bean := &model.HostPathRule{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode:        req.HostCode,
		RuleName:        req.RuleName,
		Path:            req.Path,
		MatchType:       req.MatchType,
		Priority:        req.Priority,
		TargetType:      req.TargetType,
		StripPrefix:     req.StripPrefix,
		RemoteHost:      req.RemoteHost,
		RemotePort:      req.RemotePort,
		RemoteIP:        req.RemoteIP,
		RemoteScheme:    req.RemoteScheme,
		RecordAccessLog: req.RecordAccessLog,
		ResponseTimeOut: req.ResponseTimeOut,
		StaticRoot:      req.StaticRoot,
		SpaFallback:     req.SpaFallback,
		RedirectURL:     req.RedirectURL,
		RedirectCode:    req.RedirectCode,
		Remarks:         req.Remarks,
	}
	return global.GWAF_LOCAL_DB.Create(bean).Error
}

func (s *WafHostPathRuleService) CheckIsExistApi(req request.WafHostPathRuleAddReq) int {
	var total int64
	global.GWAF_LOCAL_DB.Model(&model.HostPathRule{}).
		Where("host_code=? AND rule_name=?", req.HostCode, req.RuleName).
		Count(&total)
	return int(total)
}

func (s *WafHostPathRuleService) ModifyApi(req request.WafHostPathRuleEditReq) error {
	var total int64
	global.GWAF_LOCAL_DB.Model(&model.HostPathRule{}).
		Where("host_code=? AND rule_name=?", req.HostCode, req.RuleName).
		Count(&total)

	var bean model.HostPathRule
	global.GWAF_LOCAL_DB.Model(&model.HostPathRule{}).
		Where("host_code=? AND rule_name=?", req.HostCode, req.RuleName).
		Limit(1).Find(&bean)

	if total > 0 && bean.Id != "" && bean.Id != req.Id {
		return errors.New("当前记录已经存在")
	}

	beanMap := map[string]interface{}{
		"HostCode":        req.HostCode,
		"RuleName":        req.RuleName,
		"Path":            req.Path,
		"MatchType":       req.MatchType,
		"Priority":        req.Priority,
		"TargetType":      req.TargetType,
		"StripPrefix":     req.StripPrefix,
		"RemoteHost":      req.RemoteHost,
		"RemotePort":      req.RemotePort,
		"RemoteIP":        req.RemoteIP,
		"RemoteScheme":    req.RemoteScheme,
		"RecordAccessLog": req.RecordAccessLog,
		"ResponseTimeOut": req.ResponseTimeOut,
		"StaticRoot":      req.StaticRoot,
		"SpaFallback":     req.SpaFallback,
		"RedirectURL":     req.RedirectURL,
		"RedirectCode":    req.RedirectCode,
		"Remarks":         req.Remarks,
		"UPDATE_TIME":     customtype.JsonTime(time.Now()),
	}
	return global.GWAF_LOCAL_DB.Model(model.HostPathRule{}).Where("id = ?", req.Id).Updates(beanMap).Error
}

func (s *WafHostPathRuleService) GetDetailApi(req request.WafHostPathRuleDetailReq) model.HostPathRule {
	var bean model.HostPathRule
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}

func (s *WafHostPathRuleService) GetDetailByIdApi(id string) model.HostPathRule {
	var bean model.HostPathRule
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}

func (s *WafHostPathRuleService) GetListApi(req request.WafHostPathRuleSearchReq) ([]model.HostPathRule, int64, error) {
	var list []model.HostPathRule
	var total int64

	query := global.GWAF_LOCAL_DB.Model(&model.HostPathRule{})
	if len(req.HostCode) > 0 {
		query = query.Where("host_code=?", req.HostCode)
	}

	query.Count(&total)
	query.Order("priority asc, create_time asc").
		Limit(req.PageSize).
		Offset(req.PageSize * (req.PageIndex - 1)).
		Find(&list)

	return list, total, nil
}

func (s *WafHostPathRuleService) DelApi(req request.WafHostPathRuleDelReq) error {
	var bean model.HostPathRule
	if err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error; err != nil {
		return err
	}
	return global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.HostPathRule{}).Error
}

func (s *WafHostPathRuleService) GetListByHostCode(hostCode string) []model.HostPathRule {
	var list []model.HostPathRule
	global.GWAF_LOCAL_DB.Where("host_code=?", hostCode).Order("priority asc, create_time asc").Find(&list)
	return list
}
