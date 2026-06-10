package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"time"
)

type WafAppChangeLogService struct{}

var WafAppChangeLogServiceApp = new(WafAppChangeLogService)

// Record 写入一条变更记录
func (s *WafAppChangeLogService) Record(appCode, appName, opType, operator, operatorIP, changes string) {
	log := &model.WafAppChangeLog{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		AppCode:    appCode,
		AppName:    appName,
		OpType:     opType,
		Operator:   operator,
		OperatorIP: operatorIP,
		Changes:    changes,
	}
	global.GWAF_LOCAL_DB.Create(log)
}

// GetListByCode 分页查询应用变更记录
func (s *WafAppChangeLogService) GetListByCode(req request.WafAppChangeLogSearchReq) ([]model.WafAppChangeLog, int64) {
	var list []model.WafAppChangeLog
	var total int64
	db := global.GWAF_LOCAL_DB.Model(&model.WafAppChangeLog{}).Where("app_code = ?", req.Code)
	db.Count(&total)
	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}
	pageIndex := req.PageIndex
	if pageIndex <= 0 {
		pageIndex = 1
	}
	db.Order("create_time DESC").Limit(pageSize).Offset((pageIndex - 1) * pageSize).Find(&list)
	return list, total
}

// GetCountByCode 查询某应用的变更记录总数（用于列表徽章）
func (s *WafAppChangeLogService) GetCountByCode(code string) int64 {
	var total int64
	global.GWAF_LOCAL_DB.Model(&model.WafAppChangeLog{}).Where("app_code = ?", code).Count(&total)
	return total
}

// GetRecentByCode 获取最近 n 条变更记录（用于列表展示）
func (s *WafAppChangeLogService) GetRecentByCode(code string, n int) []model.WafAppChangeLog {
	var list []model.WafAppChangeLog
	global.GWAF_LOCAL_DB.Model(&model.WafAppChangeLog{}).
		Where("app_code = ?", code).
		Order("create_time DESC").
		Limit(n).
		Find(&list)
	return list
}
