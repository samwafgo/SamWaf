package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"time"
)

type WafOPlatformLogService struct{}

var WafOPlatformLogServiceApp = new(WafOPlatformLogService)

// AddLog 记录一条调用日志
func (receiver *WafOPlatformLogService) AddLog(logEntry model.OPlatformLog) error {
	logEntry.Id = uuid.GenUUID()
	logEntry.USER_CODE = global.GWAF_USER_CODE
	logEntry.Tenant_ID = global.GWAF_TENANT_ID
	logEntry.CREATE_TIME = customtype.JsonTime(time.Now())
	logEntry.UPDATE_TIME = customtype.JsonTime(time.Now())
	if logEntry.TimeStr == "" {
		logEntry.TimeStr = time.Now().Format("2006-01-02 15:04:05")
	}
	return global.GWAF_LOCAL_LOG_DB.Create(&logEntry).Error
}

func (receiver *WafOPlatformLogService) GetDetailApi(req request.WafOPlatformLogDetailReq) model.OPlatformLog {
	var bean model.OPlatformLog
	global.GWAF_LOCAL_LOG_DB.Where("id = ?", req.Id).Find(&bean)
	return bean
}

func (receiver *WafOPlatformLogService) GetListApi(req request.WafOPlatformLogSearchReq) ([]model.OPlatformLog, int64, error) {
	var list []model.OPlatformLog
	var total int64 = 0

	whereField := ""
	var whereValues []interface{}

	if len(req.KeyName) > 0 {
		if len(whereField) > 0 {
			whereField += " and "
		}
		whereField += "key_name like ?"
		whereValues = append(whereValues, "%"+req.KeyName+"%")
	}
	if len(req.RequestPath) > 0 {
		if len(whereField) > 0 {
			whereField += " and "
		}
		whereField += "request_path like ?"
		whereValues = append(whereValues, "%"+req.RequestPath+"%")
	}
	if len(req.ClientIP) > 0 {
		if len(whereField) > 0 {
			whereField += " and "
		}
		whereField += "client_ip = ?"
		whereValues = append(whereValues, req.ClientIP)
	}
	if len(req.RequestMethod) > 0 {
		if len(whereField) > 0 {
			whereField += " and "
		}
		whereField += "request_method = ?"
		whereValues = append(whereValues, req.RequestMethod)
	}

	global.GWAF_LOCAL_LOG_DB.Model(&model.OPlatformLog{}).Where(whereField, whereValues...).
		Order("create_time desc").
		Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_LOG_DB.Model(&model.OPlatformLog{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}

func (receiver *WafOPlatformLogService) DelApi(req request.WafOPlatformLogDelReq) error {
	return global.GWAF_LOCAL_LOG_DB.Where("id = ?", req.Id).Delete(model.OPlatformLog{}).Error
}

// AddLogAsync 异步记录日志，不阻塞主流程
func (receiver *WafOPlatformLogService) AddLogAsync(logEntry model.OPlatformLog) {
	go func() {
		_ = receiver.AddLog(logEntry)
	}()
}
