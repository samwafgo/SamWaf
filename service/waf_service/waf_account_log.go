package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
)

type WafAccountLogService struct{}

var WafAccountLogServiceApp = new(WafAccountLogService)

func (receiver *WafAccountLogService) GetDetailApi(req request.WafAccountLogDetailReq) model.AccountLog {
	var bean model.AccountLog
	global.GWAF_LOCAL_LOG_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafAccountLogService) GetListApi(req request.WafAccountLogSearchReq) ([]model.AccountLog, int64, error) {
	var bean []model.AccountLog
	var total int64 = 0
	global.GWAF_LOCAL_LOG_DB.Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&bean)
	global.GWAF_LOCAL_LOG_DB.Model(&model.AccountLog{}).Count(&total)
	return bean, total, nil
}
