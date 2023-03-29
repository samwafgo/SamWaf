package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
)

type WafSysLogService struct{}

var WafSysLogServiceApp = new(WafSysLogService)

func (receiver *WafSysLogService) GetDetailApi(req request.WafSysLogDetailReq) model.WafSysLog {
	var bean model.WafSysLog
	global.GWAF_LOCAL_LOG_DB.Debug().Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafSysLogService) GetListApi(req request.WafSysLogSearchReq) ([]model.WafSysLog, int64, error) {
	var bean []model.WafSysLog
	var total int64 = 0
	global.GWAF_LOCAL_LOG_DB.Debug().Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&bean)
	global.GWAF_LOCAL_LOG_DB.Debug().Model(&model.WafSysLog{}).Count(&total)
	return bean, total, nil
}
