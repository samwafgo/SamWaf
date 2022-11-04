package waf_service

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/request"
)

type WafLogService struct{}

var WafLogServiceApp = new(WafLogService)

func (receiver *WafLogService) AddApi(log innerbean.WebLog) error {
	global.GWAF_LOCAL_DB.Create(log)
	return nil
}
func (receiver *WafLogService) ModifyApi(log innerbean.WebLog) error {
	return nil
}
func (receiver *WafLogService) GetDetailApi(wafAttackDetailReq request.WafAttackLogDetailReq) (innerbean.WebLog, error) {
	var weblog innerbean.WebLog
	global.GWAF_LOCAL_DB.Debug().Where("REQ_UUID=?", wafAttackDetailReq.REQ_UUID).Find(&weblog)

	return weblog, nil
}
func (receiver *WafLogService) GetListApi(log request.WafAttackLogSearch) ([]innerbean.WebLog, int64, error) {
	var total int64 = 0
	var weblogs []innerbean.WebLog
	global.GWAF_LOCAL_DB.Debug().Limit(log.PageSize).Offset(log.PageSize * (log.PageIndex - 1)).Order("create_time desc").Find(&weblogs)
	global.GWAF_LOCAL_DB.Debug().Model(&innerbean.WebLog{}).Count(&total)
	return weblogs, total, nil
}
func (receiver *WafLogService) GetListByHostCodeApi(log request.WafAttackLogSearch) ([]innerbean.WebLog, int64, error) {
	var total int64 = 0
	var weblogs []innerbean.WebLog
	global.GWAF_LOCAL_DB.Debug().Where("tenant_id = ? and user_code=?  and host_code = ? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE, log.HostCode).Limit(log.PageSize).Offset(log.PageSize * (log.PageIndex - 1)).Order("create_time desc").Find(&weblogs)
	global.GWAF_LOCAL_DB.Debug().Where("tenant_id = ? and user_code=?  and host_code = ? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE, log.HostCode).Model(&innerbean.WebLog{}).Count(&total)
	return weblogs, total, nil
}
