package waf_service

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	request2 "SamWaf/model/common/request"
	"SamWaf/model/request"
)

type WafLogService struct{}

var WafLogServiceApp = new(WafLogService)

func (receiver *WafLogService) AddApi(log innerbean.WebLog) error {
	global.GWAF_LOCAL_LOG_DB.Create(log)
	return nil
}
func (receiver *WafLogService) ModifyApi(log innerbean.WebLog) error {
	return nil
}
func (receiver *WafLogService) GetDetailApi(wafAttackDetailReq request.WafAttackLogDetailReq) (innerbean.WebLog, error) {
	var weblog innerbean.WebLog
	global.GWAF_LOCAL_LOG_DB.Where("REQ_UUID=?", wafAttackDetailReq.REQ_UUID).Find(&weblog)

	return weblog, nil
}
func (receiver *WafLogService) GetListApi(log request.WafAttackLogSearch) ([]innerbean.WebLog, int64, error) {
	var total int64 = 0
	var weblogs []innerbean.WebLog

	whereCondition := &request.WafAttackLogSearch{
		HostCode:   log.HostCode,
		Rule:       log.Rule,
		Action:     log.Action,
		SrcIp:      log.SrcIp,
		StatusCode: log.StatusCode,
		Method:     log.Method,
		PageInfo: request2.PageInfo{
			PageIndex: 0,
			PageSize:  0,
			Keyword:   "",
		},
	}
	global.GWAF_LOCAL_LOG_DB.Limit(log.PageSize).Where(whereCondition).Where("unix_add_time>=? and unix_add_time<=?", log.UnixAddTimeBegin, log.UnixAddTimeEnd).Offset(log.PageSize * (log.PageIndex - 1)).Order("create_time desc").Find(&weblogs)
	global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Where(whereCondition).Where("unix_add_time>=? and unix_add_time<=?", log.UnixAddTimeBegin, log.UnixAddTimeEnd).Count(&total)
	return weblogs, total, nil
}
func (receiver *WafLogService) GetListByHostCodeApi(log request.WafAttackLogSearch) ([]innerbean.WebLog, int64, error) {
	var total int64 = 0
	var weblogs []innerbean.WebLog
	global.GWAF_LOCAL_LOG_DB.Where("host_code = ? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE, log.HostCode).Limit(log.PageSize).Offset(log.PageSize * (log.PageIndex - 1)).Order("create_time desc").Find(&weblogs)
	global.GWAF_LOCAL_LOG_DB.Where("host_code = ? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE, log.HostCode).Model(&innerbean.WebLog{}).Count(&total)
	return weblogs, total, nil
}
func (receiver *WafLogService) DeleteHistory(day string) {
	global.GWAF_LOCAL_LOG_DB.Where("create_time < ?", day).Delete(&innerbean.WebLog{})
}
