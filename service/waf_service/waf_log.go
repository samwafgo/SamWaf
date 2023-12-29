package waf_service

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/request"
	"SamWaf/wafdb"
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
func (receiver *WafLogService) GetDetailApi(req request.WafAttackLogDetailReq) (innerbean.WebLog, error) {
	var weblog innerbean.WebLog
	if len(req.CurrrentDbName) == 0 || req.CurrrentDbName == "local_log.db" {
		global.GWAF_LOCAL_LOG_DB.Where("REQ_UUID=?", req.REQ_UUID).Find(&weblog)
	} else {
		wafdb.InitManaulLogDb("", req.CurrrentDbName)
		global.GDATA_CURRENT_LOG_DB_MAP[req.CurrrentDbName].Where("REQ_UUID=?", req.REQ_UUID).Find(&weblog)
	}

	return weblog, nil
}
func (receiver *WafLogService) GetListApi(req request.WafAttackLogSearch) ([]innerbean.WebLog, int64, error) {
	var total int64 = 0
	var weblogs []innerbean.WebLog

	whereCondition := &request.WafAttackLogSearch{
		HostCode:   req.HostCode,
		Rule:       req.Rule,
		Action:     req.Action,
		SrcIp:      req.SrcIp,
		StatusCode: req.StatusCode,
		Method:     req.Method,
	}
	if len(req.CurrrentDbName) == 0 || req.CurrrentDbName == "local_log.db" {
		global.GWAF_LOCAL_LOG_DB.Limit(req.PageSize).Where(whereCondition).Where("unix_add_time>=? and unix_add_time<=?", req.UnixAddTimeBegin, req.UnixAddTimeEnd).Offset(req.PageSize * (req.PageIndex - 1)).Order("create_time desc").Find(&weblogs)
		global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Where(whereCondition).Where("unix_add_time>=? and unix_add_time<=?", req.UnixAddTimeBegin, req.UnixAddTimeEnd).Count(&total)

	} else {
		wafdb.InitManaulLogDb("", req.CurrrentDbName)
		global.GDATA_CURRENT_LOG_DB_MAP[req.CurrrentDbName].Debug().Limit(req.PageSize).Where(whereCondition).Where("unix_add_time>=? and unix_add_time<=?", req.UnixAddTimeBegin, req.UnixAddTimeEnd).Offset(req.PageSize * (req.PageIndex - 1)).Order("create_time desc").Find(&weblogs)
		global.GDATA_CURRENT_LOG_DB_MAP[req.CurrrentDbName].Model(&innerbean.WebLog{}).Where(whereCondition).Where("unix_add_time>=? and unix_add_time<=?", req.UnixAddTimeBegin, req.UnixAddTimeEnd).Count(&total)

	}
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
