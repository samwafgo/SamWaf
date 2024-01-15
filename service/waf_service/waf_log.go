package waf_service

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"errors"
	"strings"
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

	splitFilterBys := strings.Split(req.FilterBy, "|")
	splitFilterValues := strings.Split(req.FilterValue, "|")
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}

	//where字段
	{
		whereField = whereField + " (unix_add_time>=? and unix_add_time<=?)"
		if len(req.HostCode) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " host_code=? "
		}
		if len(req.Rule) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " rule=? "
		}
		if len(req.Action) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " action=? "
		}
		if len(req.SrcIp) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " src_ip=? "
		}
		if len(req.StatusCode) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " status_code=? "
		}
		if len(req.Method) > 0 {
			if len(whereField) > 0 {
				whereField = whereField + " and "
			}
			whereField = whereField + " method=? "
		}
		for _, by := range splitFilterBys {

			if len(by) > 0 {
				if !receiver.isValidFilterField(by) {
					return nil, 0, errors.New("输入过滤字段不合法")
				}
				if len(whereField) > 0 {
					whereField = whereField + " and "
				}
				if by == "guest_identification" {
					by = "guest_id_entification"
				}
				whereField = whereField + " " + by + " like ? "
			}
		}
	}

	//where字段赋值
	{
		whereValues = append(whereValues, req.UnixAddTimeBegin)
		whereValues = append(whereValues, req.UnixAddTimeEnd)
		if len(req.HostCode) > 0 {
			whereValues = append(whereValues, req.HostCode)
		}
		if len(req.Rule) > 0 {
			whereValues = append(whereValues, req.Rule)
		}
		if len(req.Action) > 0 {
			whereValues = append(whereValues, req.Action)
		}
		if len(req.SrcIp) > 0 {
			whereValues = append(whereValues, req.SrcIp)
		}
		if len(req.StatusCode) > 0 {
			whereValues = append(whereValues, req.StatusCode)
		}
		if len(req.Method) > 0 {
			whereValues = append(whereValues, req.Method)
		}
		for _, val := range splitFilterValues {
			if len(val) > 0 {
				whereValues = append(whereValues, "%"+val+"%")
			}
		}
	}

	orderInfo := ""

	/**
	排序
	*/
	if receiver.isValidSortField(req.SortBy) {
		if req.SortDescending == "desc" {
			orderInfo = req.SortBy + " desc"
		} else {
			orderInfo = req.SortBy + " asc"
		}
	} else {
		return nil, 0, errors.New("输入排序字段不合法")
	}
	if len(req.CurrrentDbName) == 0 || req.CurrrentDbName == "local_log.db" {
		global.GWAF_LOCAL_LOG_DB.Limit(req.PageSize).Where(whereField, whereValues...).Offset(req.PageSize * (req.PageIndex - 1)).Order(orderInfo).Find(&weblogs)
		global.GWAF_LOCAL_LOG_DB.Model(&innerbean.WebLog{}).Where(whereField, whereValues...).Count(&total)

	} else {
		wafdb.InitManaulLogDb("", req.CurrrentDbName)
		global.GDATA_CURRENT_LOG_DB_MAP[req.CurrrentDbName].Debug().Limit(req.PageSize).Where(whereField, whereValues...).Offset(req.PageSize * (req.PageIndex - 1)).Order(orderInfo).Find(&weblogs)
		global.GDATA_CURRENT_LOG_DB_MAP[req.CurrrentDbName].Model(&innerbean.WebLog{}).Where(whereField, whereValues...).Count(&total)

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

/*
*
判断是否合法
*/
func (receiver *WafLogService) isValidSortField(field string) bool {
	var allowedSortFields = []string{"time_spent", "create_time"}

	for _, allowedField := range allowedSortFields {
		if field == allowedField {
			return true
		}
	}
	return false
}

/*
*
判断where是否合法
*/
func (receiver *WafLogService) isValidFilterField(field string) bool {
	var allowedFilterFields = []string{"header", "guest_identification"}

	for _, allowedField := range allowedFilterFields {
		if field == allowedField {
			return true
		}
	}
	return false
}
