package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"errors"
	uuid "github.com/satori/go.uuid"
	"time"
)

type WafHostService struct{}

var WafHostServiceApp = new(WafHostService)

func (receiver *WafHostService) AddApi(wafHostAddReq request.WafHostAddReq) (string, error) {
	uniCode := ""
	if wafHostAddReq.Code == "" {
		uniCode = uuid.NewV4().String()
	} else {
		uniCode = wafHostAddReq.Code
	}
	var wafHost = &model.Hosts{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		Code:                uniCode,
		Host:                wafHostAddReq.Host,
		Port:                wafHostAddReq.Port,
		Ssl:                 wafHostAddReq.Ssl,
		GUARD_STATUS:        1,
		REMOTE_SYSTEM:       wafHostAddReq.REMOTE_SYSTEM,
		REMOTE_APP:          wafHostAddReq.REMOTE_APP,
		Remote_host:         wafHostAddReq.Remote_host,
		Remote_port:         wafHostAddReq.Remote_port,
		Remote_ip:           wafHostAddReq.Remote_ip,
		Certfile:            wafHostAddReq.Certfile,
		Keyfile:             wafHostAddReq.Keyfile,
		REMARKS:             wafHostAddReq.REMARKS,
		GLOBAL_HOST:         0,
		DEFENSE_JSON:        wafHostAddReq.DEFENSE_JSON,
		START_STATUS:        wafHostAddReq.START_STATUS,
		EXCLUDE_URL_LOG:     wafHostAddReq.EXCLUDE_URL_LOG,
		IsEnableLoadBalance: wafHostAddReq.IsEnableLoadBalance,
		LoadBalanceStage:    wafHostAddReq.LoadBalanceStage,
		UnrestrictedPort:    wafHostAddReq.UnrestrictedPort,
	}
	global.GWAF_LOCAL_DB.Create(wafHost)
	return wafHost.Code, nil
}

func (receiver *WafHostService) CheckIsExistApi(wafHostAddReq request.WafHostAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.Hosts{}, "host = ? and port= ?", wafHostAddReq.Host, wafHostAddReq.Port).Error
}
func (receiver *WafHostService) CheckIsExist(host string, port string) error {
	return global.GWAF_LOCAL_DB.First(&model.Hosts{}, "host = ? and port= ?", host, port).Error
}

func (receiver *WafHostService) ModifyApi(wafHostEditReq request.WafHostEditReq) error {
	var webHost model.Hosts
	global.GWAF_LOCAL_DB.Where("host = ? and port= ?", wafHostEditReq.Host, wafHostEditReq.Port).Find(&webHost)
	if webHost.Id != "" && webHost.Code != wafHostEditReq.CODE {
		return errors.New("当前网站和端口已经存在")
	}
	if webHost.GLOBAL_HOST == 1 {
		return errors.New("全局网站不允许单独编辑")
	}
	hostMap := map[string]interface{}{
		"Host": wafHostEditReq.Host,
		"Port": wafHostEditReq.Port,
		"Ssl":  wafHostEditReq.Ssl,
		//"GUARD_STATUS":  0,
		"REMOTE_SYSTEM":       wafHostEditReq.REMOTE_SYSTEM,
		"REMOTE_APP":          wafHostEditReq.REMOTE_APP,
		"Remote_host":         wafHostEditReq.Remote_host,
		"Remote_ip":           wafHostEditReq.Remote_ip,
		"Remote_port":         wafHostEditReq.Remote_port,
		"REMARKS":             wafHostEditReq.REMARKS,
		"GLOBAL_HOST":         0,
		"Certfile":            wafHostEditReq.Certfile,
		"Keyfile":             wafHostEditReq.Keyfile,
		"UPDATE_TIME":         customtype.JsonTime(time.Now()),
		"DEFENSE_JSON":        wafHostEditReq.DEFENSE_JSON,
		"START_STATUS":        wafHostEditReq.START_STATUS,
		"EXCLUDE_URL_LOG":     wafHostEditReq.EXCLUDE_URL_LOG,
		"IsEnableLoadBalance": wafHostEditReq.IsEnableLoadBalance,
		"LoadBalanceStage":    wafHostEditReq.LoadBalanceStage,
		"UnrestrictedPort":    wafHostEditReq.UnrestrictedPort,
	}
	err := global.GWAF_LOCAL_DB.Debug().Model(model.Hosts{}).Where("CODE=?", wafHostEditReq.CODE).Updates(hostMap).Error

	return err
}
func (receiver *WafHostService) GetDetailApi(req request.WafHostDetailReq) model.Hosts {
	var webHost model.Hosts
	global.GWAF_LOCAL_DB.Where("CODE=?", req.CODE).Find(&webHost)
	return webHost
}
func (receiver *WafHostService) GetDetailByCodeApi(code string) model.Hosts {
	var webHost model.Hosts
	global.GWAF_LOCAL_DB.Where("CODE=?", code).Find(&webHost)
	return webHost
}
func (receiver *WafHostService) GetListApi(req request.WafHostSearchReq) ([]model.Hosts, int64, error) {
	var list []model.Hosts
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	if len(req.Code) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " code=? "
	}
	if len(req.REMARKS) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " remarks like ? "
	}
	//where字段赋值
	if len(req.Code) > 0 {
		whereValues = append(whereValues, req.Code)
	}
	if len(req.REMARKS) > 0 {
		whereValues = append(whereValues, "%"+req.REMARKS+"%")
	}

	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafHostService) DelHostApi(req request.WafHostDelReq) (model.Hosts, error) {
	var webhost model.Hosts
	err := global.GWAF_LOCAL_DB.Where("CODE = ?", req.CODE).First(&webhost).Error
	if webhost.GLOBAL_HOST == 1 {
		return model.Hosts{}, errors.New("全局网站不允许单独删除")
	}
	if err != nil {
		return model.Hosts{}, err
	}
	err = global.GWAF_LOCAL_DB.Where("CODE = ?", req.CODE).Delete(model.Hosts{}).Error
	//删除规则
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.Rules{}).Error
	//删除Anticc
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.AntiCC{}).Error
	//删除禁用ip
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.IPBlockList{}).Error
	//删除禁用url
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.URLBlockList{}).Error
	//删除隐私保护url
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.LDPUrl{}).Error
	//删除白名单ip
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.IPAllowList{}).Error
	//删除白名单URL
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.URLAllowList{}).Error
	return webhost, err
}
func (receiver *WafHostService) ModifyGuardStatusApi(req request.WafHostGuardStatusReq) error {
	hostMap := map[string]interface{}{
		"GUARD_STATUS": req.GUARD_STATUS,
		"UPDATE_TIME":  customtype.JsonTime(time.Now()),
	}

	err := global.GWAF_LOCAL_DB.Model(model.Hosts{}).Where("CODE=?", req.CODE).Updates(hostMap).Error
	return err
}
func (receiver *WafHostService) ModifyStartStatusApi(req request.WafHostStartStatusReq) error {
	hostMap := map[string]interface{}{
		"START_STATUS": req.START_STATUS,
		"UPDATE_TIME":  customtype.JsonTime(time.Now()),
	}

	err := global.GWAF_LOCAL_DB.Model(model.Hosts{}).Where("CODE=?", req.CODE).Updates(hostMap).Error
	return err
}
func (receiver *WafHostService) GetAllHostApi() []model.Hosts {
	var webHosts []model.Hosts
	global.GWAF_LOCAL_DB.Order("global_host desc").Find(&webHosts)
	return webHosts
}
func (receiver *WafHostService) CheckPortExistApi(port int) int64 {
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where("port=?", port).Count(&total)
	return total
}

func (receiver *WafHostService) CheckAvailablePortExistApi(port int) int64 {
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where(" (start_status = 0 or start_status is null) and port=?", port).Count(&total)
	return total
}

func (receiver *WafHostService) IsEmptyHost() bool {
	var total int64 = 0
	err := global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Where("global_host=?", 0).Count(&total).Error
	if err == nil {
		if total == 0 {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}
