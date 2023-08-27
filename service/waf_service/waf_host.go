package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"errors"
	uuid "github.com/satori/go.uuid"
	"time"
)

type WafHostService struct{}

var WafHostServiceApp = new(WafHostService)

func (receiver *WafHostService) AddApi(wafHostAddReq request.WafHostAddReq) error {
	var wafHost = &model.Hosts{
		USER_CODE:     global.GWAF_USER_CODE,
		Tenant_id:     global.GWAF_TENANT_ID,
		Code:          uuid.NewV4().String(),
		Host:          wafHostAddReq.Host,
		Port:          wafHostAddReq.Port,
		Ssl:           wafHostAddReq.Ssl,
		GUARD_STATUS:  0,
		REMOTE_SYSTEM: wafHostAddReq.REMOTE_SYSTEM,
		REMOTE_APP:    wafHostAddReq.REMOTE_APP,
		Remote_host:   wafHostAddReq.Remote_host,
		Remote_port:   wafHostAddReq.Remote_port,
		Certfile:      wafHostAddReq.Certfile,
		Keyfile:       wafHostAddReq.Keyfile,
		REMARKS:       wafHostAddReq.REMARKS,
		CREATE_TIME:   time.Now(),
		UPDATE_TIME:   time.Now(),
	}
	global.GWAF_LOCAL_DB.Create(wafHost)
	return nil
}

func (receiver *WafHostService) CheckIsExistApi(wafHostAddReq request.WafHostAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.Hosts{}, "host = ? and port= ?", wafHostAddReq.Host, wafHostAddReq.Port).Error
}
func (receiver *WafHostService) ModifyApi(wafHostEditReq request.WafHostEditReq) error {
	var webHost model.Hosts
	global.GWAF_LOCAL_DB.Where("host = ? and port= ?", wafHostEditReq.Host, wafHostEditReq.Port).Find(&webHost)
	if webHost.Id != 0 && webHost.Code != wafHostEditReq.CODE {
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
		"REMOTE_SYSTEM": wafHostEditReq.REMOTE_SYSTEM,
		"REMOTE_APP":    wafHostEditReq.REMOTE_APP,
		"Remote_host":   wafHostEditReq.Remote_host,
		"Remote_port":   wafHostEditReq.Remote_port,
		"REMARKS":       wafHostEditReq.REMARKS,

		"Certfile":    wafHostEditReq.Certfile,
		"Keyfile":     wafHostEditReq.Keyfile,
		"UPDATE_TIME": time.Now(),
	}
	err := global.GWAF_LOCAL_DB.Model(model.Hosts{}).Where("CODE=?", wafHostEditReq.CODE).Updates(hostMap).Error

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
func (receiver *WafHostService) GetListApi(wafHostSearchReq request.WafHostSearchReq) ([]model.Hosts, int64, error) {
	var webHosts []model.Hosts
	var total int64 = 0
	global.GWAF_LOCAL_DB.Limit(wafHostSearchReq.PageSize).Offset(wafHostSearchReq.PageSize * (wafHostSearchReq.PageIndex - 1)).Order("global_host desc").Find(&webHosts)
	global.GWAF_LOCAL_DB.Model(&model.Hosts{}).Count(&total)
	return webHosts, total, nil
}
func (receiver *WafHostService) DelHostApi(req request.WafHostDelReq) error {
	var webhost model.Hosts
	err := global.GWAF_LOCAL_DB.Where("CODE = ?", req.CODE).First(&webhost).Error
	if webhost.GLOBAL_HOST == 1 {
		return errors.New("全局网站不允许单独删除")
	}
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("CODE = ?", req.CODE).Delete(model.Hosts{}).Error
	//删除规则
	err = global.GWAF_LOCAL_DB.Where("HostCode = ?", req.CODE).Delete(model.Rules{}).Error
	//删除Anticc
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.AntiCC{}).Error
	//删除禁用ip
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.IPBlockList{}).Error
	//删除禁用url
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.URLBlockList{}).Error
	//删除隐私保护url
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.LDPUrl{}).Error
	//删除白名单ip
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.IPWhiteList{}).Error
	//删除白名单URL
	err = global.GWAF_LOCAL_DB.Where("Host_Code = ?", req.CODE).Delete(model.URLWhiteList{}).Error
	return err
}
func (receiver *WafHostService) ModifyGuardStatusApi(req request.WafHostGuardStatusReq) error {
	hostMap := map[string]interface{}{
		"GUARD_STATUS": req.GUARD_STATUS,
		"UPDATE_TIME":  time.Now(),
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
