package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"errors"
	uuid "github.com/satori/go.uuid"
	"time"
)

type WafLdpUrlService struct{}

var WafLdpUrlServiceApp = new(WafLdpUrlService)

func (receiver *WafLdpUrlService) AddApi(req request.WafLdpUrlAddReq) error {
	var bean = &model.LDPUrl{
		UserCode:       global.GWAF_USER_CODE,
		TenantId:       global.GWAF_TENANT_ID,
		Id:             uuid.NewV4().String(),
		HostCode:       req.HostCode,
		CompareType:    req.CompareType,
		Url:            req.Url,
		Remarks:        req.Remarks,
		CreateTime:     time.Now(),
		LastUpdateTime: time.Now(),
	}
	global.GWAF_LOCAL_DB.Debug().Create(bean)
	return nil
}

func (receiver *WafLdpUrlService) CheckIsExistApi(req request.WafLdpUrlAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.LDPUrl{}, "host_code = ? and url= ?", req.HostCode,
		req.Url).Error
}
func (receiver *WafLdpUrlService) ModifyApi(req request.WafLdpUrlEditReq) error {
	var ipWhite model.LDPUrl
	global.GWAF_LOCAL_DB.Debug().Where("host_code = ? and url= ?", req.HostCode,
		req.Url).Find(&ipWhite)
	if ipWhite.Id != "" && ipWhite.Url != req.Url {
		return errors.New("当前网站和url已经存在")
	}
	ipWhiteMap := map[string]interface{}{
		"Host_Code":        req.HostCode,
		"Url":              req.Url,
		"Remarks":          req.Remarks,
		"Compare_Type":     req.CompareType,
		"last_update_time": time.Now(),
	}
	err := global.GWAF_LOCAL_DB.Debug().Model(model.LDPUrl{}).Where("id = ?", req.Id).Updates(ipWhiteMap).Error

	return err
}
func (receiver *WafLdpUrlService) GetDetailApi(req request.WafLdpUrlDetailReq) model.LDPUrl {
	var bean model.LDPUrl
	global.GWAF_LOCAL_DB.Debug().Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafLdpUrlService) GetListApi(req request.WafLdpUrlSearchReq) ([]model.LDPUrl, int64, error) {
	var ipWhites []model.LDPUrl
	var total int64 = 0
	global.GWAF_LOCAL_DB.Debug().Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&ipWhites)
	global.GWAF_LOCAL_DB.Debug().Model(&model.LDPUrl{}).Count(&total)
	return ipWhites, total, nil
}
func (receiver *WafLdpUrlService) DelApi(req request.WafLdpUrlDelReq) error {
	var ipWhite model.LDPUrl
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&ipWhite).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.LDPUrl{}).Error
	return err
}
