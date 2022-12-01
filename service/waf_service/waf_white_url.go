package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"errors"
	uuid "github.com/satori/go.uuid"
	"time"
)

type WafWhiteUrlService struct{}

var WafWhiteUrlServiceApp = new(WafWhiteUrlService)

func (receiver *WafWhiteUrlService) AddApi(req request.WafWhiteUrlAddReq) error {
	var bean = &model.URLWhiteList{
		UserCode:       global.GWAF_USER_CODE,
		TenantId:       global.GWAF_TENANT_ID,
		Id:             uuid.NewV4().String(),
		HostCode:       req.HostCode,
		Url:            req.Url,
		Remarks:        req.Remarks,
		CreateTime:     time.Now(),
		LastUpdateTime: time.Now(),
	}
	global.GWAF_LOCAL_DB.Debug().Create(bean)
	return nil
}

func (receiver *WafWhiteUrlService) CheckIsExistApi(req request.WafWhiteUrlAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.URLWhiteList{}, "host_code = ? and url= ?", req.HostCode,
		req.Url).Error
}
func (receiver *WafWhiteUrlService) ModifyApi(req request.WafWhiteUrlEditReq) error {
	var ipWhite model.URLWhiteList
	global.GWAF_LOCAL_DB.Debug().Where("host_code = ? and url= ?", req.HostCode,
		req.Url).Find(&ipWhite)
	if ipWhite.Id != "" && ipWhite.Url != req.Url {
		return errors.New("当前网站和url已经存在")
	}
	ipWhiteMap := map[string]interface{}{
		"Host_Code":        req.HostCode,
		"Url":              req.Url,
		"Remarks":          req.Remarks,
		"last_update_time": time.Now(),
	}
	err := global.GWAF_LOCAL_DB.Debug().Model(model.URLWhiteList{}).Where("id = ?", req.Id).Updates(ipWhiteMap).Error

	return err
}
func (receiver *WafWhiteUrlService) GetDetailApi(req request.WafWhiteUrlDetailReq) model.URLWhiteList {
	var bean model.URLWhiteList
	global.GWAF_LOCAL_DB.Debug().Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafWhiteUrlService) GetDetailByIdApi(id string) model.URLWhiteList {
	var bean model.URLWhiteList
	global.GWAF_LOCAL_DB.Debug().Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafWhiteUrlService) GetListApi(req request.WafWhiteUrlSearchReq) ([]model.URLWhiteList, int64, error) {
	var ipWhites []model.URLWhiteList
	var total int64 = 0
	global.GWAF_LOCAL_DB.Debug().Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&ipWhites)
	global.GWAF_LOCAL_DB.Debug().Model(&model.URLWhiteList{}).Count(&total)
	return ipWhites, total, nil
}
func (receiver *WafWhiteUrlService) DelApi(req request.WafWhiteUrlDelReq) error {
	var ipWhite model.URLWhiteList
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&ipWhite).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.URLWhiteList{}).Error
	return err
}
