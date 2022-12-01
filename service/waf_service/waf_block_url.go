package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"errors"
	uuid "github.com/satori/go.uuid"
	"time"
)

type WafBlockUrlService struct{}

var WafBlockUrlServiceApp = new(WafBlockUrlService)

func (receiver *WafBlockUrlService) AddApi(req request.WafBlockUrlAddReq) error {
	var bean = &model.URLBlockList{
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

func (receiver *WafBlockUrlService) CheckIsExistApi(req request.WafBlockUrlAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.URLBlockList{}, "host_code = ? and url= ?", req.HostCode,
		req.Url).Error
}
func (receiver *WafBlockUrlService) ModifyApi(req request.WafBlockUrlEditReq) error {
	var bean model.URLBlockList
	global.GWAF_LOCAL_DB.Debug().Where("host_code = ? and url= ?", req.HostCode,
		req.Url).Find(&bean)
	if bean.Id != "" && bean.Url != req.Url {
		return errors.New("当前网站和url已经存在")
	}
	modfiyMap := map[string]interface{}{
		"Host_Code":        req.HostCode,
		"Url":              req.Url,
		"Remarks":          req.Remarks,
		"last_update_time": time.Now(),
	}
	err := global.GWAF_LOCAL_DB.Debug().Model(model.URLBlockList{}).Where("id = ?", req.Id).Updates(modfiyMap).Error

	return err
}
func (receiver *WafBlockUrlService) GetDetailApi(req request.WafBlockUrlDetailReq) model.URLBlockList {
	var bean model.URLBlockList
	global.GWAF_LOCAL_DB.Debug().Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafBlockUrlService) GetDetailByIdApi(id string) model.URLBlockList {
	var bean model.URLBlockList
	global.GWAF_LOCAL_DB.Debug().Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafBlockUrlService) GetListApi(req request.WafBlockUrlSearchReq) ([]model.URLBlockList, int64, error) {
	var ipWhites []model.URLBlockList
	var total int64 = 0
	global.GWAF_LOCAL_DB.Debug().Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&ipWhites)
	global.GWAF_LOCAL_DB.Debug().Model(&model.URLBlockList{}).Count(&total)
	return ipWhites, total, nil
}
func (receiver *WafBlockUrlService) DelApi(req request.WafBlockUrlDelReq) error {
	var bean model.URLBlockList
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.URLBlockList{}).Error
	return err
}
