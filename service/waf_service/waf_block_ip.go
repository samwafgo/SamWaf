package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"errors"
	uuid "github.com/satori/go.uuid"
	"time"
)

type WafBlockIpService struct{}

var WafBlockIpServiceApp = new(WafBlockIpService)

func (receiver *WafBlockIpService) AddApi(req request.WafBlockIpAddReq) error {
	var bean = &model.IPBlockList{
		UserCode:       global.GWAF_USER_CODE,
		TenantId:       global.GWAF_TENANT_ID,
		Id:             uuid.NewV4().String(),
		HostCode:       req.HostCode,
		Ip:             req.Ip,
		Remarks:        req.Remarks,
		CreateTime:     time.Now(),
		LastUpdateTime: time.Now(),
	}
	global.GWAF_LOCAL_DB.Debug().Create(bean)
	return nil
}

func (receiver *WafBlockIpService) CheckIsExistApi(req request.WafBlockIpAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.IPBlockList{}, "host_code = ? and ip= ?", req.HostCode,
		req.Ip).Error
}
func (receiver *WafBlockIpService) ModifyApi(req request.WafBlockIpEditReq) error {
	var ipWhite model.IPBlockList
	global.GWAF_LOCAL_DB.Debug().Where("host_code = ? and ip= ?", req.HostCode,
		req.Ip).Find(&ipWhite)
	if ipWhite.Id != "" && ipWhite.Ip != req.Ip {
		return errors.New("当前网站和IP已经存在")
	}
	ipWhiteMap := map[string]interface{}{
		"Host_Code":        req.HostCode,
		"Ip":               req.Ip,
		"Remarks":          req.Remarks,
		"last_update_time": time.Now(),
	}
	err := global.GWAF_LOCAL_DB.Debug().Model(model.IPBlockList{}).Where("id = ?", req.Id).Updates(ipWhiteMap).Error

	return err
}
func (receiver *WafBlockIpService) GetDetailApi(req request.WafBlockIpDetailReq) model.IPBlockList {
	var bean model.IPBlockList
	global.GWAF_LOCAL_DB.Debug().Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafBlockIpService) GetDetailByIdApi(id string) model.IPBlockList {
	var bean model.IPBlockList
	global.GWAF_LOCAL_DB.Debug().Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafBlockIpService) GetListApi(req request.WafBlockIpSearchReq) ([]model.IPBlockList, int64, error) {
	var list []model.IPBlockList
	var total int64 = 0
	global.GWAF_LOCAL_DB.Debug().Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Debug().Model(&model.IPBlockList{}).Count(&total)
	return list, total, nil
}
func (receiver *WafBlockIpService) DelApi(req request.WafBlockIpDelReq) error {
	var bean model.IPBlockList
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.IPBlockList{}).Error
	return err
}
