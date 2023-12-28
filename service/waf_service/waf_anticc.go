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

type WafAntiCCService struct{}

var WafAntiCCServiceApp = new(WafAntiCCService)

func (receiver *WafAntiCCService) AddApi(req request.WafAntiCCAddReq) error {
	var bean = &model.AntiCC{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode: req.HostCode,
		Rate:     req.Rate,
		Limit:    req.Limit,
		Url:      req.Url,
		Remarks:  req.Remarks,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafAntiCCService) CheckIsExistApi(req request.WafAntiCCAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.AntiCC{}, "host_code = ? and url= ?", req.HostCode,
		req.Url).Error
}
func (receiver *WafAntiCCService) ModifyApi(req request.WafAntiCCEditReq) error {
	var ipWhite model.AntiCC
	global.GWAF_LOCAL_DB.Where("host_code = ? and url= ?", req.HostCode,
		req.Url).Find(&ipWhite)
	if ipWhite.Id != "" && ipWhite.Url != req.Url {
		return errors.New("当前网站和url已经存在")
	}
	ipWhiteMap := map[string]interface{}{
		"Host_Code":   req.HostCode,
		"Url":         req.Url,
		"Rate":        req.Rate,
		"Limit":       req.Limit,
		"Remarks":     req.Remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.AntiCC{}).Where("id = ?", req.Id).Updates(ipWhiteMap).Error

	return err
}
func (receiver *WafAntiCCService) GetDetailApi(req request.WafAntiCCDetailReq) model.AntiCC {
	var bean model.AntiCC
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafAntiCCService) GetDetailByIdApi(id string) model.AntiCC {
	var bean model.AntiCC
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafAntiCCService) GetListApi(req request.WafAntiCCSearchReq) ([]model.AntiCC, int64, error) {
	var list []model.AntiCC
	var total int64 = 0

	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""
	if len(req.HostCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " host_code=? "
	}
	if len(req.Url) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " url =? "
	}
	//where字段赋值
	if len(req.HostCode) > 0 {
		whereValues = append(whereValues, req.HostCode)
	}
	if len(req.Url) > 0 {
		whereValues = append(whereValues, req.Url)
	}

	global.GWAF_LOCAL_DB.Model(&model.AntiCC{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.AntiCC{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafAntiCCService) DelApi(req request.WafAntiCCDelReq) error {
	var ipWhite model.AntiCC
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&ipWhite).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.AntiCC{}).Error
	return err
}
