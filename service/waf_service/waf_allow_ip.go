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

type WafWhiteIpService struct{}

var WafWhiteIpServiceApp = new(WafWhiteIpService)

func (receiver *WafWhiteIpService) AddApi(wafWhiteIpAddReq request.WafAllowIpAddReq) error {
	var wafHost = &model.IPAllowList{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode: wafWhiteIpAddReq.HostCode,
		Ip:       wafWhiteIpAddReq.Ip,
		Remarks:  wafWhiteIpAddReq.Remarks,
	}
	global.GWAF_LOCAL_DB.Create(wafHost)
	return nil
}

func (receiver *WafWhiteIpService) CheckIsExistApi(wafWhiteIpAddReq request.WafAllowIpAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.IPAllowList{}, "host_code = ? and ip= ?", wafWhiteIpAddReq.HostCode,
		wafWhiteIpAddReq.Ip).Error
}
func (receiver *WafWhiteIpService) ModifyApi(wafWhiteIpEditReq request.WafAllowIpEditReq) error {
	var ipWhite model.IPAllowList
	global.GWAF_LOCAL_DB.Where("host_code = ? and ip= ?", wafWhiteIpEditReq.HostCode,
		wafWhiteIpEditReq.Ip).Find(&ipWhite)
	if ipWhite.Id != "" && ipWhite.Ip != wafWhiteIpEditReq.Ip {
		return errors.New("当前网站和IP已经存在")
	}
	ipWhiteMap := map[string]interface{}{
		"Host_Code":   wafWhiteIpEditReq.HostCode,
		"Ip":          wafWhiteIpEditReq.Ip,
		"Remarks":     wafWhiteIpEditReq.Remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.IPAllowList{}).Where("id = ?", wafWhiteIpEditReq.Id).Updates(ipWhiteMap).Error

	return err
}
func (receiver *WafWhiteIpService) GetDetailApi(req request.WafAllowIpDetailReq) model.IPAllowList {
	var ipWhite model.IPAllowList
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&ipWhite)
	return ipWhite
}
func (receiver *WafWhiteIpService) GetDetailByIdApi(id string) model.IPAllowList {
	var ipWhite model.IPAllowList
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&ipWhite)
	return ipWhite
}
func (receiver *WafWhiteIpService) GetDetailByIPApi(ip string, hostCode string) model.IPAllowList {
	var ipWhite model.IPAllowList
	global.GWAF_LOCAL_DB.Where("ip=? and host_code=?", ip, hostCode).Find(&ipWhite)
	return ipWhite
}
func (receiver *WafWhiteIpService) GetListApi(req request.WafAllowIpSearchReq) ([]model.IPAllowList, int64, error) {
	var ipWhites []model.IPAllowList
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
	if len(req.Ip) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " ip =? "
	}
	//where字段赋值
	if len(req.HostCode) > 0 {
		whereValues = append(whereValues, req.HostCode)
	}
	if len(req.Ip) > 0 {
		whereValues = append(whereValues, req.Ip)
	}

	global.GWAF_LOCAL_DB.Model(&model.IPAllowList{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&ipWhites)
	global.GWAF_LOCAL_DB.Model(&model.IPAllowList{}).Where(whereField, whereValues...).Count(&total)

	return ipWhites, total, nil
}
func (receiver *WafWhiteIpService) DelApi(req request.WafAllowIpDelReq) error {
	var ipWhite model.IPAllowList
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&ipWhite).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.IPAllowList{}).Error
	return err
}
