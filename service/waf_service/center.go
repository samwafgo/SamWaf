package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	uuid "github.com/satori/go.uuid"
	"time"
)

type CenterService struct{}

var CenterServiceApp = new(CenterService)

func (receiver *CenterService) AddApi(req request.CenterClientUpdateReq) error {
	var bean = &model.Center{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		ClientServerName:     req.ClientServerName,
		ClientUserCode:       req.ClientUserCode,
		ClientTenantId:       req.ClientTenantId,
		ClientToken:          req.ClientToken,
		ClientSsl:            req.ClientSsl,
		ClientIP:             req.ClientIP,
		ClientPort:           req.ClientPort,
		ClientNewVersion:     req.ClientNewVersion,
		ClientNewVersionDesc: req.ClientNewVersionDesc,
		ClientSystemType:     req.ClientSystemType,
		LastVisitTime:        customtype.JsonTime(time.Now()),
		Remarks:              "",
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *CenterService) CheckIsExistApi(req request.CenterClientUpdateReq) error {
	return global.GWAF_LOCAL_DB.First(&model.Center{}, "client_user_code = ? and client_tenant_id= ?",
		req.ClientUserCode, req.ClientTenantId).Error
}
func (receiver *CenterService) ModifyApi(req request.CenterClientUpdateReq) error {
	var bean model.Center
	global.GWAF_LOCAL_DB.Where("client_user_code = ? and client_tenant_id= ?",
		req.ClientUserCode, req.ClientTenantId).Find(&bean)
	beanMap := map[string]interface{}{
		"ClientServerName":     req.ClientServerName,
		"ClientSsl":            req.ClientSsl,
		"ClientToken":          req.ClientToken,
		"ClientIP":             req.ClientIP,
		"ClientPort":           req.ClientPort,
		"ClientNewVersion":     req.ClientNewVersion,
		"ClientNewVersionDesc": req.ClientNewVersionDesc,
		"ClientSystemType":     req.ClientSystemType,
		"LastVisitTime":        customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.Center{}).Where("client_user_code = ? and client_tenant_id= ?",
		req.ClientUserCode, req.ClientTenantId).Updates(beanMap).Error

	return err
}
func (receiver *CenterService) GetDetailApi(req request.CenterClientDetailReq) model.Center {
	var bean model.Center
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *CenterService) GetDetailByIdApi(id string) model.Center {
	var bean model.Center
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *CenterService) GetDetailByTencentUserCode(clientTenantId, clientUserCode string) model.Center {
	var bean model.Center
	global.GWAF_LOCAL_DB.Where("client_tenant_id  = ? and client_user_code= ?", clientTenantId, clientUserCode).Find(&bean)
	return bean
}

func (receiver *CenterService) GetListApi(req request.CenterClientSearchReq) ([]model.Center, int64, error) {
	var list []model.Center
	var total int64 = 0

	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""
	/*if len(req.HostCode) > 0 {
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
	}*/

	global.GWAF_LOCAL_DB.Model(&model.Center{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.Center{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}

func (receiver *CenterService) CountApi() (int64, error) {

	var total int64 = 0

	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""
	global.GWAF_LOCAL_DB.Model(&model.Center{}).Where(whereField, whereValues...).Count(&total)

	return total, nil
}
