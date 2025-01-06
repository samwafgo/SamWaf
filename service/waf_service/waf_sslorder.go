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

type WafSSLOrderService struct{}

var WafSSLOrderServiceApp = new(WafSSLOrderService)

func (receiver *WafSSLOrderService) AddApi(req request.WafSslorderaddReq) (model.SslOrder, error) {
	var bean = &model.SslOrder{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode:      req.HostCode,
		ApplyPlatform: req.ApplyPlatform,
		ApplyMethod:   req.ApplyMethod,
		ApplyDns:      req.ApplyDns,
		ApplyDomain:   req.ApplyDomain,
		ApplyEmail:    req.ApplyEmail,
		ApplyStatus:   "submitted",
	}
	global.GWAF_LOCAL_DB.Create(bean)

	return *bean, nil
}

func (receiver *WafSSLOrderService) ModifyApi(req request.WafSslordereditReq) error {

	sslOrderMap := map[string]interface{}{
		"HostCode":      req.HostCode,
		"ApplyPlatform": req.ApplyPlatform,
		"ApplyMethod":   req.ApplyMethod,
		"ApplyDns":      req.ApplyDns,
		"ApplyDomain":   req.ApplyDomain,
		"ApplyEmail":    req.ApplyEmail,
		"ApplyStatus":   req.ApplyStatus,
		"UPDATE_TIME":   customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.SslOrder{}).Where("id = ?", req.Id).Updates(sslOrderMap).Error

	return err
}
func (receiver *WafSSLOrderService) GetDetailApi(req request.WafSslorderdetailReq) model.SslOrder {
	return receiver.GetDetailById(req.Id)
}
func (receiver *WafSSLOrderService) GetListApi(req request.WafSslordersearchReq) ([]model.SslOrder, int64, error) {
	var list []model.SslOrder
	var total int64 = 0

	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	//where字段
	if len(req.HostCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " host_code =? "
	}

	//where字段赋值
	if len(req.HostCode) > 0 {
		whereValues = append(whereValues, req.HostCode)
	}

	/**排序*/
	orderInfo := "create_time desc"

	global.GWAF_LOCAL_DB.Model(&model.SslOrder{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Order(orderInfo).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.SslOrder{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafSSLOrderService) DelApi(req request.WafSslorderdeleteReq) error {
	var bean model.SslOrder
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.SslOrder{}).Error
	return err
}
func (receiver *WafSSLOrderService) GetDetailById(id string) model.SslOrder {
	var bean model.SslOrder
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafSSLOrderService) ModifyById(sslOrder model.SslOrder) error {

	sslOrderMap := map[string]interface{}{
		"HostCode":                sslOrder.HostCode,
		"ApplyPlatform":           sslOrder.ApplyPlatform,
		"ApplyMethod":             sslOrder.ApplyMethod,
		"ApplyDns":                sslOrder.ApplyDns,
		"ApplyDomain":             sslOrder.ApplyDomain,
		"ApplyEmail":              sslOrder.ApplyEmail,
		"ApplyStatus":             sslOrder.ApplyStatus,
		"ApplyKey":                sslOrder.ApplyKey,
		"ResultDomain":            sslOrder.ResultDomain,
		"ResultCertURL":           sslOrder.ResultCertURL,
		"ResultCertStableURL":     sslOrder.ResultCertStableURL,
		"ResultPrivateKey":        sslOrder.ResultPrivateKey,
		"ResultCertificate":       sslOrder.ResultCertificate,
		"ResultIssuerCertificate": sslOrder.ResultIssuerCertificate,
		"ResultCSR":               sslOrder.ResultCSR,
		"ResultValidTo":           sslOrder.ResultValidTo,
		"ResultError":             sslOrder.ResultError,
		"UPDATE_TIME":             customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.SslOrder{}).Where("id = ?", sslOrder.Id).Updates(sslOrderMap).Error

	return err
}

// RenewAdd续期
func (receiver *WafSSLOrderService) RenewAdd(orderId string) (model.SslOrder, error) {

	order := receiver.GetDetailById(orderId)
	var bean = &model.SslOrder{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode:                order.HostCode,
		ApplyPlatform:           order.ApplyPlatform,
		ApplyMethod:             order.ApplyMethod,
		ApplyDns:                order.ApplyDns,
		ApplyDomain:             order.ApplyDomain,
		ApplyEmail:              order.ApplyEmail,
		ApplyKey:                order.ApplyKey,
		ApplyStatus:             "submitted",
		ResultDomain:            order.ResultDomain,
		ResultCertURL:           order.ResultCertURL,
		ResultCertStableURL:     order.ResultCertStableURL,
		ResultPrivateKey:        order.ResultPrivateKey,
		ResultCertificate:       order.ResultCertificate,
		ResultIssuerCertificate: order.ResultIssuerCertificate,
		ResultCSR:               order.ResultCSR,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return *bean, nil
}

// GetLastedInfo 查询最新的没有过期的
func (receiver *WafSSLOrderService) GetLastedInfo(hostCode string) (model.SslOrder, error) {
	var bean model.SslOrder

	global.GWAF_LOCAL_DB.Model(&model.SslOrder{}).Where("host_code=?", hostCode).Where("result_certificate is not null").Order("create_time desc").Limit(1).First(&bean)

	return bean, nil
}
