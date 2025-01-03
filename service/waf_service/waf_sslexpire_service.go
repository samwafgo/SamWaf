package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/model/response"
	"errors"
	uuid "github.com/satori/go.uuid"
	"time"
)

type WafSslExpireService struct{}

var WafSslExpireServiceApp = new(WafSslExpireService)

func (receiver *WafSslExpireService) AddApi(req request.WafSslExpireAddReq) error {
	var bean = &model.SslExpire{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},

		Domain:   req.Domain,
		Port:     req.Port,
		VisitLog: req.VisitLog,
		Status:   req.Status,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafSslExpireService) Add(domain string, port int) error {
	var bean = &model.SslExpire{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},

		Domain: domain,
		Port:   port,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafSslExpireService) CheckIsExistApi(req request.WafSslExpireAddReq) int {
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.Domain) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " domain=? "
	}

	if req.Port > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " port=? "
	}

	//where字段赋值
	if len(req.Domain) > 0 {
		whereValues = append(whereValues, req.Domain)
	}
	if req.Port > 0 {
		whereValues = append(whereValues, req.Port)
	}
	global.GWAF_LOCAL_DB.Model(&model.SslExpire{}).Where(whereField, whereValues...).Count(&total)
	return int(total)
}

func (receiver *WafSslExpireService) CheckIsExist(domain string, port int) int {
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(domain) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " domain=? "
	}

	if port > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " port=? "
	}

	//where字段赋值
	if len(domain) > 0 {
		whereValues = append(whereValues, domain)
	}
	if port > 0 {
		whereValues = append(whereValues, port)
	}
	global.GWAF_LOCAL_DB.Model(&model.SslExpire{}).Where(whereField, whereValues...).Count(&total)
	return int(total)
}

func (receiver *WafSslExpireService) ModifyApi(req request.WafSslExpireEditReq) error {
	// 根据唯一字段生成查询条件（只有在UniFields不为空时才进行存在性检查）

	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.Domain) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " domain=? "
	}

	if req.Port > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " port=? "
	}

	//where字段赋值
	if len(req.Domain) > 0 {
		whereValues = append(whereValues, req.Domain)
	}
	if req.Port > 0 {
		whereValues = append(whereValues, req.Port)
	}
	global.GWAF_LOCAL_DB.Model(&model.SslExpire{}).Where(whereField, whereValues...).Count(&total)
	// 查询是否已存在记录
	var bean model.SslExpire
	global.GWAF_LOCAL_DB.Model(&model.SslExpire{}).Where(whereField, whereValues...).Limit(1).Find(&bean)

	if int(total) > 0 && bean.Id != "" && bean.Id != req.Id {
		return errors.New("当前记录已经存在")
	}

	beanMap := map[string]interface{}{

		"Domain":   req.Domain,
		"Port":     req.Port,
		"VisitLog": req.VisitLog,
		"Status":   req.Status,

		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.SslExpire{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}

func (receiver *WafSslExpireService) Modify(req model.SslExpire) error {

	beanMap := map[string]interface{}{
		"Domain":      req.Domain,
		"Port":        req.Port,
		"VisitLog":    req.VisitLog,
		"Status":      req.Status,
		"ValidTo":     req.ValidTo,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.SslExpire{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}
func (receiver *WafSslExpireService) GetDetailApi(req request.WafSslExpireDetailReq) model.SslExpire {
	var bean model.SslExpire
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafSslExpireService) GetDetailByIdApi(id string) model.SslExpire {
	var bean model.SslExpire
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafSslExpireService) GetListApi(req request.WafSslExpireSearchReq) ([]response.WafSslCheckRep, int64, error) {
	var list []model.SslExpire
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.SslExpire{}).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Order("valid_to asc").Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.SslExpire{}).Count(&total)

	var repList []response.WafSslCheckRep

	for _, sslCheckBean := range list {

		rep := response.WafSslCheckRep{
			SslExpire:      sslCheckBean,
			ExpirationInfo: sslCheckBean.ExpirationMessage(),
			ExpirationDay:  sslCheckBean.ExpirationDay(),
		}
		repList = append(repList, rep)
	}
	return repList, total, nil
}

func (receiver *WafSslExpireService) GetAllList() ([]model.SslExpire, int64, error) {
	var list []model.SslExpire
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.SslExpire{}).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.SslExpire{}).Count(&total)

	return list, total, nil
}
func (receiver *WafSslExpireService) DelApi(req request.WafSslExpireDelReq) error {
	var bean model.SslExpire
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.SslExpire{}).Error
	return err
}
