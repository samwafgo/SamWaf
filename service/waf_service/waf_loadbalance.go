package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"errors"
	"time"
)

type WafLoadBalanceService struct{}

var WafLoadBalanceServiceApp = new(WafLoadBalanceService)

func (receiver *WafLoadBalanceService) AddApi(req request.WafLoadBalanceAddReq) error {
	var addBean = &model.LoadBalance{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode:    req.HostCode,
		Remote_ip:   req.Remote_ip,
		Remote_port: req.Remote_port,
		Weight:      req.Weight,
		Remarks:     req.Remarks,
	}
	global.GWAF_LOCAL_DB.Create(addBean)
	return nil
}

func (receiver *WafLoadBalanceService) CheckIsExistApi(req request.WafLoadBalanceAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.LoadBalance{}, "host_code = ? and remote_ip= ? and remote_port= ?", req.HostCode,
		req.Remote_ip, req.Remote_port).Error
}
func (receiver *WafLoadBalanceService) ModifyApi(req request.WafLoadBalanceEditReq) error {
	var editBean model.LoadBalance
	global.GWAF_LOCAL_DB.Where("host_code = ? and remote_ip= ? and remote_port= ?", req.HostCode,
		req.Remote_ip, req.Remote_port).Find(&editBean)
	if editBean.Id != "" && editBean.Remote_ip != editBean.Remote_ip && editBean.Remote_port != editBean.Remote_port {
		return errors.New("当前网站和IP已经存在")
	}
	editMap := map[string]interface{}{
		"Host_Code":   req.HostCode,
		"Remote_Ip":   req.Remote_ip,
		"Remote_Port": req.Remote_port,
		"Weight":      req.Weight,
		"Remarks":     req.Remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.LoadBalance{}).Where("id = ?", req.Id).Updates(editMap).Error

	return err
}
func (receiver *WafLoadBalanceService) GetDetailApi(req request.WafLoadBalanceDetailReq) model.LoadBalance {
	var bean model.LoadBalance
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafLoadBalanceService) GetDetailByIdApi(id string) model.LoadBalance {
	var bean model.LoadBalance
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafLoadBalanceService) GetListApi(req request.WafLoadBalanceSearchReq) ([]model.LoadBalance, int64, error) {
	var list []model.LoadBalance
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
	if len(req.Remote_ip) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " remote_ip =? "
	}
	if req.Remote_port > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " remote_port =? "
	}
	//where字段赋值
	if len(req.HostCode) > 0 {
		whereValues = append(whereValues, req.HostCode)
	}
	if len(req.Remote_ip) > 0 {
		whereValues = append(whereValues, req.Remote_ip)
	}
	if req.Remote_port > 0 {
		whereValues = append(whereValues, req.Remote_port)
	}

	global.GWAF_LOCAL_DB.Model(&model.LoadBalance{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.LoadBalance{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafLoadBalanceService) DelApi(req request.WafLoadBalanceDelReq) error {
	var bean model.LoadBalance
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.LoadBalance{}).Error
	return err
}

// GetListByHostCodeApi 通过主机码获取负载信息
func (receiver *WafLoadBalanceService) GetListByHostCodeApi(hostCode string) []model.LoadBalance {
	var list []model.LoadBalance
	global.GWAF_LOCAL_DB.Where("host_code = ?", hostCode).Order("create_time asc").Find(&list)
	return list
}
