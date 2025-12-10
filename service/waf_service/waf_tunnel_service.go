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

type WafTunnelService struct{}

var WafTunnelServiceApp = new(WafTunnelService)

func (receiver *WafTunnelService) AddApi(req request.WafTunnelAddReq) (*model.Tunnel, error) {
	var bean = &model.Tunnel{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},

		Code:              req.Code,
		Name:              req.Name,
		Port:              req.Port,
		Protocol:          req.Protocol,
		RemotePort:        req.RemotePort,
		RemoteIp:          req.RemoteIp,
		AllowIp:           req.AllowIp,
		DenyIp:            req.DenyIp,
		StartStatus:       req.StartStatus,
		ConnTimeout:       req.ConnTimeout,
		ReadTimeout:       req.ReadTimeout,
		WriteTimeout:      req.WriteTimeout,
		MaxInConnect:      req.MaxInConnect,
		MaxOutConnect:     req.MaxOutConnect,
		AllowedTimeRanges: req.AllowedTimeRanges,
		Remark:            req.Remark,
	}
	if bean.Code == "" {
		bean.Code = bean.Id
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return bean, nil
}

func (receiver *WafTunnelService) CheckIsExistApi(req request.WafTunnelAddReq) int {
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.Name) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " name=? "
	}

	//where字段赋值

	if len(req.Name) > 0 {
		if len(whereField) > 0 {
			whereValues = append(whereValues, req.Name)
		}
	}

	global.GWAF_LOCAL_DB.Model(&model.Tunnel{}).Where(whereField, whereValues...).Count(&total)
	return int(total)
}

func (receiver *WafTunnelService) ModifyApi(req request.WafTunnelEditReq) error {
	// 根据唯一字段生成查询条件（只有在UniFields不为空时才进行存在性检查）

	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.Name) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " name=? "
	}

	//where字段赋值

	if len(req.Name) > 0 {
		whereValues = append(whereValues, req.Name)
	}

	global.GWAF_LOCAL_DB.Model(&model.Tunnel{}).Where(whereField, whereValues...).Count(&total)
	// 查询是否已存在记录
	var bean model.Tunnel
	global.GWAF_LOCAL_DB.Model(&model.Tunnel{}).Where(whereField, whereValues...).Limit(1).Find(&bean)

	if int(total) > 0 && bean.Id != "" && bean.Id != req.Id {
		return errors.New("当前记录已经存在")
	}

	beanMap := map[string]interface{}{

		"Code":              req.Code,
		"Name":              req.Name,
		"Port":              req.Port,
		"Protocol":          req.Protocol,
		"RemotePort":        req.RemotePort,
		"RemoteIp":          req.RemoteIp,
		"AllowIp":           req.AllowIp,
		"DenyIp":            req.DenyIp,
		"StartStatus":       req.StartStatus,
		"ConnTimeout":       req.ConnTimeout,
		"ReadTimeout":       req.ReadTimeout,
		"WriteTimeout":      req.WriteTimeout,
		"MaxInConnect":      req.MaxInConnect,
		"MaxOutConnect":     req.MaxOutConnect,
		"AllowedTimeRanges": req.AllowedTimeRanges,
		"Remark":            req.Remark,

		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.Tunnel{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}
func (receiver *WafTunnelService) GetDetailApi(req request.WafTunnelDetailReq) model.Tunnel {
	var bean model.Tunnel
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafTunnelService) GetDetailByIdApi(id string) model.Tunnel {
	var bean model.Tunnel
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafTunnelService) GetListApi(req request.WafTunnelSearchReq) ([]model.Tunnel, int64, error) {
	var list []model.Tunnel
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.Tunnel{}).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.Tunnel{}).Count(&total)

	return list, total, nil
}
func (receiver *WafTunnelService) DelApi(req request.WafTunnelDelReq) error {
	var bean model.Tunnel
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.Tunnel{}).Error
	return err
}

// GetTunnelConnections 获取隧道连接信息
func (receiver *WafTunnelService) GetTunnelConnections(id string) (model.Tunnel, error) {
	var tunnel model.Tunnel
	err := global.GWAF_LOCAL_DB.Where("id = ?", id).First(&tunnel).Error
	if err != nil {
		return model.Tunnel{}, err
	}

	return tunnel, nil
}
