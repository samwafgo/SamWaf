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

type WafBlockingPageService struct{}

var WafBlockingPageServiceApp = new(WafBlockingPageService)

func (receiver *WafBlockingPageService) AddApi(req request.WafBlockingPageAddReq) error {
	var bean = &model.BlockingPage{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},

		BlockingPageName: req.BlockingPageName,
		BlockingType:     req.BlockingType,
		HostCode:         req.HostCode,
		ResponseCode:     req.ResponseCode,
		ResponseHeader:   req.ResponseHeader,
		ResponseContent:  req.ResponseContent,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafBlockingPageService) CheckIsExistApi(req request.WafBlockingPageAddReq) int {
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.BlockingType) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " blocking_type=? "
	}

	if len(req.HostCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " host_code=? "
	}

	// 对于 other_block 类型，需要检查 response_code 的唯一性
	// 同一个网站下，相同的 blocking_type + response_code 组合必须唯一
	if len(req.ResponseCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " response_code=? "
	}

	//where字段赋值

	if len(req.BlockingType) > 0 {
		if len(whereField) > 0 {
			whereValues = append(whereValues, req.BlockingType)
		}
	}

	if len(req.HostCode) > 0 {
		if len(whereField) > 0 {
			whereValues = append(whereValues, req.HostCode)
		}
	}

	if len(req.ResponseCode) > 0 {
		if len(whereField) > 0 {
			whereValues = append(whereValues, req.ResponseCode)
		}
	}

	global.GWAF_LOCAL_DB.Model(&model.BlockingPage{}).Where(whereField, whereValues...).Count(&total)
	return int(total)
}

func (receiver *WafBlockingPageService) ModifyApi(req request.WafBlockingPageEditReq) error {
	// 根据唯一字段生成查询条件（只有在UniFields不为空时才进行存在性检查）

	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.BlockingType) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " blocking_type=? "
	}

	if len(req.HostCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " host_code=? "
	}

	// 对于 other_block 类型，需要检查 response_code 的唯一性
	// 同一个网站下，相同的 blocking_type + response_code 组合必须唯一
	if len(req.ResponseCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " response_code=? "
	}

	//where字段赋值

	if len(req.BlockingType) > 0 {
		whereValues = append(whereValues, req.BlockingType)
	}

	if len(req.HostCode) > 0 {
		whereValues = append(whereValues, req.HostCode)
	}

	if len(req.ResponseCode) > 0 {
		whereValues = append(whereValues, req.ResponseCode)
	}

	global.GWAF_LOCAL_DB.Model(&model.BlockingPage{}).Where(whereField, whereValues...).Count(&total)
	// 查询是否已存在记录
	var bean model.BlockingPage
	global.GWAF_LOCAL_DB.Model(&model.BlockingPage{}).Where(whereField, whereValues...).Limit(1).Find(&bean)

	if int(total) > 0 && bean.Id != "" && bean.Id != req.Id {
		return errors.New("当前记录已经存在")
	}

	beanMap := map[string]interface{}{

		"BlockingPageName": req.BlockingPageName,
		"BlockingType":     req.BlockingType,
		"HostCode":         req.HostCode,
		"ResponseCode":     req.ResponseCode,
		"ResponseHeader":   req.ResponseHeader,
		"ResponseContent":  req.ResponseContent,

		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.BlockingPage{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}
func (receiver *WafBlockingPageService) GetDetailApi(req request.WafBlockingPageDetailReq) model.BlockingPage {
	var bean model.BlockingPage
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafBlockingPageService) GetDetailByIdApi(id string) model.BlockingPage {
	var bean model.BlockingPage
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafBlockingPageService) GetListApi(req request.WafBlockingPageSearchReq) ([]model.BlockingPage, int64, error) {
	var list []model.BlockingPage
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.BlockingPage{}).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.BlockingPage{}).Count(&total)

	return list, total, nil
}
func (receiver *WafBlockingPageService) DelApi(req request.WafBlockingPageDelReq) error {
	var bean model.BlockingPage
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.BlockingPage{}).Error
	return err
}
