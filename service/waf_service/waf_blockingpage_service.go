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
		AttackType:       req.AttackType,
		HostCode:         req.HostCode,
		ResponseCode:     req.ResponseCode,
		ResponseHeader:   req.ResponseHeader,
		ResponseContent:  req.ResponseContent,
		ContentPriority:  req.ContentPriority,
	}
	return global.GWAF_LOCAL_DB.Create(bean).Error
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
	if req.BlockingType != "not_match_website" && len(req.ResponseCode) > 0 {
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

	if req.BlockingType != "not_match_website" && len(req.ResponseCode) > 0 {
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
	if req.BlockingType != "not_match_website" && len(req.ResponseCode) > 0 {
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

	if req.BlockingType != "not_match_website" && len(req.ResponseCode) > 0 {
		whereValues = append(whereValues, req.ResponseCode)
	}

	err := global.GWAF_LOCAL_DB.Model(&model.BlockingPage{}).Where(whereField, whereValues...).Where("id <> ?", req.Id).Count(&total).Error
	if err != nil {
		return err
	}
	if total > 0 {
		return errors.New("当前记录已经存在")
	}

	beanMap := map[string]interface{}{

		"BlockingPageName": req.BlockingPageName,
		"BlockingType":     req.BlockingType,
		"AttackType":       req.AttackType,
		"HostCode":         req.HostCode,
		"ResponseCode":     req.ResponseCode,
		"ResponseHeader":   req.ResponseHeader,
		"ResponseContent":  req.ResponseContent,
		"ContentPriority":  req.ContentPriority,

		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err = global.GWAF_LOCAL_DB.Model(model.BlockingPage{}).Where("id = ?", req.Id).Updates(beanMap).Error

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
	query := global.GWAF_LOCAL_DB.Model(&model.BlockingPage{})
	if req.HostCode != "" {
		query = query.Where("host_code = ?", req.HostCode)
	}
	if req.BlockingType != "" {
		query = query.Where("blocking_type = ?", req.BlockingType)
	} else {
		// 主列表只维护通用拦截模板；全局未匹配网站的专用记录由独立入口管理
		query = query.Where("blocking_type <> ? OR blocking_type IS NULL", "not_match_website")
	}
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	err := query.Order("update_time DESC, id DESC").Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list).Error
	return list, total, err
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
