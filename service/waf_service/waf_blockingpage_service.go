package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"gorm.io/gorm"
)

type WafBlockingPageService struct{}

var WafBlockingPageServiceApp = new(WafBlockingPageService)

func (receiver *WafBlockingPageService) AddApi(req request.WafBlockingPageAddReq) error {
	id := uuid.GenUUID()
	if req.BlockingType == model.BlockingPageTypeBackendUnavailable {
		// 固定主键由数据库保证同一全局站点并发新建时只保存一条。
		sum := sha256.Sum256([]byte(req.BlockingType + ":" + req.HostCode))
		id = hex.EncodeToString(sum[:])
	}
	var bean = &model.BlockingPage{
		BaseOrm: baseorm.BaseOrm{
			Id:          id,
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

func matchingBlockingPages(blockingType, hostCode, responseCode string) *gorm.DB {
	query := global.GWAF_LOCAL_DB.Model(&model.BlockingPage{})
	if blockingType != "" {
		query = query.Where("blocking_type = ?", blockingType)
	}
	if hostCode != "" {
		query = query.Where("host_code = ?", hostCode)
	}
	if responseCode != "" && blockingType != model.BlockingPageTypeUnmatchedHost && blockingType != model.BlockingPageTypeBackendUnavailable {
		query = query.Where("response_code = ?", responseCode)
	}
	return query
}

func (receiver *WafBlockingPageService) CheckIsExistApi(req request.WafBlockingPageAddReq) int {
	var total int64
	matchingBlockingPages(req.BlockingType, req.HostCode, req.ResponseCode).Count(&total)
	return int(total)
}

func (receiver *WafBlockingPageService) ModifyApi(req request.WafBlockingPageEditReq) error {
	var total int64
	err := matchingBlockingPages(req.BlockingType, req.HostCode, req.ResponseCode).Where("id <> ?", req.Id).Count(&total).Error
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
		query = query.Where("blocking_type NOT IN ? OR blocking_type IS NULL", []string{
			model.BlockingPageTypeUnmatchedHost, model.BlockingPageTypeBackendUnavailable,
		})
	}
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	err := query.Order("update_time DESC, id DESC").Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list).Error
	return list, total, err
}
func (receiver *WafBlockingPageService) LoadBlockingPageMap(hostCode string) map[string]model.BlockingPage {
	var pages []model.BlockingPage
	global.GWAF_LOCAL_DB.Where("host_code = ?", hostCode).Order("update_time ASC, id ASC").Find(&pages)
	result := make(map[string]model.BlockingPage)
	for _, page := range pages {
		switch page.BlockingType {
		case model.BlockingPageTypeUnmatchedHost:
			result[page.BlockingType] = page
		case model.BlockingPageTypeBackendUnavailable:
			if hostCode == global.GWAF_GLOBAL_HOST_CODE {
				result[page.BlockingType] = page
			}
		case model.BlockingPageTypeOther:
			switch page.ResponseCode {
			case "", model.BlockingPageTypeUnmatchedHost, model.BlockingPageTypeBackendUnavailable:
			default:
				result[page.ResponseCode] = page
			}
		}
	}
	return result
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
