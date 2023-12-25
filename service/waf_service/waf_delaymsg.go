package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	uuid "github.com/satori/go.uuid"
	"time"
)

type WafDelayMsgService struct{}

var WafDelayMsgServiceApp = new(WafDelayMsgService)

func (receiver *WafDelayMsgService) Add(DelayType, DelayTile, DelayContent string) error {
	var bean = &model.DelayMsg{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		DelayType:    DelayType,
		DelayTile:    DelayTile,
		DelayContent: DelayContent,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}
func (receiver *WafDelayMsgService) GetAllList() ([]model.DelayMsg, int64, error) {
	var ipWhites []model.DelayMsg
	var total int64 = 0
	global.GWAF_LOCAL_DB.Find(&ipWhites)
	global.GWAF_LOCAL_DB.Model(&model.DelayMsg{}).Count(&total)
	return ipWhites, total, nil
}
func (receiver *WafDelayMsgService) DelApi(id string) error {
	var bean model.DelayMsg
	err := global.GWAF_LOCAL_DB.Where("id = ?", id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", id).Delete(model.DelayMsg{}).Error
	return err
}
