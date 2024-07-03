package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
)

type WafOneKeyModService struct{}

var WafOneKeyModServiceApp = new(WafOneKeyModService)

func (receiver *WafOneKeyModService) GetDetailApi(req request.WafOneKeyModDetailReq) model.OneKeyMod {
	var bean model.OneKeyMod
	global.GWAF_LOCAL_LOG_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafOneKeyModService) GetListApi(req request.WafOneKeyModSearchReq) ([]model.OneKeyMod, int64, error) {
	var list []model.OneKeyMod
	var total int64 = 0

	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	global.GWAF_LOCAL_LOG_DB.Model(&model.OneKeyMod{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Order("create_time desc").Find(&list)
	global.GWAF_LOCAL_LOG_DB.Model(&model.OneKeyMod{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafOneKeyModService) DelApi(req request.WafOneKeyModDelReq) error {
	var bean model.OneKeyMod
	err := global.GWAF_LOCAL_LOG_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_LOG_DB.Where("id = ?", req.Id).Delete(model.OneKeyMod{}).Error
	return err
}
