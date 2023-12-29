package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
)

type WafShareDbService struct{}

var WafShareDbServiceApp = new(WafShareDbService)

func (receiver *WafShareDbService) AddApi(shareDb model.ShareDb) error {
	global.GWAF_LOCAL_DB.Create(shareDb)
	return nil
}

func (receiver *WafShareDbService) GetListApi(req request.WafShareDbReq) ([]model.ShareDb, int64, error) {
	var list []model.ShareDb
	var total int64 = 0

	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	//where字段赋值

	global.GWAF_LOCAL_DB.Model(&model.ShareDb{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.ShareDb{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}

// 获取所有db
func (receiver *WafShareDbService) GetAllShareDbApi() ([]model.ShareDb, error) {
	var list []model.ShareDb
	global.GWAF_LOCAL_DB.Model(&model.ShareDb{}).Find(&list)

	return list, nil
}
