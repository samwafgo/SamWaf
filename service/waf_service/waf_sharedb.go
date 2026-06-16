package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/wafdb/dialect"
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

// 获取所有db（按当前驱动过滤分片类型）
// 历史遗留：share_dbs 表会同时存在 SQLite 文件分片(local_log*.db)与 MySQL 表分片(web_logs*)，
// 用户切换驱动后另一种分片对当前库无意义，这里按 ShareDb.IsTableShard() 与当前驱动是否文件型过滤：
//   - SQLite(文件型) 只保留文件分片(.db)
//   - MySQL(非文件型) 只保留表分片(无 .db 后缀)
func (receiver *WafShareDbService) GetAllShareDbApi() ([]model.ShareDb, error) {
	var all []model.ShareDb
	global.GWAF_LOCAL_DB.Model(&model.ShareDb{}).Find(&all)

	fileBased := dialect.Get().IsFileBased()
	list := make([]model.ShareDb, 0, len(all))
	for _, s := range all {
		// 文件型驱动保留非表分片(.db)，非文件型驱动保留表分片
		if s.IsTableShard() != fileBased {
			list = append(list, s)
		}
	}
	return list, nil
}
