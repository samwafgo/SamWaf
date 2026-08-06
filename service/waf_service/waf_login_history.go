package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"time"
)

// loginHistoryKeepPerAccount 每个账号最多保留的登录历史条数
//
// 登录历史是「给人看的最近几次记录」，不是长期审计流水（长期审计另有 sys_log），
// 定长裁剪可以让这张表的体积和登录频率脱钩，不至于把日志库撑大。
const loginHistoryKeepPerAccount = 200

type WafLoginHistoryService struct{}

var WafLoginHistoryServiceApp = new(WafLoginHistoryService)

// AddApi 记录一次登录历史（登录成功后调用）
//
// 任何失败都只记日志、不打断登录：写审计流水失败不应该把用户挡在门外。
func (receiver *WafLoginHistoryService) AddApi(bean model.LoginHistory) {
	if global.GWAF_LOCAL_LOG_DB == nil {
		return
	}
	bean.BaseOrm = baseorm.BaseOrm{
		Id:          uuid.GenUUID(),
		USER_CODE:   global.GWAF_USER_CODE,
		Tenant_ID:   global.GWAF_TENANT_ID,
		CREATE_TIME: customtype.JsonTime(time.Now()),
		UPDATE_TIME: customtype.JsonTime(time.Now()),
	}
	if err := global.GWAF_LOCAL_LOG_DB.Create(&bean).Error; err != nil {
		zlog.Warn("记录登录历史失败", "error", err.Error())
		return
	}
	receiver.trim(bean.LoginAccount)
}

// trim 裁剪单个账号的历史，只保留最近 loginHistoryKeepPerAccount 条
func (receiver *WafLoginHistoryService) trim(loginAccount string) {
	var total int64
	global.GWAF_LOCAL_LOG_DB.Model(&model.LoginHistory{}).Where("login_account = ?", loginAccount).Count(&total)
	if total <= loginHistoryKeepPerAccount {
		return
	}
	var olds []model.LoginHistory
	global.GWAF_LOCAL_LOG_DB.Where("login_account = ?", loginAccount).
		Order("create_time desc").
		Offset(loginHistoryKeepPerAccount).Limit(int(total) - loginHistoryKeepPerAccount).
		Find(&olds)
	for _, o := range olds {
		global.GWAF_LOCAL_LOG_DB.Where("id = ?", o.Id).Delete(model.LoginHistory{})
	}
}

// GetListApi 分页查询登录历史（按时间倒序）
//
// 账号名走 GORM 参数化查询，不拼 SQL。
func (receiver *WafLoginHistoryService) GetListApi(req request.WafLoginHistorySearchReq) ([]model.LoginHistory, int64, error) {
	var beans []model.LoginHistory
	var total int64 = 0

	whereField := ""
	var whereValues []interface{}
	if req.LoginAccount != "" {
		whereField = "login_account = ?"
		whereValues = append(whereValues, req.LoginAccount)
	}
	if req.LoginIp != "" {
		if whereField != "" {
			whereField += " and "
		}
		whereField += "login_ip = ?"
		whereValues = append(whereValues, req.LoginIp)
	}
	// is_changed 入参用字符串："" 不过滤，"0"/"1" 才是真实取值
	// （用 int 的话零值 0 和"没传"分不开，会把不过滤变成只看未变化的记录）
	// 绑定时转回 int：Postgres 下拿字符串比整型列会撞类型不匹配。
	if req.IsChanged == "0" || req.IsChanged == "1" {
		if whereField != "" {
			whereField += " and "
		}
		whereField += "is_changed = ?"
		changed := 0
		if req.IsChanged == "1" {
			changed = 1
		}
		whereValues = append(whereValues, changed)
	}

	db := global.GWAF_LOCAL_LOG_DB.Model(&model.LoginHistory{})
	if whereField != "" {
		db = db.Where(whereField, whereValues...)
	}
	if err := db.Count(&total).Error; err != nil {
		return beans, 0, err
	}

	query := global.GWAF_LOCAL_LOG_DB.Model(&model.LoginHistory{})
	if whereField != "" {
		query = query.Where(whereField, whereValues...)
	}
	err := query.Order("create_time desc").
		Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).
		Find(&beans).Error
	return beans, total, err
}
