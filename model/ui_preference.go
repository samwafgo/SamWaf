package model

import "SamWaf/model/baseorm"

// UIPreference 管理端界面偏好（按登录账号归属），如访问日志的列配置
// 注意：字段命名有意避开 waf_sql_query 的敏感规则——
// 表名不含 config/account，列名不用 value/params（会触发整表封禁）、不用 pref_key（key 会被剥列）
type UIPreference struct {
	baseorm.BaseOrm
	LoginAccount string `gorm:"size:100;index" json:"login_account"` //归属登录账号
	PrefName     string `gorm:"size:100;index" json:"pref_name"`     //偏好名，如 visit_log_columns
	PrefJson     string `gorm:"type:text" json:"pref_json"`          //偏好内容(JSON字符串)
}
