package model

import (
	"SamWaf/customtype"
	"SamWaf/model/baseorm"
	"strings"
)

/*
*
分库
*/
type ShareDb struct {
	baseorm.BaseOrm
	DbLogicType string              `json:"db_logic_type"` //数据库逻辑类型  默认："log"
	StartTime   customtype.JsonTime `json:"start_time"`    //开始时间
	EndTime     customtype.JsonTime `json:"end_time"`      //结束时间
	FileName    string              `json:"file_name"`     //文件名：SQLite 下为 .db 文件名；MySQL 下为表名（无后缀）
	Cnt         int64               `json:"cnt"`           //当前数量
}

// IsTableShard 在 MySQL/SQL Server 模式下返回 true（FileName 存的是表名而非文件名）
func (s ShareDb) IsTableShard() bool {
	suffix := ".db"
	return !strings.HasSuffix(s.FileName, suffix)
}
