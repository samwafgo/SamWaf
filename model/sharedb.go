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
	DbLogicType string              `gorm:"size:50" json:"db_logic_type"` //数据库逻辑类型  默认："log"
	StartTime   customtype.JsonTime `json:"start_time"`                   //开始时间
	EndTime     customtype.JsonTime `json:"end_time"`                     //结束时间
	FileName    string              `gorm:"size:255" json:"file_name"`    //文件名：SQLite 下为 .db 文件名；MySQL 下为表名（无后缀）
	Cnt         int64               `json:"cnt"`                          //当前数量
	PeriodKey   string              `gorm:"size:16" json:"period_key"`    //周期键（月，如 202609）。按体积切出来的旧分片为空
}

// IsPeriodShard 返回 true 表示这是按时间周期切出来的分区（M3），
// false 表示按行数/体积切出来的旧分片——两者的时间范围都记在 StartTime/EndTime 里，
// 区别只在「名字能不能算出周期」以及界面上怎么标。
func (s ShareDb) IsPeriodShard() bool {
	return s.PeriodKey != ""
}

// IsTableShard 在 MySQL/SQL Server 模式下返回 true（FileName 存的是表名而非文件名）
func (s ShareDb) IsTableShard() bool {
	suffix := ".db"
	return !strings.HasSuffix(s.FileName, suffix)
}
