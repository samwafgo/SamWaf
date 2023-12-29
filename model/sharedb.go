package model

import (
	"SamWaf/customtype"
	"SamWaf/model/baseorm"
)

/*
*
分库
*/
type ShareDb struct {
	baseorm.BaseOrm
	DbLogicType string              `json:"db_logic_type"` //数据库逻辑类型  默认：”log“
	StartTime   customtype.JsonTime `json:"start_time"`    //开始时间
	EndTime     customtype.JsonTime `json:"end_time"`      //结束时间
	FileName    string              `json:"file_name"`     //文件名
	Cnt         int64               `json:"cnt"`           //当前数量
}
