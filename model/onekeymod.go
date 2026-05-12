package model

import "SamWaf/model/baseorm"

/*
*
一键修改备份
*/
type OneKeyMod struct {
	baseorm.BaseOrm
	OpSystem      string `gorm:"size:50" json:"op_system"`        //系统类型
	FilePath      string `gorm:"size:500" json:"file_path"`       //文件路径
	BeforeContent string `gorm:"type:text" json:"before_content"` //修改前内容
	AfterContent  string `gorm:"type:text" json:"after_content"`  //修改后内容
	IsRestore     int    `json:"is_restore"`                      //是否还原
	Remarks       string `gorm:"size:500" json:"remarks"`         //备注
}
