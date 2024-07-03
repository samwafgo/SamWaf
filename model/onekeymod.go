package model

import "SamWaf/model/baseorm"

/*
*
一键修改备份
*/
type OneKeyMod struct {
	baseorm.BaseOrm
	OpSystem      string `json:"op_system"`      //系统类型
	FilePath      string `json:"file_path"`      //文件路径
	BeforeContent string `json:"before_content"` //修改前内容
	AfterContent  string `json:"after_content"`  //修改后内容
	Remarks       string `json:"remarks"`        //备注
}
