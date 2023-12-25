package model

import (
	"SamWaf/model/baseorm"
)

type WafSysLog struct {
	baseorm.BaseOrm
	OpType    string `json:"op_type"`    //操作类型
	OpContent string `json:"op_content"` //操作内容
}
