package model

import "SamWaf/model/baseorm"

type Sensitive struct {
	baseorm.BaseOrm
	Type    int    `json:"type"`    //敏感词类型
	Content string `json:"content"` //内容
	Remarks string `json:"remarks"` //备注
}
