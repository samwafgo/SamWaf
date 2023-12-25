package model

import (
	"SamWaf/model/baseorm"
)

/*
*
延迟信息
*/
type DelayMsg struct {
	baseorm.BaseOrm
	DelayType    string `json:"delay_type"`    //操作类型
	DelayTile    string `json:"delay_title"`   //操作标题
	DelayContent string `json:"delay_content"` //操作内容
}
