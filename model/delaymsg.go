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
	DelayType    string `gorm:"size:50" json:"delay_type"`      //操作类型
	DelayTile    string `gorm:"size:255" json:"delay_title"`    //操作标题
	DelayContent string `gorm:"type:text" json:"delay_content"` //操作内容
}
