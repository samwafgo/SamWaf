package model

import "SamWaf/model/baseorm"

type Sensitive struct {
	baseorm.BaseOrm
	CheckDirection string `gorm:"size:50" json:"check_direction"` //敏感词检测方向 in ,out ,all
	Action         string `gorm:"size:50" json:"action"`          //敏感词检测后动作 deny,replace
	Content        string `gorm:"type:text" json:"content"`       //内容
	Remarks        string `gorm:"size:500" json:"remarks"`        //备注
}
