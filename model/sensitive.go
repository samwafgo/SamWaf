package model

import "SamWaf/model/baseorm"

type Sensitive struct {
	baseorm.BaseOrm
	CheckDirection string `json:"check_direction"` //敏感词检测方向 in ,out ,all
	Action         string `json:"action"`          //敏感词检测后动作 deny,replace
	Content        string `json:"content"`         //内容
	Remarks        string `json:"remarks"`         //备注
}
