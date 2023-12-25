package model

import (
	"SamWaf/model/baseorm"
)

/*
*
系统配置
*/
type SystemConfig struct {
	baseorm.BaseOrm
	IsSystem string `json:"is_system"` //是否是系统值
	Item     string `json:"item"`
	Value    string `json:"value"`
	HashInfo string `json:"hash_info"`
	Remarks  string `json:"remarks"` //备注
}
