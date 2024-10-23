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
	IsSystem  string `json:"is_system"`  //是否是系统值
	ItemClass string `json:"item_class"` //所属分类
	Item      string `json:"item"`
	Value     string `json:"value"`
	ItemType  string `json:"item_type"` //配置类型 普通字符串，可选项
	Options   string `json:"options"`   //如果ItemType == 可选项 这个地方有数据
	HashInfo  string `json:"hash_info"`
	Remarks   string `json:"remarks"` //备注
}
