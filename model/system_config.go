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
	IsSystem  string `gorm:"size:10" json:"is_system"`   //是否是系统值
	ItemClass string `gorm:"size:100" json:"item_class"` //所属分类
	Item      string `gorm:"size:255" json:"item"`
	Value     string `gorm:"type:text" json:"value"`
	ItemType  string `gorm:"size:50" json:"item_type"` //配置类型 普通字符串，可选项
	Options   string `gorm:"type:text" json:"options"` //如果ItemType == 可选项 这个地方有数据
	HashInfo  string `gorm:"size:255" json:"hash_info"`
	Remarks   string `gorm:"size:500" json:"remarks"` //备注
}
