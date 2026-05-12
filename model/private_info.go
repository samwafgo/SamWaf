package model

import "SamWaf/model/baseorm"

type PrivateInfo struct {
	baseorm.BaseOrm
	PrivateKey              string `gorm:"size:255" json:"private_key"`                //密钥key
	PrivateValue            string `gorm:"type:text" json:"private_value"`             //密钥值
	PrivateGroupName        string `gorm:"size:255" json:"private_group_name"`         //分组名称
	PrivateGroupBelongCloud string `gorm:"size:100" json:"private_group_belong_cloud"` //分组归属云
	Remarks                 string `gorm:"size:500" json:"remarks"`                    //备注
}
