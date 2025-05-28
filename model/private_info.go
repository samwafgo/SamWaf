package model

import "SamWaf/model/baseorm"

type PrivateInfo struct {
	baseorm.BaseOrm
	PrivateKey              string `json:"private_key"`                //密钥key
	PrivateValue            string `json:"private_value"`              //密钥值
	PrivateGroupName        string `json:"private_group_name"`         //分组名称
	PrivateGroupBelongCloud string `json:"private_group_belong_cloud"` //分组归属云
	Remarks                 string `json:"remarks"`                    //备注
}
