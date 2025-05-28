package model

import "SamWaf/model/baseorm"

type PrivateGroup struct {
	baseorm.BaseOrm
	PrivateGroupName        string `json:"private_group_name"`         //分组名称
	PrivateGroupBelongCloud string `json:"private_group_belong_cloud"` //分组归属云
}
