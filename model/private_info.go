package model

import "SamWaf/model/baseorm"

type PrivateInfo struct {
	baseorm.BaseOrm
	PrivateKey   string `json:"private_key"`   //密钥key
	PrivateValue string `json:"private_value"` //密钥值
	Remarks      string `json:"remarks"`       //备注
}
