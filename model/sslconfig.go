package model

type Sslconfig struct {
	Id        int    `gorm:"primary_key" json:" - "` //
	Tenant_id string `json:"tenant_id"`              //
	Code      string `json:"code"`                   //
	Certfile  string `json:"certfile"`               //
	Keyfile   string `json:"keyfile"`                //
}
