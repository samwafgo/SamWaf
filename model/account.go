package model

import "time"

type Account struct {
	Id             string    `gorm:"primary_key" json:"id"`
	UserCode       string    `json:"user_code"`        //用户码（主要键）
	TenantId       string    `json:"tenant_id"`        //租户ID（主要键）
	LoginAccount   string    `json:"login_account"`    //登录账号
	LoginPassword  string    `json:"login_password"`   //密码md5加密
	Status         int       `json:"status"`           //状态
	Remarks        string    `json:"remarks"`          //备注
	CreateTime     time.Time `json:"create_time"`      //创建时间
	LastUpdateTime time.Time `json:"last_update_time"` //上次更新时间
}

type AccountLog struct {
	Id           string    `gorm:"primary_key" json:"id"`
	UserCode     string    `json:"user_code"`     //用户码（主要键）
	TenantId     string    `json:"tenant_id"`     //租户ID（主要键）
	LoginAccount string    `json:"login_account"` //登录账号
	OpType       string    `json:"op_type"`       //操作类型
	OpContent    string    `json:"op_content"`    //操作内容
	CreateTime   time.Time `json:"create_time"`   //创建时间
}
type TokenInfo struct {
	Id             string    `gorm:"primary_key" json:"id"`
	UserCode       string    `json:"user_code"`        //用户码（主要键）
	TenantId       string    `json:"tenant_id"`        //租户ID（主要键）
	LoginAccount   string    `json:"login_account"`    //登录账号
	LoginIp        string    `json:"login_ip"`         //登录IP
	AccessToken    string    `json:"access_token"`     //访问码
	CreateTime     time.Time `json:"create_time"`      //创建时间
	LastUpdateTime time.Time `json:"last_update_time"` //上次更新时间
}
