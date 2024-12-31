package response

import "SamWaf/customtype"

type AllHostRep struct {
	Code string `json:"value"` //唯一码
	Host string `json:"label"` //域名
}

type AllShareDbRep struct {
	StartTime customtype.JsonTime `json:"start_time"` //开始时间
	EndTime   customtype.JsonTime `json:"end_time"`   //结束时间
	FileName  string              `json:"file_name"`  //文件名
	Cnt       int64               `json:"cnt"`        //当前数量
}

// AllDomainRep 域名信息
type AllDomainRep struct {
	Code string `json:"value"` //唯一码
	Host string `json:"label"` //域名
}
