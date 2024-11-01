package request

import "SamWaf/model/common/request"

type SslConfigAddReq struct {
	CertContent string `json:"cert_content" form:"cert_content"` // 证书文件内容
	KeyContent  string `json:"key_content" form:"key_content"`   // 密钥文件内容
	KeyPath     string `json:"key_path"`                         //密钥文件位置
	CertPath    string `json:"cert_path"`                        //crt文件配置
}
type SslConfigEditReq struct {
	Id          string `json:"id"`
	CertContent string `json:"cert_content" form:"cert_content"` // 证书文件内容
	KeyContent  string `json:"key_content" form:"key_content"`   // 密钥文件内容
	KeyPath     string `json:"key_path"`                         //密钥文件位置
	CertPath    string `json:"cert_path"`                        //crt文件配置
}
type SslConfigDetailReq struct {
	Id string `json:"id"   form:"id"`
}
type SslConfigDeleteReq struct {
	Id string `json:"id"   form:"id"`
}
type SslConfigSearchReq struct {
	Domains string `json:"domains"` // 证书适用的域名
	request.PageInfo
}
