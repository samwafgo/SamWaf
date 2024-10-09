package request

import "SamWaf/model/common/request"

type SslConfigAddReq struct {
	CertContent string `json:"cert_content" form:"cert_content"` // 证书文件内容
	KeyContent  string `json:"key_content" form:"key_content"`   // 密钥文件内容
}
type SslConfigEditReq struct {
	Id          string `json:"id"`
	CertContent string `json:"cert_content" form:"cert_content"` // 证书文件内容
	KeyContent  string `json:"key_content" form:"key_content"`   // 密钥文件内容
}
type SslConfigDetailReq struct {
	Id string `json:"id"`
}
type SslConfigDeleteReq struct {
	Id string `json:"id"`
}
type SslConfigSearchReq struct {
	Domains string `json:"domains"` // 证书适用的域名
	request.PageInfo
}
