package request

import "SamWaf/model/common/request"

type WafOneKeyModDelReq struct {
	Id string `json:"id"  form:"id"`
}

type WafOneKeyModRestoreReq struct {
	Id string `json:"id"  form:"id"`
}
type WafOneKeyModDetailReq struct {
	Id string `json:"id"  form:"id"`
}
type WafOneKeyModSearchReq struct {
	request.PageInfo
}
type WafDoOneKeyModReq struct {
	FilePath string `json:"file_path"` //文件所在路径
}
