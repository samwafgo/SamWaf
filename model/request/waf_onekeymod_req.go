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

// WafParseNginxReq 解析 nginx 配置为待添加主机候选
type WafParseNginxReq struct {
	Source   string `json:"source"`    //来源: "text" 粘贴文本 | "scan" 扫描目录
	Content  string `json:"content"`   //source=text 时的粘贴内容
	FilePath string `json:"file_path"` //source=scan 时的目录
}
