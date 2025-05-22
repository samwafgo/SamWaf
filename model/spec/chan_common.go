package spec

type ChanCommonHost struct {
	HostCode   string
	Type       int
	Content    interface{}
	OldContent interface{}
}

// ChanCommon 通用通道
type ChanCommon struct {
	Type       int         //某种类型 1 比如代表隧道
	OpType     int         //操作类型 1代表新增 2代表删除 3代表修改
	Content    interface{} //新增的内容
	OldContent interface{} //修改前的内容
}
