package waftunnelmodel

type NetRunTime struct {
	//tcp udp
	ServerType string
	Port       int
	Status     int         // 0 是启动完成 ，1 是新增，2 是编辑 3，是删除
	Svr        interface{} // 支持任何网络连接类型
}
