package innerbean

import "net/http"

type ServerRunTime struct {
	//tcp http https
	ServerType string
	Port       int
	Status     int // 0 是启动完成 ，1 是新增，2 是编辑 3，是删除
	Svr        *http.Server
}
