package innerbean

import "net/http"

type ServerRunTime struct {
	//tcp http https
	ServerType string
	Port       int
	Status     int
	Svr        *http.Server
}
