package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type SqlQueryRouter struct {
}

func (receiver *SqlQueryRouter) InitSqlQueryRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafSqlQueryApi
	router := group.Group("")
	router.POST("/samwaf/sql_query/execute", api.ExecuteQueryApi)
}
