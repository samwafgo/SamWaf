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
	router.POST("/api/v1/sql_query/execute", api.ExecuteQueryApi)
	router.GET("/api/v1/sql_query/table_info", api.GetTableInfoApi)
}
