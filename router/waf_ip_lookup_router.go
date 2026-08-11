package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type IPLookupRouter struct {
}

func (receiver *IPLookupRouter) InitIPLookupRouter(group *gin.RouterGroup) {
	apiObj := api.APIGroupAPP.WafIPLookupApi
	router := group.Group("")

	router.GET("/api/v1/wafhost/ip/lookup", apiObj.LookupApi) // 查一个IP落在哪些名单里
}
