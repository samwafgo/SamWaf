package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

type WafSqlQueryApi struct {
}

func (w *WafSqlQueryApi) ExecuteQueryApi(c *gin.Context) {
	response.FailWithMessage("该接口已禁用", c)
}

func (w *WafSqlQueryApi) GetTableInfoApi(c *gin.Context) {
	response.FailWithMessage("该接口已禁用", c)
}
