package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/service/waf_service"
	"SamWaf/wafconfig"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

func normalizeAdminTitle(title string) (string, error) {
	if !utf8.ValidString(title) {
		return "", fmt.Errorf("标题必须是有效 UTF-8 文本")
	}
	for _, r := range title {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return "", fmt.Errorf("标题必须为单行文本且不能包含控制字符")
		}
	}
	title = strings.TrimSpace(title)
	if utf8.RuneCountInString(title) > 100 {
		return "", fmt.Errorf("标题不能超过100个字符")
	}
	return title, nil
}

func (w *WafVpConfigApi) GetAdminTitlesApi(c *gin.Context) {
	titles := (waf_service.WafAdminTitlesService{}).Get()
	response.OkWithDetailed(response2.WafVpConfigAdminTitlesGetResp{
		AdminTitle: titles.AdminTitle,
	}, "获取成功", c)
}

func (w *WafVpConfigApi) UpdateAdminTitlesApi(c *gin.Context) {
	var req request.WafVpConfigAdminTitlesUpdateReq
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024))
	var fields map[string]json.RawMessage
	if err != nil || !utf8.Valid(body) || json.Unmarshal(body, &fields) != nil || len(fields) != 1 {
		response.FailWithMessage("解析请求失败", c)
		return
	}
	value, ok := fields["admin_title"]
	if !ok || string(value) == "null" || json.Unmarshal(body, &req) != nil {
		response.FailWithMessage("解析请求失败", c)
		return
	}
	adminTitle, err := normalizeAdminTitle(req.AdminTitle)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	if err := (waf_service.WafAdminTitlesService{}).Update(wafconfig.AdminTitles{
		AdminTitle: adminTitle,
	}); err != nil {
		response.FailWithMessage("更新管理端标题失败", c)
		return
	}
	w.GetAdminTitlesApi(c)
}
