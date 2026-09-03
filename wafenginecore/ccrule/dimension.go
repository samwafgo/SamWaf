package ccrule

import (
	"SamWaf/innerbean"
	"SamWaf/model"
	"net/http"
	"strings"
)

// hostTotalDimValue 站点总量维度的固定取值：整站共用一个计数桶。
const hostTotalDimValue = "__host_total__"

// DimValue 取出本次请求在该规则统计维度下的归堆取值。
//
// 返回的 fellBack 表示维度字段取不到值、已回退按客户端 IP 统计。
// 这一步不能省：把所有「没带这个字段」的访客归到同一个空取值上，
// 会让他们共用一个计数桶，一个人触发阈值就把整批正常访客一起挡住。
func (cr *CompiledRule) DimValue(r *http.Request, log *innerbean.WebLog, clientIP string) (value string, fellBack bool) {
	switch cr.Rule.StatDim {
	case model.CCStatDimHostTotal:
		return hostTotalDimValue, false

	case model.CCStatDimIPURI:
		return clientIP + "|" + r.URL.Path, false

	case model.CCStatDimHeader:
		if v := strings.TrimSpace(r.Header.Get(cr.Rule.StatDimField)); v != "" {
			return v, false
		}

	case model.CCStatDimCookie, model.CCStatDimSession:
		name := cr.Rule.StatDimField
		if name == "" {
			name = "SESSION"
		}
		if ck, err := r.Cookie(name); err == nil {
			if v := strings.TrimSpace(ck.Value); v != "" {
				return v, false
			}
		}

	case model.CCStatDimQuery:
		if v := strings.TrimSpace(r.URL.Query().Get(cr.Rule.StatDimField)); v != "" {
			return v, false
		}

	case model.CCStatDimBody:
		if vs := bodyFieldValues(log, cr.Rule.StatDimField); len(vs) > 0 {
			if v := strings.TrimSpace(vs[0]); v != "" {
				return v, false
			}
		}
	}

	// 含 CCStatDimIP 与所有取不到值的情况
	if cr.Rule.StatDim == model.CCStatDimIP {
		return clientIP, false
	}
	return clientIP, true
}
