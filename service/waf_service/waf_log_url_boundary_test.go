package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"strconv"
	"testing"
)

func TestLogURLKeywordLiteralBoundaries(t *testing.T) {
	_, live, _ := setupLogLookupTest(t)
	urls := []string{"/!%", "/!_", "/tail!", "/back\\slash", "/ padded ", "/encoded%2Fpart", "/unit\x1fseparator"}
	for i, url := range urls {
		if err := live.Create(&model.AccessLog{LogNarrow: model.LogNarrow{
			ReqUUID: "boundary-" + strconv.Itoa(i), TenantId: global.GWAF_TENANT_ID, UserCode: global.GWAF_USER_CODE,
			URL: url, UNIX_ADD_TIME: 1,
		}}).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, url := range urls {
		req := request.WafAttackLogSearch{URLKeyword: url, UnixAddTimeBegin: "0", UnixAddTimeEnd: "10", SortBy: "unix_add_time"}
		req.PageIndex, req.PageSize = 1, 10
		rows, total, _, err := WafLogServiceApp.GetListApiWithMeta(req)
		if err != nil || total != 1 || len(rows) != 1 || rows[0].URL != url {
			t.Fatalf("literal keyword %q: total=%d len=%d err=%v", url, total, len(rows), err)
		}
		other := req
		other.URLKeyword += "x"
		if countCacheKey(req, "archive") == countCacheKey(other, "archive") {
			t.Fatalf("different keywords share a cache key: %q", url)
		}
	}
}
