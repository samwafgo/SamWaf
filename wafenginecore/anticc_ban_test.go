package wafenginecore

import (
	"SamWaf/innerbean"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCCBanLogNarrowCopy(t *testing.T) {
	original := innerbean.WebLog{
		REQ_UUID: "ban-request", HOST_CODE: "host", SRC_IP: "203.0.113.10", NetSrcIp: "127.0.0.1",
		URL: "/test", METHOD: "POST", ACTION: "通过", UNIX_ADD_TIME: time.Now().UnixMilli() - 10,
		HEADER: "header", BODY: "body", RES_BODY: "response", COOKIES: "cookie", POST_FORM: "form",
		ResHeader: "res-header", SrcByteBody: []byte("body"), SrcByteResBody: []byte("response"),
		SrcURL: []byte("url"), BodyDecoded: "decoded", CookiesDecoded: "decoded-cookie",
		BodyValues: []string{"value"}, BodyFields: []string{"field"}, BodyHash: "hash",
	}
	before := original
	for _, code := range []int{403, 429, 444} {
		got := ccBanLog(&original, code)
		if got.REQ_UUID != original.REQ_UUID || got.SRC_IP != original.SRC_IP || got.NetSrcIp != original.NetSrcIp || got.URL != original.URL {
			t.Fatal("request identifiers changed")
		}
		if got.STATUS_CODE != code || got.ACTION != "阻止" || got.RULE != "CC封禁" || !got.SkipPayloadStore || !got.IsSecurityEvent() {
			t.Fatalf("incorrect event: %+v", got)
		}
		if code == 444 && got.STATUS != "连接关闭" {
			t.Fatal("444 must record connection closure")
		}
		if got.HEADER != "" || got.BODY != "" || got.RES_BODY != "" || got.COOKIES != "" || got.POST_FORM != "" || got.ResHeader != "" || got.BodyDecoded != "" || got.CookiesDecoded != "" || got.BodyHash != "" || len(got.SrcByteBody)+len(got.SrcByteResBody)+len(got.SrcURL)+len(got.BodyValues)+len(got.BodyFields) != 0 {
			t.Fatal("narrow log retains payload")
		}
		if got.TimeSpent < 0 || !reflect.DeepEqual(original, before) {
			t.Fatal("original request changed or negative duration")
		}
		encoded, err := json.Marshal(got)
		if err != nil || strings.Contains(string(encoded), "SkipPayloadStore") || strings.Contains(string(encoded), "skip_payload") {
			t.Fatal("runtime marker leaked to JSON")
		}
	}
}
