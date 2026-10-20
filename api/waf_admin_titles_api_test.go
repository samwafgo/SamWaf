package api

import (
	"SamWaf/global"
	"SamWaf/wafconfig"
	"SamWaf/wafsec"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNormalizeAdminTitle(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		invalid           bool
	}{
		{name: "empty"},
		{name: "trim", input: "  管理后台　", want: "管理后台"},
		{name: "100 unicode", input: strings.Repeat("界", 100), want: strings.Repeat("界", 100)},
		{name: "101 unicode", input: strings.Repeat("界", 101), invalid: true},
		{name: "html remains text", input: "<b>Ops & Admin</b>", want: "<b>Ops & Admin</b>"},
		{name: "invalid utf8", input: string([]byte{0xff}), invalid: true},
		{name: "newline", input: "a\nb", invalid: true},
		{name: "trailing newline", input: "title\n", invalid: true},
		{name: "tab", input: "a\tb", invalid: true},
		{name: "nul", input: "a\x00b", invalid: true},
		{name: "delete", input: "a\x7fb", invalid: true},
		{name: "line separator", input: "a b", invalid: true},
		{name: "paragraph separator", input: "a b", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeAdminTitle(tc.input)
			if (err != nil) != tc.invalid || (!tc.invalid && got != tc.want) {
				t.Fatalf("got %q, %v; want %q, invalid=%v", got, err, tc.want, tc.invalid)
			}
		})
	}
}

func TestAdminTitlesGetEncryptedSingleField(t *testing.T) {
	priorLegacy := global.GCONFIG_COMM_LEGACY_KEY
	global.GCONFIG_COMM_LEGACY_KEY = true
	t.Cleanup(func() { global.GCONFIG_COMM_LEGACY_KEY = priorLegacy })
	r := gin.New()
	r.GET("/api/v1/public/uiconfig", (&WafVpConfigApi{}).GetAdminTitlesApi)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/public/uiconfig", nil))
	var envelope struct {
		Code int    `json:"code"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || envelope.Code != 0 || envelope.Data == "" {
		t.Fatalf("invalid encrypted response: %s, %v", w.Body.String(), err)
	}
	plain, err := wafsec.AesDecrypt(envelope.Data, global.GWAF_COMMUNICATION_KEY)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal(plain, &fields); err != nil {
		t.Fatal(err)
	}
	want := wafconfig.GetAdminTitles()
	if len(fields) != 1 || fields["admin_title"] != want.AdminTitle {
		t.Fatalf("unexpected fields: %s", plain)
	}
}

func TestAdminTitlesUpdateRejectsInvalidRequest(t *testing.T) {
	r := gin.New()
	r.POST("/titles", (&WafVpConfigApi{}).UpdateAdminTitlesApi)
	for _, body := range []string{
		`{"admin_title":123}`, `{"admin_title":true}`, `{"admin_title":null}`,
		`{"admin_title":"a\nb"}`,
		`{"admin_title":"` + strings.Repeat("界", 101) + `"}`,
		"{\"admin_title\":\"" + string([]byte{0xff}) + "\"}",
		`{}`, `null`, `[]`, `{"other":"title"}`,
		`{"admin_title":"title","other":"extra"}`,
		`{"admin_title":"title"} {}`,
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", "/titles", strings.NewReader(body)))
		var envelope struct {
			Code int `json:"code"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || envelope.Code != -1 {
			t.Fatalf("invalid request accepted: %q, response %s", body, w.Body.String())
		}
	}
}
