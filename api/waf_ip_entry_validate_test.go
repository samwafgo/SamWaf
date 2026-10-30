package api

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"encoding/json"
	"fmt"
	"testing"
)

func TestNeedsBlockAllConfirmation(t *testing.T) {
	for _, ip := range []string{"0.0.0.0/0", "::/0", "1.2.3.4/0", "0.0.0.0/00"} {
		if !needsBlockAllConfirmation(model.IPEntryTypeIP, ip, false) {
			t.Errorf("%q needs confirmation", ip)
		}
		if needsBlockAllConfirmation(model.IPEntryTypeIP, ip, true) {
			t.Errorf("%q confirmed entry must be allowed", ip)
		}
	}
	for _, ip := range []string{"10.0.0.0/8", "::/64", "192.0.2.1", "0.0.0.0"} {
		if needsBlockAllConfirmation(model.IPEntryTypeIP, ip, false) {
			t.Errorf("%q does not need confirmation", ip)
		}
	}
	if needsBlockAllConfirmation(model.IPEntryTypeGroup, "", false) {
		t.Error("group reference must not prompt for an empty IP")
	}
}

func TestBlockAllConfirmationAPI(t *testing.T) {
	setupNotifyTestEnv(t, &model.IPBlockList{})
	api := new(WafBlockIpApi)
	for i, ip := range []string{"0.0.0.0/0", "::/0"} {
		host := fmt.Sprintf("host-%d", i)
		body := fmt.Sprintf(`{"host_code":%q,"ip":%q}`, host, ip)
		checkCode := func(body string, edit bool, want int) {
			t.Helper()
			handler := api.AddApi
			if edit {
				handler = api.ModifyBlockIpApi
			}
			rec := doJSONPost(t, handler, body)
			var res response.Response
			if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
				t.Fatal(err)
			}
			if res.Code != want {
				t.Fatalf("got code %d, want %d: %s", res.Code, want, res.Msg)
			}
		}
		checkCode(body, false, response.NEED_CONFIRM_BLOCK_ALL)
		var count int64
		global.GWAF_LOCAL_DB.Model(&model.IPBlockList{}).Where("host_code = ?", host).Count(&count)
		if count != 0 || len(global.GWAF_CHAN_MSG) != 0 {
			t.Fatal("unconfirmed request changed state")
		}
		checkCode(fmt.Sprintf(`{"host_code":%q,"ip":%q,"confirm_block_all":true}`, host, ip), false, response.SUCCESS)
		var bean model.IPBlockList
		if err := global.GWAF_LOCAL_DB.Where("host_code = ?", host).First(&bean).Error; err != nil {
			t.Fatal(err)
		}
		if bean.Ip != ip || bean.IsEnable != 1 {
			t.Fatalf("unexpected saved entry: %+v", bean)
		}
		drainChanMsg()
		edit := fmt.Sprintf(`{"id":%q,"host_code":%q,"ip":%q,"remarks":"updated"}`, bean.Id, host, ip)
		checkCode(edit, true, response.NEED_CONFIRM_BLOCK_ALL)
		global.GWAF_LOCAL_DB.Where("id = ?", bean.Id).First(&bean)
		if bean.Remarks != "" || len(global.GWAF_CHAN_MSG) != 0 {
			t.Fatal("unconfirmed edit changed state")
		}
		checkCode(fmt.Sprintf(`{"id":%q,"host_code":%q,"ip":%q,"remarks":"updated","confirm_block_all":true}`, bean.Id, host, ip), true, response.SUCCESS)
		global.GWAF_LOCAL_DB.Where("id = ?", bean.Id).First(&bean)
		if bean.Remarks != "updated" {
			t.Fatal("confirmed edit did not persist")
		}
		drainChanMsg()
	}
}

func TestBlockAllConfirmationCannotEnableSystemLayer(t *testing.T) {
	for _, layer := range []string{"system", "both"} {
		for _, ip := range []string{"0.0.0.0/0", "::/0"} {
			rec := doJSONPost(t, new(WafBlockIpApi).AddApi,
				fmt.Sprintf(`{"host_code":"host-a","ip":%q,"target_layer":%q,"confirm_block_all":true}`, ip, layer))
			var res response.Response
			if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
				t.Fatal(err)
			}
			if res.Code != response.ERROR {
				t.Fatalf("system entry must be rejected: %+v", res)
			}
		}
	}
}
