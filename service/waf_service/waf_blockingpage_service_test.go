package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	commonreq "SamWaf/model/common/request"
	"SamWaf/model/request"
	"testing"
)

func TestBackendUnavailablePagePersistence(t *testing.T) {
	db := setupHostGroupTestDB(t)
	if err := db.AutoMigrate(&model.BlockingPage{}); err != nil {
		t.Fatal(err)
	}
	oldCode := global.GWAF_GLOBAL_HOST_CODE
	global.GWAF_GLOBAL_HOST_CODE = "global-website-uuid"
	t.Cleanup(func() { global.GWAF_GLOBAL_HOST_CODE = oldCode })
	service := WafBlockingPageServiceApp
	hostCode := global.GWAF_GLOBAL_HOST_CODE
	for _, req := range []request.WafBlockingPageAddReq{
		{HostCode: hostCode, BlockingType: model.BlockingPageTypeBackendUnavailable, ResponseCode: "503", ResponseContent: "outage"},
		{HostCode: hostCode, BlockingType: model.BlockingPageTypeOther, ResponseCode: "503", ResponseContent: "http status"},
		{HostCode: hostCode, BlockingType: model.BlockingPageTypeUnmatchedHost, ResponseCode: "403", ResponseContent: "unmatched"},
	} {
		if err := service.AddApi(req); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.AddApi(request.WafBlockingPageAddReq{HostCode: hostCode, BlockingType: model.BlockingPageTypeBackendUnavailable, ResponseCode: "503"}); err == nil {
		t.Fatal("duplicate dedicated page added")
	}
	search := request.WafBlockingPageSearchReq{HostCode: hostCode, PageInfo: commonreq.PageInfo{PageIndex: 1, PageSize: 10}}
	rows, total, err := service.GetListApi(search)
	if err != nil || total != 1 || len(rows) != 1 || rows[0].BlockingType != model.BlockingPageTypeOther {
		t.Fatalf("main list: rows=%v total=%d err=%v", rows, total, err)
	}
	search.BlockingType = model.BlockingPageTypeBackendUnavailable
	rows, total, err = service.GetListApi(search)
	if err != nil || total != 1 || len(rows) != 1 || rows[0].ResponseContent != "outage" {
		t.Fatalf("dedicated list: rows=%v total=%d err=%v", rows, total, err)
	}
	pageID := rows[0].Id
	if err := service.ModifyApi(request.WafBlockingPageEditReq{Id: pageID, HostCode: hostCode, BlockingType: search.BlockingType, ResponseCode: "503", ResponseContent: "updated"}); err != nil {
		t.Fatal(err)
	}
	pages := service.LoadBlockingPageMap(hostCode)
	if pages[search.BlockingType].ResponseContent != "updated" || pages["503"].ResponseContent != "http status" || pages[model.BlockingPageTypeUnmatchedHost].ResponseContent != "unmatched" {
		t.Fatalf("unexpected page map: %v", pages)
	}
	if err := service.DelApi(request.WafBlockingPageDelReq{Id: pageID}); err != nil {
		t.Fatal(err)
	}
	if _, found := service.LoadBlockingPageMap(hostCode)[search.BlockingType]; found {
		t.Fatal("deleted page still found")
	}
}
