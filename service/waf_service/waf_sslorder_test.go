package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"path/filepath"
	"testing"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
)

func TestFailSubmittedSSLOrderPreservesExistingCertificate(t *testing.T) {
	db, err := gorm.Open(sqlitedriver.Open(filepath.Join(t.TempDir(), "sslorders.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		t.Cleanup(func() { _ = sqlDB.Close() })
	}
	if err := db.AutoMigrate(&model.SslOrder{}); err != nil {
		t.Fatal(err)
	}
	previous := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = db
	t.Cleanup(func() { global.GWAF_LOCAL_DB = previous })

	priorTenant, priorUser := global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "tenant", "user"
	t.Cleanup(func() { global.GWAF_TENANT_ID, global.GWAF_USER_CODE = priorTenant, priorUser })
	saved := model.SslOrder{
		BaseOrm:  baseorm.BaseOrm{Id: "saved", Tenant_ID: "tenant", USER_CODE: "user", CREATE_TIME: customtype.JsonTime(time.Now().Add(-time.Hour))},
		HostCode: "site", ApplyMethod: "http01", ApplyStatus: "success", ResultCertificate: []byte("saved cert"),
		ResultValidTo: customtype.JsonTime(time.Now().Add(24 * time.Hour)),
	}
	if err := db.Create(&saved).Error; err != nil {
		t.Fatal(err)
	}
	pending, err := WafSSLOrderServiceApp.RenewAdd(saved, request.WafSslordereditReq{ApplyStatus: "renewed", ApplyMethod: "dns01"})
	if err != nil || pending.ApplyStatus != "submitted" || pending.ApplyMethod != "dns01" {
		t.Fatalf("renewal order not created from edited settings: status=%s method=%s err=%v", pending.ApplyStatus, pending.ApplyMethod, err)
	}
	if latest, err := WafSSLOrderServiceApp.GetLastedInfo(saved.HostCode); err != nil || latest.Id != saved.Id {
		t.Fatalf("pending renewal shadowed the installed certificate: latest=%s err=%v", latest.Id, err)
	}
	wrongOwner := pending
	wrongOwner.USER_CODE = "other"
	for _, order := range []model.SslOrder{wrongOwner, saved} {
		if err := WafSSLOrderServiceApp.FailSubmittedOrder(order, "worker stopped"); err != nil {
			t.Fatal(err)
		}
	}
	check := func(id, status, certificate, failure string) {
		t.Helper()
		var order model.SslOrder
		if err := db.First(&order, "id = ?", id).Error; err != nil {
			t.Fatal(err)
		}
		if order.ApplyStatus != status || string(order.ResultCertificate) != certificate || order.ResultError != failure {
			t.Fatalf("%s: got status=%s, cert=%q, error=%q", id, order.ApplyStatus, order.ResultCertificate, order.ResultError)
		}
	}
	check(saved.Id, "success", "saved cert", "")
	check(pending.Id, "submitted", "saved cert", "")
	if err := WafSSLOrderServiceApp.FailSubmittedOrder(pending, "worker stopped"); err != nil {
		t.Fatal(err)
	}
	check(pending.Id, "fail", "", "worker stopped")
}
