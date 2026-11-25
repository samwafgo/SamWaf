package wafdb

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"SamWaf/model"
	"SamWaf/model/baseorm"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
)

func TestSecurityAuditLogObjectFieldsMigration(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "audit-migration.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	type legacyAudit struct {
		baseorm.BaseOrm
		Category string
		Event    string
		Message  string
	}
	table := db.Table((model.SecurityAuditLog{}).TableName())
	if err := table.AutoMigrate(&legacyAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := table.Create(&legacyAudit{
		BaseOrm: baseorm.BaseOrm{Id: "legacy"}, Category: model.AuditCategoryAccess,
		Event: model.AccessEventLoginOK, Message: "legacy login",
	}).Error; err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := addSecurityAuditObjectFields(db); err != nil {
			t.Fatal(err)
		}
	}
	if !db.Migrator().HasIndex(&model.SecurityAuditLog{}, "idx_security_audit_object") {
		t.Fatal("missing object lookup index")
	}

	var legacy model.SecurityAuditLog
	if err := db.Where("id = ?", "legacy").Take(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	if legacy.Category != model.AuditCategoryAccess || legacy.Event != model.AccessEventLoginOK || legacy.Message != "legacy login" ||
		legacy.ObjectType != "" || legacy.ObjectID != "" || len(legacy.Detail) != 0 {
		t.Fatalf("unexpected historical audit row: %+v", legacy)
	}
	wire, err := json.Marshal(legacy)
	if err != nil || !json.Valid(wire) {
		t.Fatalf("historical row does not marshal: %s (%v)", wire, err)
	}
	if err := table.Create(map[string]any{
		"id": "new", "object_type": "tunnel", "object_id": "tunnel-1", "detail": `{"reason":"manual_refresh"}`,
	}).Error; err != nil {
		t.Fatal(err)
	}
	var next model.SecurityAuditLog
	if err := db.Where("object_type = ? AND object_id = ?", "tunnel", "tunnel-1").Take(&next).Error; err != nil {
		t.Fatal(err)
	}
	if next.Id != "new" || string(next.Detail) != `{"reason":"manual_refresh"}` {
		t.Fatalf("unexpected audit row after migration: %+v", next)
	}
}
