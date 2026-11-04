package waf_service

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafsec"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newLocalAPIKeyTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	oldDB := global.GWAF_LOCAL_DB
	oldDialect := func() (d dialect.DBDialect) {
		defer func() { _ = recover() }()
		return dialect.Get()
	}()
	oldUser, oldTenant := global.GWAF_USER_CODE, global.GWAF_TENANT_ID
	dialect.Register(&dialect.SQLiteDialect{})
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB = oldDB
		global.GWAF_USER_CODE, global.GWAF_TENANT_ID = oldUser, oldTenant
		dialect.Register(oldDialect)
	})
	dir := t.TempDir()
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "local_keys.db")+"?_busy_timeout=5000"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open temporary SQLite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get temporary connection: %v", err)
	}
	// SQLite concurrency uses a serialized pool in this fixture.
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.OPlatformKey{}); err != nil {
		t.Fatalf("create key table: %v", err)
	}
	if err := wafsec.InitDataKey(dir, ""); err != nil {
		t.Fatalf("initialize test data key: %v", err)
	}
	global.GWAF_LOCAL_DB = db
	global.GWAF_USER_CODE, global.GWAF_TENANT_ID = "local-key-test", "local-key-test"
	return db
}

func readLocalAPIKeyRow(t *testing.T, db *gorm.DB) model.OPlatformKey {
	t.Helper()
	var row model.OPlatformKey
	if err := db.Where("local_only = ?", 1).First(&row).Error; err != nil {
		t.Fatalf("read local key row: %v", err)
	}
	return row
}

func assertLocalAPIKeyEncrypted(t *testing.T, row model.OPlatformKey, plain string) {
	t.Helper()
	if row.ApiKey == plain || !wafsec.IsDataKeyCiphertext(row.ApiKey) {
		t.Fatal("local key must be encrypted in storage")
	}
	decoded, err := wafsec.DataDecrypt(row.ApiKey, nil)
	if err != nil || decoded != plain {
		t.Fatal("stored local key must decrypt to the returned value")
	}
	if row.LocalOnly != 1 || row.Status != 1 || row.RateLimit != 0 {
		t.Fatal("local key defaults must be enabled, local-only and unlimited")
	}
}

func assertLocalAPIKeyRejected(t *testing.T, key string) {
	t.Helper()
	if _, err := WafOPlatformKeyServiceApp.GetByApiKey(key); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("expected missing key, got %v", err)
	}
}

func TestLocalOnlyKeyLifecycle(t *testing.T) {
	db := newLocalAPIKeyTestDB(t)
	svc := WafOPlatformKeyServiceApp
	key, action, err := svc.EnsureLocalOnlyKey(false)
	if err != nil || action != "created" {
		t.Fatalf("initialization action=%s error=%v", action, err)
	}
	if len(key) != 35 || !strings.HasPrefix(key, "sk-") {
		t.Fatal("generated key must have the expected format")
	}
	first := readLocalAPIKeyRow(t, db)
	assertLocalAPIKeyEncrypted(t, first, key)
	if first.Id == "" || first.KeyName != "本机命令行(CLI)" {
		t.Fatal("local key metadata missing")
	}
	found, err := svc.GetByApiKey(key)
	if err != nil || found.Id != first.Id || found.ApiKey != key {
		t.Fatal("encrypted local key must resolve by its plaintext credential")
	}
	assertLocalAPIKeyRejected(t, first.ApiKey)
	reused, action, err := svc.EnsureLocalOnlyKey(false)
	if err != nil || action != "reused" || reused != key {
		t.Fatalf("reuse action=%s error=%v", action, err)
	}
	second := readLocalAPIKeyRow(t, db)
	if second.Id != first.Id || second.ApiKey != first.ApiKey {
		t.Fatal("reuse must preserve the existing record and ciphertext")
	}
	rotated, action, err := svc.EnsureLocalOnlyKey(true)
	if err != nil || action != "rotated" || rotated == key {
		t.Fatalf("rotate action=%s error=%v", action, err)
	}
	third := readLocalAPIKeyRow(t, db)
	if third.Id != first.Id {
		t.Fatal("rotation must retain the key record")
	}
	assertLocalAPIKeyEncrypted(t, third, rotated)
	assertLocalAPIKeyRejected(t, key)
	assertLocalAPIKeyRejected(t, third.ApiKey)
	if found, err := svc.GetByApiKey(rotated); err != nil || found.Id != first.Id {
		t.Fatal("rotated key must resolve")
	}
	var count int64
	if err := db.Model(&model.OPlatformKey{}).Where("local_only = ?", 1).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("expected one local key, count=%d error=%v", count, err)
	}
}

func TestLocalOnlyKeyRestoresUsableState(t *testing.T) {
	past := time.Now().Add(-24 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	future := time.Now().Add(24 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	for _, tc := range []struct {
		name               string
		status             int
		expiry, wantExpiry string
	}{
		{"disabled", 0, "", ""},
		{"expired", 1, past, ""},
		{"disabled_expired", 0, past, ""},
		{"invalid_expiry", 1, "invalid", ""},
		{"future_expiry", 1, future, future},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newLocalAPIKeyTestDB(t)
			svc := WafOPlatformKeyServiceApp
			key, _, err := svc.EnsureLocalOnlyKey(false)
			if err != nil {
				t.Fatalf("create key: %v", err)
			}
			row := readLocalAPIKeyRow(t, db)
			if err := db.Model(&model.OPlatformKey{}).Where("id = ?", row.Id).Updates(map[string]interface{}{"status": tc.status, "expire_time": tc.expiry}).Error; err != nil {
				t.Fatalf("set key state: %v", err)
			}
			reused, action, err := svc.EnsureLocalOnlyKey(false)
			if err != nil || action != "reused" || reused != key {
				t.Fatalf("restore action=%s error=%v", action, err)
			}
			restored := readLocalAPIKeyRow(t, db)
			if restored.Status != 1 || restored.ExpireTime != tc.wantExpiry {
				t.Fatal("reuse must restore disabled/expired state and retain a future expiration")
			}
			assertLocalAPIKeyEncrypted(t, restored, key)
		})
	}
}

func TestLocalOnlyKeyResetAndMask(t *testing.T) {
	db := newLocalAPIKeyTestDB(t)
	svc := WafOPlatformKeyServiceApp
	key, _, err := svc.EnsureLocalOnlyKey(false)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	row := readLocalAPIKeyRow(t, db)
	wantMask := key[:6] + "****" + key[len(key)-4:]
	detail := svc.GetDetailApi(request.WafOPlatformKeyDetailReq{Id: row.Id})
	if detail.ApiKey != wantMask {
		t.Fatal("detail must mask the decrypted local key")
	}
	search := request.WafOPlatformKeySearchReq{}
	search.PageIndex, search.PageSize = 1, 10
	list, count, err := svc.GetListApi(search)
	if err != nil || count != 1 || len(list) != 1 || list[0].ApiKey != wantMask {
		t.Fatal("list must mask the decrypted local key")
	}
	newKey, err := svc.ResetApiKey(request.WafOPlatformKeyResetSecretReq{Id: row.Id})
	if err != nil || newKey == key {
		t.Fatalf("reset key: %v", err)
	}
	assertLocalAPIKeyEncrypted(t, readLocalAPIKeyRow(t, db), newKey)
	assertLocalAPIKeyRejected(t, key)
	found, err := svc.GetByApiKey(newKey)
	if err != nil || found.Id != row.Id || found.LocalOnly != 1 {
		t.Fatal("reset must preserve the local key identity and lookup")
	}
}

func TestLocalOnlyKeyInvalidCiphertext(t *testing.T) {
	db := newLocalAPIKeyTestDB(t)
	svc := WafOPlatformKeyServiceApp
	key, _, err := svc.EnsureLocalOnlyKey(false)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	row := readLocalAPIKeyRow(t, db)
	const broken = "swk1:invalid"
	if err := db.Model(&model.OPlatformKey{}).Where("id = ?", row.Id).Update("api_key", broken).Error; err != nil {
		t.Fatalf("set ciphertext: %v", err)
	}
	assertLocalAPIKeyRejected(t, key)
	assertLocalAPIKeyRejected(t, broken)
	if got, action, err := svc.EnsureLocalOnlyKey(false); err == nil || got != "" || action != "" {
		t.Fatal("reuse must fail without returning a credential when decryption fails")
	}
	if detail := svc.GetDetailApi(request.WafOPlatformKeyDetailReq{Id: row.Id}); detail.ApiKey != "****" {
		t.Fatal("decryption failure must remain masked")
	}
	rotated, action, err := svc.EnsureLocalOnlyKey(true)
	if err != nil || action != "rotated" || rotated == key {
		t.Fatalf("rotate invalid ciphertext action=%s error=%v", action, err)
	}
	assertLocalAPIKeyEncrypted(t, readLocalAPIKeyRow(t, db), rotated)
	if _, err := svc.GetByApiKey(rotated); err != nil {
		t.Fatalf("resolve replacement key: %v", err)
	}
}

func TestLocalOnlyKeyOrdinaryCompatibility(t *testing.T) {
	db := newLocalAPIKeyTestDB(t)
	svc := WafOPlatformKeyServiceApp
	id, ordinary, err := svc.AddApi(request.WafOPlatformKeyAddReq{KeyName: "ordinary"})
	if err != nil {
		t.Fatalf("create ordinary key: %v", err)
	}
	var raw model.OPlatformKey
	if err := db.Where("id = ?", id).First(&raw).Error; err != nil {
		t.Fatalf("read ordinary row: %v", err)
	}
	if raw.ApiKey != ordinary || raw.LocalOnly != 0 {
		t.Fatal("ordinary key storage and scope must stay compatible")
	}
	local, action, err := svc.EnsureLocalOnlyKey(false)
	if err != nil || action != "created" || local == ordinary {
		t.Fatalf("create independent local key action=%s error=%v", action, err)
	}
	if got, err := svc.GetByApiKey(ordinary); err != nil || got.Id != id || got.LocalOnly != 0 {
		t.Fatal("ordinary plaintext lookup must continue working")
	}
	replacement, err := svc.ResetApiKey(request.WafOPlatformKeyResetSecretReq{Id: id})
	if err != nil || replacement == ordinary {
		t.Fatalf("reset ordinary key: %v", err)
	}
	var reset model.OPlatformKey
	if err := db.Where("id = ?", id).First(&reset).Error; err != nil {
		t.Fatalf("read reset ordinary row: %v", err)
	}
	if reset.ApiKey != replacement || reset.LocalOnly != 0 {
		t.Fatal("ordinary reset must preserve existing storage and scope")
	}
	assertLocalAPIKeyRejected(t, ordinary)
	if got, err := svc.GetByApiKey(replacement); err != nil || got.Id != id {
		t.Fatal("ordinary replacement must resolve")
	}
}

func TestLocalOnlyKeyLegacyPlaintextUpgrade(t *testing.T) {
	db := newLocalAPIKeyTestDB(t)
	svc := WafOPlatformKeyServiceApp
	key, _, err := svc.EnsureLocalOnlyKey(false)
	if err != nil {
		t.Fatalf("create local key: %v", err)
	}
	row := readLocalAPIKeyRow(t, db)
	if err := db.Model(&model.OPlatformKey{}).Where("id = ?", row.Id).Update("api_key", key).Error; err != nil {
		t.Fatalf("set plaintext local row: %v", err)
	}
	if got, err := svc.GetByApiKey(key); err != nil || got.Id != row.Id {
		t.Fatal("existing plaintext local row must resolve")
	}
	reused, action, err := svc.EnsureLocalOnlyKey(false)
	if err != nil || action != "reused" || reused != key {
		t.Fatalf("upgrade local row action=%s error=%v", action, err)
	}
	assertLocalAPIKeyEncrypted(t, readLocalAPIKeyRow(t, db), key)
}

func TestLocalOnlyKeyDatabaseFailure(t *testing.T) {
	db := newLocalAPIKeyTestDB(t)
	if err := db.Migrator().DropTable(&model.OPlatformKey{}); err != nil {
		t.Fatalf("drop temporary table: %v", err)
	}
	key, action, err := WafOPlatformKeyServiceApp.EnsureLocalOnlyKey(false)
	if err == nil || key != "" || action != "" {
		t.Fatal("database failure must not return a successful credential result")
	}
}

func TestLocalOnlyKeyConcurrentInitializationSQLite(t *testing.T) {
	db := newLocalAPIKeyTestDB(t)
	svc := WafOPlatformKeyServiceApp
	const workers = 8
	type outcome struct {
		key, action string
		err         error
	}
	outcomes := make(chan outcome, workers)
	for i := 0; i < workers; i++ {
		go func() {
			key, action, err := svc.EnsureLocalOnlyKey(false)
			outcomes <- outcome{key, action, err}
		}()
	}
	winner := ""
	for i := 0; i < workers; i++ {
		got := <-outcomes
		if got.err != nil {
			t.Fatalf("concurrent initialization: %v", got.err)
		}
		if got.action != "created" && got.action != "reused" {
			t.Fatalf("unexpected action: %s", got.action)
		}
		if got.key == "" {
			t.Fatal("concurrent initialization returned an empty key")
		}
		if winner == "" {
			winner = got.key
		} else if got.key != winner {
			t.Fatal("concurrent initialization must return one shared key")
		}
	}
	if winner == "" {
		t.Fatal("no winner key captured")
	}
	var count int64
	if err := db.Model(&model.OPlatformKey{}).Where("local_only = ?", 1).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("expected one local key, count=%d error=%v", count, err)
	}
	assertLocalAPIKeyEncrypted(t, readLocalAPIKeyRow(t, db), winner)
}

func TestLocalOnlyKeyCreateConflictFollowsReuseSQLite(t *testing.T) {
	db := newLocalAPIKeyTestDB(t)
	svc := WafOPlatformKeyServiceApp
	key, _, err := svc.EnsureLocalOnlyKey(false)
	if err != nil {
		t.Fatalf("create local key: %v", err)
	}
	row := readLocalAPIKeyRow(t, db)
	if row.Status != 1 {
		t.Fatal("setup key must start enabled")
	}
	if err := db.Model(&model.OPlatformKey{}).Where("id = ?", row.Id).Updates(map[string]interface{}{"status": 0, "expire_time": "2000-01-01 00:00:00"}).Error; err != nil {
		t.Fatalf("set existing state: %v", err)
	}
	attempts := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() { _, _, err := svc.EnsureLocalOnlyKey(false); attempts <- err }()
	}
	for i := 0; i < 4; i++ {
		if err := <-attempts; err != nil {
			t.Fatalf("conflict recovery reuse: %v", err)
		}
	}
	restored := readLocalAPIKeyRow(t, db)
	if restored.Status != 1 || restored.ExpireTime != "" {
		t.Fatal("conflict recovery must restore the existing local key")
	}
	var count int64
	if err := db.Model(&model.OPlatformKey{}).Where("local_only = ?", 1).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("expected one local key, count=%d error=%v", count, err)
	}
	assertLocalAPIKeyEncrypted(t, restored, key)
}
