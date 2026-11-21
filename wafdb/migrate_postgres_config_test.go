package wafdb

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestMigratePostgresConfigSelectsKVAndKeepsBackup 验证数据库/KV 一起切换，原配置仍可逐字节恢复。
func TestMigratePostgresConfigSelectsKVAndKeepsBackup(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "conf"), 0700); err != nil {
		t.Fatal(err)
	}
	original := []byte("database:\n  driver: sqlite\ncache:\n  type: redis\n")
	path := filepath.Join(dir, "conf", "config.yml")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	m := &MigrateTool{opts: MigrateOptions{CurrentDir: dir}, dstKind: "postgres"}
	if err := m.saveTargetToConfig(); err != nil {
		t.Fatal(err)
	}
	backups, err := filepath.Glob(filepath.Join(dir, "conf", "config.pre-postgres-*.yml"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("backup files=%v err=%v", backups, err)
	}
	data, err := os.ReadFile(backups[0])
	if err != nil || !bytes.Equal(original, data) {
		t.Fatal("original config backup differs")
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]interface{}
	if err = yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config["database"].(map[string]interface{})["driver"] != "postgres" || config["cache"].(map[string]interface{})["type"] != "postgres" {
		t.Fatal("migration did not switch both database and KV cache")
	}
}
