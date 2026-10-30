package waflogexport

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"SamWaf/wafsec"
	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func testOptions(t *testing.T, format string) Options {
	t.Helper()
	if err := wafsec.InitDataKey(t.TempDir(), ""); err != nil {
		t.Fatal(err)
	}
	return Options{Dir: t.TempDir(), Format: format, Tables: []string{"access_log", "security_event"}, Key: "test-only-log-key", TaskID: "task-1"}
}
func testRow(id string) map[string]interface{} {
	return map[string]interface{}{"req_uuid": id, "url": "中文\nquoted,\"text\"", "guest_id_entification": "00001234567890123456789", "create_time": "2026-10-29 12:00:00", "time_spent": int64(9007199254740993), "ai_score": 0.25, "status_code": int64(200), "body": "excluded"}
}
func readZIP(t *testing.T, r *Result) map[string][]byte {
	t.Helper()
	stream, err := OpenArchive(r.Path, r.WrappedKey, r.Manifest.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	raw, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != r.SHA256 || int64(len(raw)) != r.ZIPBytes {
		t.Fatal("zip checksum")
	}
	archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, entry := range archive.File {
		f, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name], err = io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range r.Manifest.Files {
		sum := sha256.Sum256(files[f.Name])
		if f.Bytes != int64(len(files[f.Name])) || f.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("file checksum %s", f.Name)
		}
	}
	return files
}
func TestJSONLSplitDedupAndFieldProtocol(t *testing.T) {
	o := testOptions(t, "jsonl")
	o.PartBytes = 20
	b, err := NewBuilder(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	row := testRow("1")
	if err = b.AddBatch("access_log", []map[string]interface{}{row, row}); err != nil {
		t.Fatal(err)
	}
	row2 := testRow("1")
	row2["status_code"] = 403
	if err = b.AddBatch("access_log", []map[string]interface{}{row2, testRow("2")}); err != nil {
		t.Fatal(err)
	}
	if err = b.AddBatch("security_event", []map[string]interface{}{testRow("1")}); err != nil {
		t.Fatal(err)
	}
	r, err := b.Close()
	if err != nil {
		t.Fatal(err)
	}
	files := readZIP(t, r)
	if r.Manifest.Counts["access_log"] != (TableCount{Read: 4, Skipped: 2, Conflicts: 1, Written: 2}) {
		t.Fatalf("counts %+v", r.Manifest.Counts)
	}
	if r.Manifest.Counts["security_event"].Written != 1 || len(r.Manifest.Files) != 3 {
		t.Fatal("split/cross-table dedup")
	}
	var rowOut map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(files["access_log/part-000001.jsonl"]))
	decoder.UseNumber()
	if err = decoder.Decode(&rowOut); err != nil {
		t.Fatal(err)
	}
	if rowOut["time_spent"] != json.Number("9007199254740993") || rowOut["guest_identification"] != "00001234567890123456789" || rowOut["host"] != nil {
		t.Fatalf("types/mapping %+v", rowOut)
	}
	if _, ok := rowOut["body"]; ok {
		t.Fatal("unexpected field")
	}
	if bytes.Count(files["access_log/part-000001.jsonl"], []byte{'\n'}) != 1 {
		t.Fatal("physical lines")
	}
	data, err := os.ReadFile(r.Path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("quoted")) || bytes.HasPrefix(data, []byte("PK")) {
		t.Fatal("plaintext archive")
	}
	entries, err := os.ReadDir(o.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "logs.zip.enc" {
		t.Fatalf("leftovers %+v", entries)
	}
}
func TestCSVEmptyAndFormula(t *testing.T) {
	o := testOptions(t, "csv")
	o.CSVMaxRows = 1
	b, err := NewBuilder(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	row := testRow("1")
	row["url"] = " \t\r=1+1"
	if err = b.AddBatch("access_log", []map[string]interface{}{row, testRow("2")}); err != nil {
		t.Fatal(err)
	}
	r, err := b.Close()
	if err != nil {
		t.Fatal(err)
	}
	files := readZIP(t, r)
	for _, f := range r.Manifest.Files {
		if !bytes.HasPrefix(files[f.Name], []byte{0xef, 0xbb, 0xbf}) {
			t.Fatal("BOM missing")
		}
	}
	records, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(files["access_log/part-000001.csv"]), "\ufeff"))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range records[0] {
		if name == "url" && records[1][i] != "' \t\r=1+1" {
			t.Fatal("formula prefix")
		}
	}
	empty, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(files["security_event/part-000001.csv"]), "\ufeff"))).ReadAll()
	if err != nil || len(empty) != 1 {
		t.Fatal("empty header", err)
	}
}
func TestSQLiteEncryptedCompatible(t *testing.T) {
	o := testOptions(t, "sqlite")
	b, err := NewBuilder(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.AddBatch("access_log", []map[string]interface{}{testRow("1")}); err != nil {
		t.Fatal(err)
	}
	// Both database files are encrypted while the builder is active.
	for _, name := range []string{"dedup.encrypted.db", "logs.encrypted.db"} {
		data, err := os.ReadFile(filepath.Join(o.Dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.HasPrefix(data, []byte("SQLite format 3")) {
			t.Fatal("plaintext sqlite")
		}
	}
	r, err := b.Close()
	if err != nil {
		t.Fatal(err)
	}
	files := readZIP(t, r)
	path := filepath.Join(t.TempDir(), "check.db")
	if err = os.WriteFile(path, files["logs.encrypted.db"], 0600); err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(sqlite.Open(path+"?_db_key="+url.QueryEscape(o.Key)), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB(db)
	var rows []map[string]interface{}
	if err = db.Table("access_log").Find(&rows).Error; err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	var n int64
	if err = db.Table("security_event").Count(&n).Error; err != nil || n != 0 {
		t.Fatal(n, err)
	}
	if db.Migrator().HasTable("event_payload") {
		t.Fatal("unexpected table")
	}
	if rows[0]["guest_identification"] != "00001234567890123456789" {
		t.Fatal(rows)
	}
}
func TestQuotaCancelAndWhitelist(t *testing.T) {
	t.Run("quota", func(t *testing.T) {
		o := testOptions(t, "jsonl")
		o.MaxBytes = 1
		b, err := NewBuilder(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		if err = b.AddBatch("access_log", []map[string]interface{}{testRow("1")}); !errors.Is(err, ErrQuota) {
			t.Fatal(err)
		}
		if _, err = b.Close(); !errors.Is(err, ErrQuota) {
			t.Fatal(err)
		}
		entries, _ := os.ReadDir(o.Dir)
		if len(entries) != 0 {
			t.Fatal("incomplete output retained")
		}
	})
	t.Run("cancel", func(t *testing.T) {
		o := testOptions(t, "jsonl")
		ctx, cancel := context.WithCancel(context.Background())
		b, err := NewBuilder(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		if err = b.AddBatch("access_log", []map[string]interface{}{testRow("1")}); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		_, _ = b.Close()
	})
	t.Run("whitelist", func(t *testing.T) {
		o := testOptions(t, "jsonl")
		o.Tables = []string{"event_payload"}
		if _, err := NewBuilder(context.Background(), o); err == nil {
			t.Fatal("accepted table")
		}
	})
	t.Run("unknown-add", func(t *testing.T) {
		o := testOptions(t, "jsonl")
		b, err := NewBuilder(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		defer b.Abort()
		if err = b.AddBatch("event_payload", nil); err == nil {
			t.Fatal("accepted table")
		}
	})
}
func TestClosePackageKeepsUnownedFile(t *testing.T) {
	o := testOptions(t, "csv")
	foreign := filepath.Join(o.Dir, "logs.encrypted.db")
	if err := os.WriteFile(foreign, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := NewBuilder(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.AddBatch("access_log", []map[string]interface{}{testRow("1")}); err != nil {
		t.Fatal(err)
	}
	r, err := b.Close()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(foreign)
	if err != nil || string(data) != "keep" {
		t.Fatal("unowned file changed", err)
	}
	fi, err := os.Stat(r.Path)
	if err != nil || fi.Size() != r.Size {
		t.Fatal("result size", err)
	}
}

func TestSymlinkDirectoryRejected(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		cmd := exec.Command("cmd", "/c", "mklink", "/J", link, target)
		if out, jerr := cmd.CombinedOutput(); jerr != nil {
			t.Skipf("link unavailable: %v %s; junction: %v %s", err, "", jerr, out)
		}
	}
	o := testOptions(t, "jsonl")
	o.Dir = filepath.Join(link, "newdir")
	if _, err := NewBuilder(context.Background(), o); err == nil {
		t.Fatal("accepted symlinked export directory")
	}
	if _, err := os.Lstat(filepath.Join(target, "newdir")); !os.IsNotExist(err) {
		t.Fatal("directory created through symlink")
	}
}

func TestMinFreeBytesHugeReserve(t *testing.T) {
	o := testOptions(t, "jsonl")
	o.MinFreeBytes = 1
	b, err := NewBuilder(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Abort()
	b.options.MinFreeBytes = math.MaxUint64 - 100
	if err = b.checkQuota(200); !errors.Is(err, ErrQuota) {
		t.Fatalf("overflowing reserve accepted: %v", err)
	}
}

func TestCloseCancelCleansDirectory(t *testing.T) {
	o := testOptions(t, "sqlite")
	ctx, cancel := context.WithCancel(context.Background())
	b, err := NewBuilder(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.AddBatch("access_log", []map[string]interface{}{testRow("1")}); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err = b.Close(); err == nil {
		t.Fatal("close succeeded after cancel")
	}
	entries, _ := os.ReadDir(o.Dir)
	if len(entries) != 0 {
		t.Fatalf("incomplete output retained: %+v", entries)
	}
}

func TestCSVCellTextAndManifest(t *testing.T) {
	o := testOptions(t, "csv")
	b, err := NewBuilder(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	row := testRow("1")
	row["guest_id_entification"] = "007"
	if err = b.AddBatch("access_log", []map[string]interface{}{row}); err != nil {
		t.Fatal(err)
	}
	r, err := b.Close()
	if err != nil {
		t.Fatal(err)
	}
	files := readZIP(t, r)
	records, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(files["access_log/part-000001.csv"]), string(rune(0xfeff))))).ReadAll()
	if err != nil || len(records) != 2 {
		t.Fatal(records, err)
	}
	fields, _ := Fields("access_log")
	if len(records[0]) != len(fields) {
		t.Fatal("header width")
	}
	for i, f := range fields {
		if records[0][i] != f.Name {
			t.Fatalf("header field %d = %q", i, records[0][i])
		}
		if f.Type == "text" && row[f.Name] != nil && records[1][i] != row[f.Name] {
			t.Fatalf("text cell %s = %q", f.Name, records[1][i])
		}
	}
	if r.Manifest.Counts["access_log"].Written != 1 || r.Manifest.Fields["security_event"] == nil {
		t.Fatalf("manifest %+v", r.Manifest)
	}
}

func TestJSONLFieldSetExact(t *testing.T) {
	o := testOptions(t, "jsonl")
	b, err := NewBuilder(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.AddBatch("security_event", []map[string]interface{}{testRow("1")}); err != nil {
		t.Fatal(err)
	}
	r, err := b.Close()
	if err != nil {
		t.Fatal(err)
	}
	files := readZIP(t, r)
	var rowOut map[string]interface{}
	if err = json.Unmarshal(files["security_event/part-000001.jsonl"], &rowOut); err != nil {
		t.Fatal(err)
	}
	fields, _ := Fields("security_event")
	if len(rowOut) != len(fields) {
		t.Fatalf("field set size %d != %d", len(rowOut), len(fields))
	}
	for _, f := range fields {
		if _, ok := rowOut[f.Name]; !ok {
			t.Fatalf("missing field %s", f.Name)
		}
	}
	if rowOut["payload_hash"] != nil {
		t.Fatal("expected null payload_hash")
	}
}

func TestCSVFormulaWhitespace(t *testing.T) {
	for _, prefix := range []string{"", " ", "\t", "\r\n", "\x00", " ", "\ufeff"} {
		for _, trigger := range []string{"=", "+", "-", "@"} {
			s := prefix + trigger + "123"
			if csvText(s) != "'"+s {
				t.Fatalf("unprotected %q", s)
			}
		}
	}
}
