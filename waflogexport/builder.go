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
	"fmt"
	"hash"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"SamWaf/wafsec"
	sqlite "github.com/samwafgo/sqlitedriver"
	"github.com/shirou/gopsutil/v4/disk"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var ErrQuota = errors.New("export quota exceeded")
var ErrClosed = errors.New("export builder closed")

type dedupKey struct {
	Table   string `gorm:"column:table_name;primaryKey;size:32"`
	ReqUUID string `gorm:"primaryKey;size:64"`
	Digest  string `gorm:"size:64"`
}

func (dedupKey) TableName() string { return "export_keys" }

type part struct {
	table  string
	info   FileInfo
	hash   hash.Hash
	writer io.Writer
}
type Builder struct {
	ctx       context.Context
	options   Options
	manifest  Manifest
	db        *gorm.DB
	sqliteDB  *gorm.DB
	file      *os.File
	zip       *zip.Writer
	stream    *wafsec.StreamWriter
	zipped    *countHashWriter
	wrapped   string
	active    *part
	parts     map[string]int
	total     int64
	quotaRows int
	err       error
	closed    bool
	paths     []string
	result    *Result
}

type countHashWriter struct {
	dst io.Writer
	h   hash.Hash
	n   int64
}

func (w *countHashWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 {
		_, _ = w.h.Write(p[:n])
		w.n += int64(n)
	}
	return n, err
}

type quotaWriter struct{ b *Builder }

func (w quotaWriter) Write(p []byte) (int, error) {
	if err := w.b.checkQuota(int64(len(p))); err != nil {
		return 0, err
	}
	return w.b.file.Write(p)
}

func NewBuilder(ctx context.Context, o Options) (*Builder, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if o.Format != "csv" && o.Format != "jsonl" && o.Format != "sqlite" {
		return nil, errors.New("unsupported export format")
	}
	if len(o.Tables) < 1 || len(o.Tables) > 2 || len(o.Key) == 0 || len(o.TaskID) == 0 {
		return nil, errors.New("invalid export options")
	}
	seen := map[string]bool{}
	for _, t := range o.Tables {
		if _, err := Fields(t); err != nil {
			return nil, err
		}
		if seen[t] {
			return nil, errors.New("duplicate export table")
		}
		seen[t] = true
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 10 << 30
	}
	if o.TempQuotaBytes <= 0 {
		o.TempQuotaBytes = 20 << 30
	}
	if o.PartBytes <= 0 {
		if o.Format == "csv" {
			o.PartBytes = 128 << 20
		} else {
			o.PartBytes = 256 << 20
		}
	}
	if o.CSVMaxRows <= 0 {
		o.CSVMaxRows = 100000
	}
	dir, err := filepath.Abs(filepath.Clean(o.Dir))
	if err != nil || o.Dir == "" {
		return nil, errors.New("invalid export directory")
	}
	o.Dir = dir
	if err = secureDir(dir); err != nil {
		return nil, err
	}
	o.Tables = append([]string(nil), o.Tables...)
	b := &Builder{ctx: ctx, options: o, manifest: o.Manifest, parts: map[string]int{}}
	b.manifest.SchemaVersion = "1"
	b.manifest.TaskID = o.TaskID
	b.manifest.Format = o.Format
	b.manifest.Tables = o.Tables
	b.manifest.Counts = map[string]TableCount{}
	b.manifest.Fields = map[string][]Field{}
	b.manifest.Files = nil
	if b.manifest.Timezone == "" {
		b.manifest.Timezone = "source-local; timestamps preserved"
	}
	if b.manifest.Consistency == "" {
		b.manifest.Consistency = "per-source snapshot; not a global snapshot"
	}
	b.manifest.Notes = append(b.manifest.Notes, "Only access_log and security_event; event_payload and legacy web_logs excluded.", "Deduplication is per table and req_uuid; first source wins; differing rows counted as conflicts.", "Integer fields use signed 64-bit JSON numbers; consumers must preserve precision.")
	if o.Format == "csv" {
		b.manifest.Notes = append(b.manifest.Notes, "CSV NULL and empty string both use empty cells; formula-like text (including leading whitespace/control characters) is prefixed with an apostrophe; long identifiers and timestamps are text.")
	}
	if o.Format == "sqlite" {
		b.manifest.Notes = append(b.manifest.Notes, "SQLite requires a compatible encrypted SQLite driver and this instance log database key; no key is included.")
	}
	for _, t := range o.Tables {
		b.manifest.Counts[t] = TableCount{}
		b.manifest.Fields[t], _ = Fields(t)
	}
	if err = b.checkQuota(0); err != nil {
		return nil, err
	}
	fail := func(e error) (*Builder, error) { _ = b.Abort(); return nil, e }
	b.db, err = b.openDB("dedup.encrypted.db")
	if err != nil {
		return fail(err)
	}
	if err = b.db.AutoMigrate(&dedupKey{}); err != nil {
		return fail(errors.New("initialize export deduplication"))
	}
	if o.Format == "sqlite" {
		b.sqliteDB, err = b.openDB("logs.encrypted.db")
		if err != nil {
			return fail(err)
		}
		for _, t := range o.Tables {
			if err = b.sqliteDB.Exec(sqliteSchemas[t]).Error; err != nil {
				return fail(errors.New("initialize export database"))
			}
		}
	}
	b.file, err = b.create("logs.zip.enc")
	if err != nil {
		return fail(err)
	}
	key, wrapped, err := wafsec.NewStreamKey()
	if err != nil {
		return fail(err)
	}
	b.wrapped = wrapped
	b.stream, err = wafsec.NewStreamWriter(quotaWriter{b}, key, o.TaskID)
	clear(key)
	if err != nil {
		return fail(err)
	}
	b.zipped = &countHashWriter{dst: b.stream, h: sha256.New()}
	b.zip = zip.NewWriter(b.zipped)
	return b, nil
}

func secureDir(dir string) error {
	for path := dir; ; path = filepath.Dir(path) {
		fi, err := os.Lstat(path)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
				return errors.New("invalid export directory component")
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		next := filepath.Dir(path)
		if next == path {
			break
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for path := dir; ; path = filepath.Dir(path) {
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return errors.New("invalid export directory component")
		}
		next := filepath.Dir(path)
		if next == path {
			break
		}
	}
	return nil
}

func (b *Builder) create(name string) (*os.File, error) {
	path := filepath.Join(b.options.Dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		b.paths = append(b.paths, path)
	}
	return f, err
}
func (b *Builder) openDB(name string) (*gorm.DB, error) {
	f, err := b.create(name)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	dsn := filepath.ToSlash(filepath.Join(b.options.Dir, name)) + "?_db_key=" + url.QueryEscape(b.options.Key) + "&_journal_mode=MEMORY&_synchronous=FULL&_temp_store=MEMORY"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent), SkipDefaultTransaction: true})
	if err != nil {
		return nil, errors.New("open encrypted export database")
	}
	raw, err := db.DB()
	if err != nil {
		return nil, err
	}
	raw.SetMaxOpenConns(1)
	if err = db.Exec("PRAGMA temp_store=MEMORY").Error; err != nil {
		_ = raw.Close()
		return nil, err
	}
	return db, nil
}

func (b *Builder) checkQuota(extra int64) error {
	if err := b.ctx.Err(); err != nil {
		return err
	}
	var total int64
	err := filepath.WalkDir(b.options.Dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("export directory contains symlink")
		}
		if !d.IsDir() {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			if !fi.Mode().IsRegular() {
				return errors.New("invalid export file")
			}
			total += fi.Size()
		}
		return nil
	})
	if err != nil {
		return err
	}
	if extra < 0 || total > b.options.TempQuotaBytes-extra {
		return ErrQuota
	}
	if b.options.MinFreeBytes > 0 {
		usage, err := disk.Usage(b.options.Dir)
		if err != nil {
			return err
		}
		if usage.Free < b.options.MinFreeBytes || uint64(extra) > usage.Free-b.options.MinFreeBytes {
			return ErrQuota
		}
	}
	return nil
}

func (b *Builder) SetSources(sources []SourceStatus) {
	b.manifest.Sources = append([]SourceStatus(nil), sources...)
}
func (b *Builder) Stats() Stats {
	counts := map[string]TableCount{}
	for k, v := range b.manifest.Counts {
		counts[k] = v
	}
	return Stats{Counts: counts, Bytes: b.total}
}
func (b *Builder) fail(err error) error {
	if b.err == nil {
		b.err = err
	}
	return err
}

func (b *Builder) AddBatch(table string, rows []map[string]interface{}) error {
	if b.closed {
		return ErrClosed
	}
	if b.err != nil {
		return b.err
	}
	count, ok := b.manifest.Counts[table]
	if !ok {
		return b.fail(errors.New("unselected export table"))
	}
	for i, row := range rows {
		if i == 0 || b.quotaRows >= 64 {
			if err := b.checkQuota(0); err != nil {
				return b.fail(err)
			}
			b.quotaRows = 0
		}
		count.Read++
		b.manifest.Counts[table] = count
		normalized, err := normalize(table, row)
		if err != nil {
			return b.fail(err)
		}
		encoded, err := json.Marshal(normalized)
		if err != nil {
			return b.fail(err)
		}
		digest := sha256.Sum256(encoded)
		key := dedupKey{Table: table, ReqUUID: normalized["req_uuid"].(string), Digest: hex.EncodeToString(digest[:])}
		var old []dedupKey
		err = b.db.WithContext(b.ctx).Where("table_name = ? AND req_uuid = ?", table, key.ReqUUID).Find(&old).Error
		if err != nil {
			return b.fail(fmt.Errorf("read export deduplication: %w", err))
		}
		if len(old) > 0 {
			count.Skipped++
			if old[0].Digest != key.Digest {
				count.Conflicts++
			}
			b.manifest.Counts[table] = count
			continue
		}
		var data []byte
		if b.options.Format == "csv" {
			data, err = b.csvRow(table, normalized)
		} else {
			data = append(encoded, '\n')
		}
		if err != nil {
			return b.fail(err)
		}
		if b.total > b.options.MaxBytes-int64(len(data)) {
			return b.fail(ErrQuota)
		}
		// Reserve enough disk space before database growth and compressed output.
		if err = b.checkQuota(int64(len(data))*2 + 65536); err != nil {
			return b.fail(err)
		}
		if b.options.Format == "sqlite" {
			err = b.sqliteDB.WithContext(b.ctx).Table(table).Create(normalized).Error
		} else {
			err = b.writeRow(table, data)
		}
		if err != nil {
			return b.fail(err)
		}
		if err = b.db.WithContext(b.ctx).Create(&key).Error; err != nil {
			return b.fail(errors.New("write export deduplication"))
		}
		b.total += int64(len(data))
		count.Written++
		b.quotaRows++
		b.manifest.Counts[table] = count
	}
	if err := b.checkQuota(0); err != nil {
		return b.fail(err)
	}
	return nil
}

func (b *Builder) csvRow(table string, row map[string]interface{}) ([]byte, error) {
	fields, _ := Fields(table)
	cells := make([]string, len(fields))
	for i, f := range fields {
		cells[i] = csvText(row[f.Name])
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(cells); err != nil {
		return nil, err
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}
func (b *Builder) finishPart() {
	if b.active == nil {
		return
	}
	b.active.info.SHA256 = hex.EncodeToString(b.active.hash.Sum(nil))
	b.manifest.Files = append(b.manifest.Files, b.active.info)
	b.active = nil
}
func (b *Builder) startPart(table string) error {
	b.finishPart()
	b.parts[table]++
	name := fmt.Sprintf("%s/part-%06d.%s", table, b.parts[table], b.options.Format)
	w, err := b.zip.Create(name)
	if err != nil {
		return err
	}
	p := &part{table: table, info: FileInfo{Name: name}, hash: sha256.New()}
	p.writer = io.MultiWriter(w, p.hash)
	b.active = p
	if b.options.Format == "csv" {
		var buf bytes.Buffer
		buf.Write([]byte{0xef, 0xbb, 0xbf})
		cw := csv.NewWriter(&buf)
		fields, _ := Fields(table)
		header := make([]string, len(fields))
		for i, f := range fields {
			header[i] = f.Name
		}
		if err = cw.Write(header); err != nil {
			return err
		}
		cw.Flush()
		if err = cw.Error(); err != nil {
			return err
		}
		if _, err = p.writer.Write(buf.Bytes()); err != nil {
			return err
		}
		p.info.Bytes += int64(buf.Len())
	}
	return nil
}
func (b *Builder) writeRow(table string, data []byte) error {
	if b.active == nil || b.active.table != table || (b.active.info.Rows > 0 && (b.active.info.Bytes+int64(len(data)) > b.options.PartBytes || (b.options.Format == "csv" && b.active.info.Rows >= b.options.CSVMaxRows))) {
		if err := b.startPart(table); err != nil {
			return err
		}
	}
	if err := streamWrite(b.active.writer, data); err != nil {
		return err
	}
	b.active.info.Bytes += int64(len(data))
	b.active.info.Rows++
	return nil
}
func streamWrite(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func (b *Builder) Close() (*Result, error) {
	if b.closed {
		if b.result != nil {
			return b.result, nil
		}
		if b.err != nil {
			return nil, b.err
		}
		return nil, ErrClosed
	}
	if b.err != nil {
		err := b.err
		_ = b.Abort()
		return nil, err
	}
	if err := b.closePackage(); err != nil {
		b.err = err
		_ = b.Abort()
		return nil, err
	}
	b.closed = true
	info, err := b.file.Stat()
	if err != nil {
		_ = b.Abort()
		return nil, err
	}
	if err = b.file.Close(); err != nil {
		_ = b.Abort()
		return nil, err
	}
	b.result = &Result{Path: b.file.Name(), Manifest: b.manifest, Size: info.Size(), ZIPBytes: b.zipped.n, SHA256: hex.EncodeToString(b.zipped.h.Sum(nil)), WrappedKey: b.wrapped}
	return b.result, nil
}
func closeDB(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	raw, err := db.DB()
	if err != nil {
		return err
	}
	return raw.Close()
}
func (b *Builder) closePackage() error {
	if err := b.checkQuota(0); err != nil {
		return err
	}
	if b.options.Format == "sqlite" {
		for _, t := range b.options.Tables {
			if err := b.sqliteDB.Exec(sqliteIndexes[t]).Error; err != nil {
				return errors.New("index export database")
			}
			if err := b.checkQuota(0); err != nil {
				return err
			}
		}
		if err := closeDB(b.sqliteDB); err != nil {
			return err
		}
		b.sqliteDB = nil
		f, err := os.Open(filepath.Join(b.options.Dir, "logs.encrypted.db"))
		if err != nil {
			return err
		}
		w, err := b.zip.Create("logs.encrypted.db")
		if err != nil {
			_ = f.Close()
			return err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(w, h), &contextReader{ctx: b.ctx, reader: f})
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		var rows int64
		for _, c := range b.manifest.Counts {
			rows += c.Written
		}
		b.manifest.Files = append(b.manifest.Files, FileInfo{Name: "logs.encrypted.db", Bytes: n, Rows: rows, SHA256: hex.EncodeToString(h.Sum(nil))})
	} else {
		b.finishPart()
		for _, t := range b.options.Tables {
			if b.parts[t] == 0 {
				if err := b.startPart(t); err != nil {
					return err
				}
				b.finishPart()
			}
		}
	}
	if err := closeDB(b.db); err != nil {
		return err
	}
	b.db = nil
	b.manifest.GeneratedAt = time.Now().UTC()
	w, err := b.zip.Create("manifest.json")
	if err != nil {
		return err
	}
	if err = json.NewEncoder(w).Encode(b.manifest); err != nil {
		return err
	}
	w, err = b.zip.Create("README.txt")
	if err != nil {
		return err
	}
	if _, err = io.WriteString(w, "SamWaf log export schema v1\n"+strings.Join(b.manifest.Notes, "\n")+"\nSee manifest.json for fields, counts and source status.\n"); err != nil {
		return err
	}
	if err = b.zip.Close(); err != nil {
		return err
	}
	if err = b.stream.Close(); err != nil {
		return err
	}
	if err = b.file.Sync(); err != nil {
		return err
	}
	for _, path := range b.paths {
		if path == b.file.Name() {
			continue
		}
		if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return b.checkQuota(0)
}
func (b *Builder) Abort() error {
	b.closed = true
	_ = closeDB(b.db)
	b.db = nil
	_ = closeDB(b.sqliteDB)
	b.sqliteDB = nil
	if b.file != nil {
		_ = b.file.Close()
	}
	var first error
	for _, p := range b.paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	return first
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

type archiveReader struct {
	io.Reader
	f *os.File
}

func (r *archiveReader) Close() error { return r.f.Close() }
func OpenArchive(path, wrappedKey, taskID string) (io.ReadCloser, error) {
	key, err := wafsec.UnwrapStreamKey(wrappedKey)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	fi, err := os.Lstat(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("invalid export archive")
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	reader, err := wafsec.NewStreamReader(f, key, taskID)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &archiveReader{Reader: reader, f: f}, nil
}
