package wafdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/utils"
	"SamWaf/wafdb/dialect"
	"SamWaf/waflogexport"
	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	ErrExportSourceMapping  = errors.New("EXPORT_SOURCE_MAPPING_UNRESOLVED")
	ErrExportSourcePressure = errors.New("EXPORT_SOURCE_PRESSURE")
)

const DefaultExportSQLiteWALBytes int64 = 2 * 1024 * 1024 * 1024

// ExportReadOptions applies to source storage, independently of output quotas.
type ExportReadOptions struct {
	MaxSQLiteWALBytes int64
	BatchTimeout      time.Duration
}

type ExportRowBatch struct {
	Table string
	Rows  []map[string]interface{}
}
type ExportTableStatus struct {
	State          string   `json:"state"`
	MissingColumns []string `json:"missing_columns,omitempty"`
	Rows           int64    `json:"rows"`
}
type ExportSourceStatus struct {
	Driver       string                       `json:"driver"`
	SnapshotTime time.Time                    `json:"snapshot_time"`
	EndTime      string                       `json:"end_time"`
	Tables       map[string]ExportTableStatus `json:"tables"`
}

var exportSuffixRE = regexp.MustCompile(`^(?:[0-9]{6}(?:_[0-9]{2,})?|[0-9]{8}|[0-9]{14})$`)

// ReadExportSource requires the caller's read lease from enumeration through completion.
func ReadExportSource(ctx context.Context, ident, tenant, start, end string, tables []string, onBatch func(ExportRowBatch) error) (ExportSourceStatus, error) {
	return ReadExportSourceWithOptions(ctx, ident, tenant, start, end, tables, onBatch, ExportReadOptions{})
}

func ReadExportSourceWithOptions(ctx context.Context, ident, tenant, start, end string, tables []string, onBatch func(ExportRowBatch) error, opts ExportReadOptions) (status ExportSourceStatus, err error) {
	status = ExportSourceStatus{Driver: dialect.Get().Name(), EndTime: end, Tables: map[string]ExportTableStatus{}}
	if tenant == "" || end == "" || onBatch == nil || len(tables) < 1 || len(tables) > 2 {
		return status, errors.New("invalid export source arguments")
	}
	const layout = "2006-01-02 15:04:05"
	hi, err := time.ParseInLocation(layout, end, time.Local)
	if err != nil {
		return status, errors.New("invalid export end boundary")
	}
	if start != "" {
		lo, e := time.ParseInLocation(layout, start, time.Local)
		if e != nil || !lo.Before(hi) {
			return status, errors.New("invalid export start boundary")
		}
	}
	seen := map[string]bool{}
	for _, table := range tables {
		if _, e := waflogexport.Fields(table); e != nil || seen[table] {
			return status, errors.New("invalid export table selection")
		}
		seen[table] = true
	}
	if opts.MaxSQLiteWALBytes == 0 {
		opts.MaxSQLiteWALBytes = DefaultExportSQLiteWALBytes
	}
	if opts.MaxSQLiteWALBytes < 0 {
		return status, errors.New("invalid source WAL budget")
	}
	if opts.BatchTimeout == 0 {
		opts.BatchTimeout = 30 * time.Second
	}
	if opts.BatchTimeout < 0 || opts.BatchTimeout > 30*time.Second {
		return status, errors.New("invalid source batch timeout")
	}
	db, suffix, walPath, closeDB, err := openExportSource(ctx, ident)
	if err != nil {
		return status, err
	}
	defer func() {
		if e := closeDB(); err == nil && e != nil {
			err = e
		}
	}()
	if err = checkExportWAL(walPath, opts.MaxSQLiteWALBytes); err != nil {
		return status, err
	}
	txopts := &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}
	if status.Driver == "sqlite" {
		txopts.Isolation = sql.LevelDefault
	}
	tx := db.WithContext(ctx).Begin(txopts)
	if tx.Error != nil {
		return status, tx.Error
	}
	defer tx.Rollback()
	// The first metadata read pins SQLite's snapshot; server engines pin it on first data read.
	mctx, mcancel := context.WithTimeout(ctx, opts.BatchTimeout)
	existing, err := dialect.Get().ListTables(tx.WithContext(mctx))
	mcancel()
	if err != nil {
		return status, err
	}
	names := make(map[string]bool, len(existing))
	for _, name := range existing {
		names[name] = true
	}
	if suffix != "" && !names[model.AccessLogTableName+suffix] && !names[model.SecurityEventTableName+suffix] {
		return status, ErrExportSourceMapping
	}
	type readTable struct {
		logical, physical string
		columns           []string
	}
	plans := []readTable{}
	for _, table := range tables {
		physical := table + suffix
		if !names[physical] {
			status.Tables[table] = ExportTableStatus{State: "missing"}
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, opts.BatchTimeout)
		cols, e := dialect.Get().ColumnInfo(tx.WithContext(cctx), physical)
		cancel()
		if e != nil {
			return status, e
		}
		available := map[string]bool{}
		for _, col := range cols {
			available[strings.ToLower(col.Name)] = true
		}
		for _, required := range []string{"req_uuid", "create_time", "tenant_id", "user_code"} {
			if !available[required] {
				return status, fmt.Errorf("EXPORT_SOURCE_REQUIRED_COLUMN: %s", required)
			}
		}
		fields, _ := waflogexport.Fields(table)
		ts := ExportTableStatus{State: "ready"}
		p := readTable{logical: table, physical: physical}
		for _, field := range fields {
			if available[field.Column] {
				p.columns = append(p.columns, field.Column)
			} else {
				ts.MissingColumns = append(ts.MissingColumns, field.Column)
			}
		}
		status.Tables[table] = ts
		plans = append(plans, p)
	}
	// Pin the server snapshot before any consumer callback can run.
	for _, p := range plans {
		var first []map[string]interface{}
		qctx, cancel := context.WithTimeout(ctx, opts.BatchTimeout)
		e := tx.WithContext(qctx).Table(p.physical).Select("req_uuid").Where("tenant_id = ? AND user_code = ?", tenant, global.GWAF_USER_CODE).Limit(1).Find(&first).Error
		cancel()
		if e != nil {
			return status, e
		}
	}
	status.SnapshotTime = time.Now()
	for _, p := range plans {
		cursor := ""
		for {
			if e := ctx.Err(); e != nil {
				return status, e
			}
			if e := checkExportWAL(walPath, opts.MaxSQLiteWALBytes); e != nil {
				return status, e
			}
			var rows []map[string]interface{}
			qctx, cancel := context.WithTimeout(ctx, opts.BatchTimeout)
			q := tx.WithContext(qctx).Table(p.physical).Select(p.columns).Where("tenant_id = ? AND user_code = ?", tenant, global.GWAF_USER_CODE).Where("create_time < ?", end)
			if start != "" {
				q = q.Where("create_time >= ?", start)
			}
			if cursor != "" {
				q = q.Where("req_uuid > ?", cursor)
			}
			e := q.Order("req_uuid ASC").Limit(exportBatchSize).Find(&rows).Error
			cancel()
			if e != nil {
				return status, e
			}
			if len(rows) == 0 {
				break
			}
			for _, row := range rows {
				for k, v := range row {
					if b, ok := v.([]byte); ok {
						row[k] = string(b)
					}
				}
				for _, missing := range status.Tables[p.logical].MissingColumns {
					row[missing] = nil
				}
			}
			last, ok := rows[len(rows)-1]["req_uuid"].(string)
			if !ok || last == "" || (cursor != "" && last <= cursor) {
				return status, errors.New("EXPORT_SOURCE_INVALID_CURSOR")
			}
			if e := onBatch(ExportRowBatch{Table: p.logical, Rows: rows}); e != nil {
				return status, e
			}
			ts := status.Tables[p.logical]
			ts.Rows += int64(len(rows))
			status.Tables[p.logical] = ts
			cursor = last
			if e := checkExportWAL(walPath, opts.MaxSQLiteWALBytes); e != nil {
				return status, e
			}
			if len(rows) < exportBatchSize {
				break
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return status, err
	}
	// Read transactions release their snapshot without a commit/write path.
	err = tx.Rollback().Error
	return status, err
}

func checkExportWAL(path string, max int64) error {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path + "-wal")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Size() > max {
		return ErrExportSourcePressure
	}
	return nil
}

func openExportSource(ctx context.Context, ident string) (*gorm.DB, string, string, func() error, error) {
	noop := func() error { return nil }
	live := isLiveIdent(ident)
	if !dialect.Get().IsFileBased() {
		db := global.GWAF_LOCAL_LOG_DB
		if db == nil {
			return nil, "", "", noop, errors.New("log database unavailable")
		}
		if live {
			return db, "", "", noop, nil
		}
		for _, base := range []string{model.AccessLogTableName, LogTableName} {
			if strings.HasPrefix(ident, base+"_") {
				suffix := strings.TrimPrefix(ident, base+"_")
				if exportSuffixRE.MatchString(suffix) {
					return db, "_" + suffix, "", noop, nil
				}
			}
		}
		return nil, "", "", noop, errors.New("invalid export source identifier")
	}
	if live {
		if global.GWAF_LOCAL_LOG_DB == nil {
			return nil, "", "", noop, errors.New("log database unavailable")
		}
		// PRAGMA database_list is connection metadata and does not access log rows.
		var files []struct {
			Name string
			File string
		}
		if err := global.GWAF_LOCAL_LOG_DB.WithContext(ctx).Raw("PRAGMA database_list").Scan(&files).Error; err != nil {
			return nil, "", "", noop, err
		}
		path := ""
		for _, file := range files {
			if file.Name == "main" {
				path = file.File
			}
		}
		return global.GWAF_LOCAL_LOG_DB, "", path, noop, nil
	}
	path, err := ShardFilePath(ident)
	if err != nil {
		return nil, "", "", noop, err
	}
	path = filepath.Clean(path)
	root := filepath.Clean(filepath.Join(utils.GetCurrentDir(), "data"))
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, "", "", noop, errors.New("invalid archive path")
	}
	actualRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, "", "", noop, err
	}
	actual, err := filepath.EvalSymlinks(path)
	if os.IsNotExist(err) {
		return nil, "", "", noop, ErrShardMissing
	}
	if err != nil {
		return nil, "", "", noop, err
	}
	actualRel, err := filepath.Rel(actualRoot, actual)
	if err != nil || actualRel == ".." || strings.HasPrefix(actualRel, ".."+string(filepath.Separator)) {
		return nil, "", "", noop, errors.New("invalid archive path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, "", "", noop, err
	}
	if !info.Mode().IsRegular() {
		return nil, "", "", noop, errors.New("archive is not a regular file")
	}
	params := url.Values{"mode": {"ro"}, "_query_only": {"1"}, "_db_key": {global.GWAF_PWD_LOGDB}, "_busy_timeout": {"5000"}, "_cache_size": {"-8192"}}
	db, err := gorm.Open(sqlite.Open("file:"+filepath.ToSlash(path)+"?"+params.Encode()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, "", "", noop, errors.New("EXPORT_SOURCE_OPEN_FAILED")
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, "", "", noop, err
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	db.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", before_query)
	db.Callback().Query().Before("gorm:update").Register("tenant_plugin:before_update", before_update)
	return db, "", path, sqlDB.Close, nil
}
