package wafdb

import (
	"SamWaf/global"
	"SamWaf/utils"
	"SamWaf/wafdb/dialect"
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ===========================================================================
// Checkpoint model
// ===========================================================================

// MigrationCheckpoint tracks per-table migration progress.
// Stored in the MySQL core database (_migration_checkpoint table).
type MigrationCheckpoint struct {
	SrcDB        string    `gorm:"column:src_db;primaryKey;size:32"`
	TblName      string    `gorm:"column:table_name;primaryKey;size:128"`
	TotalRows    int64     `gorm:"column:total_rows"`
	CopiedRows   int64     `gorm:"column:copied_rows"`
	LastCursor   int64     `gorm:"column:last_cursor"`    // = OFFSET position
	Status       string    `gorm:"column:status;size:16"` // pending/running/done/failed
	StartedAt    time.Time `gorm:"column:started_at"`
	UpdatedAt    time.Time `gorm:"column:updated_at"`
	ErrorMessage string    `gorm:"column:error_message;type:text"`
}

func (MigrationCheckpoint) TableName() string { return "_migration_checkpoint" }

// ===========================================================================
// Options and result types
// ===========================================================================

// MigrateOptions controls migration behaviour.
type MigrateOptions struct {
	DryRun     bool
	Force      bool
	BatchSize  int
	CurrentDir string
}

type tableMigrateResult struct {
	Name     string
	SrcRows  int64
	DstRows  int64
	Status   string // "ok" | "skipped" | "failed" | "dry-run"
	Error    string
	Duration time.Duration
}

type dbMigrateResult struct {
	SrcLabel string
	DstLabel string
	Tables   []tableMigrateResult
}

// ===========================================================================
// Tables that must not be copied
// ===========================================================================

var migrateSkipTables = map[string]bool{
	"migrations":            true, // gormigrate internal
	"_migration_checkpoint": true, // this tool's own table
}

// ===========================================================================
// MigrateTool
// ===========================================================================

// MigrateTool runs offline SQLite → MySQL data migration with checkpoint/resume.
type MigrateTool struct {
	opts    MigrateOptions
	cpDB    *gorm.DB // checkpoint DB (MySQL core)
	results []dbMigrateResult
	startAt time.Time
}

// RunMigrateDB is the entry point called from the CLI (samwaf migratedb).
func RunMigrateDB(opts MigrateOptions) error {
	if opts.BatchSize <= 0 {
		opts.BatchSize = 1000
	}
	if opts.CurrentDir == "" {
		opts.CurrentDir = utils.GetCurrentDir()
	}
	t := &MigrateTool{opts: opts, startAt: time.Now()}
	return t.run()
}

func (t *MigrateTool) run() error {
	fmt.Println("================================================")
	fmt.Println("         SamWaf 数据迁移工具 (SQLite → MySQL)")
	fmt.Println("================================================")

	if t.opts.DryRun {
		fmt.Println(">>> DRY-RUN 模式：只做预估，不写入任何数据 <<<")
	}
	if t.opts.Force {
		fmt.Println(">>> FORCE 模式：目标表已有数据时强制覆盖 <<<")
	}

	fmt.Println()
	fmt.Println("  ⚠️  重要提示：迁移期间请确保 SamWaf 服务已停止运行！")
	fmt.Println("     运行中迁移可能导致数据不完整或丢失。")
	fmt.Println("     建议步骤：停止服务 → 运行迁移 → 验证数据 → 切换驱动 → 重启服务")
	fmt.Println()

	// 1. 交互式采集 MySQL 连接参数
	if err := t.promptMySQLConfig(); err != nil {
		return err
	}

	// 2. 注册 MySQL 方言（schema 迁移函数依赖 dialect.Get()）
	dialect.Register(&dialect.MySQLDialect{})

	// 3. 测试连接
	fmt.Println("\n测试 MySQL 连接...")
	testDB, testErr := openMySQLDB(global.GWAF_MYSQL_CORE_DB)
	if testErr != nil {
		return fmt.Errorf("MySQL 连接失败: %w\n请检查连接参数后重试", testErr)
	}
	if sqlDB, e := testDB.DB(); e == nil {
		sqlDB.Close()
	}
	fmt.Println("连接成功 ✓")

	fmt.Printf("\n批大小   : %d 行/批\n", t.opts.BatchSize)
	fmt.Printf("数据目录 : %s/data\n", t.opts.CurrentDir)

	// 4. 选择迁移范围
	type migPair struct {
		srcPath   string
		srcKey    string
		srcLabel  string
		dstDBName string
		dstLabel  string
		schemaMig func(*gorm.DB) error
	}

	allPairs := []migPair{
		{
			srcPath:   filepath.Join(t.opts.CurrentDir, "data", "local.db"),
			srcKey:    global.GWAF_PWD_COREDB,
			srcLabel:  "core",
			dstDBName: global.GWAF_MYSQL_CORE_DB,
			dstLabel:  "mysql_core",
			schemaMig: func(db *gorm.DB) error {
				if err := RunCoreDBMigrations(db); err != nil {
					return err
				}
				return RunTaskInitMigrations(db)
			},
		},
		{
			srcPath:   filepath.Join(t.opts.CurrentDir, "data", "local_log.db"),
			srcKey:    global.GWAF_PWD_LOGDB,
			srcLabel:  "log",
			dstDBName: global.GWAF_MYSQL_LOG_DB,
			dstLabel:  "mysql_log",
			schemaMig: RunLogDBMigrations,
		},
		{
			srcPath:   filepath.Join(t.opts.CurrentDir, "data", "local_stats.db"),
			srcKey:    global.GWAF_PWD_STATDB,
			srcLabel:  "stats",
			dstDBName: global.GWAF_MYSQL_STATS_DB,
			dstLabel:  "mysql_stats",
			schemaMig: RunStatsDBMigrations,
		},
	}

	scopeReader := bufio.NewReader(os.Stdin)
	fmt.Println("\n请选择迁移范围：")
	fmt.Println("  1. 仅迁移核心库 (core)")
	fmt.Println("  2. 迁移全部（核心库 + 日志库 + 统计库）[默认]")
	scopeLine, scopeErr := readLine(scopeReader, "请输入选项", "2")
	if scopeErr != nil {
		fmt.Println("已取消。")
		return nil
	}

	var pairs []migPair
	switch scopeLine {
	case "1":
		pairs = allPairs[:1]
		fmt.Println("已选择：仅核心库")
	default:
		pairs = allPairs
		fmt.Println("已选择：全部（核心库 + 日志库 + 统计库）")
	}

	// 5. 迁移前行数预览（打开每个 SQLite，统计表数和总行数）
	fmt.Println("\n数据预览（SQLite 源库行数）：")
	fmt.Printf("  %-8s  %-30s  %8s  %12s\n", "库", "文件", "表数量", "总行数")
	fmt.Println("  " + strings.Repeat("-", 62))
	var totalTables, totalRows int64
	for _, p := range pairs {
		if _, statErr := os.Stat(p.srcPath); os.IsNotExist(statErr) {
			fmt.Printf("  %-8s  %-30s  %8s  %12s\n", p.srcLabel, filepath.Base(p.srcPath), "-", "文件不存在")
			continue
		}
		tblCnt, rowCnt, surveyErr := t.surveySource(p.srcPath, p.srcKey)
		if surveyErr != nil {
			fmt.Printf("  %-8s  %-30s  %8s  %12s\n", p.srcLabel, filepath.Base(p.srcPath), "?", "读取失败")
			continue
		}
		fmt.Printf("  %-8s  %-30s  %8d  %12d\n", p.srcLabel, filepath.Base(p.srcPath), tblCnt, rowCnt)
		totalTables += tblCnt
		totalRows += rowCnt
	}
	fmt.Println("  " + strings.Repeat("-", 62))
	fmt.Printf("  %-39s  %8d  %12d\n", "合计", totalTables, totalRows)

	// 6. 确认后才开始写入（dry-run 跳过）
	if !t.opts.DryRun {
		fmt.Println()
		confirmReader := bufio.NewReader(os.Stdin)
		answer, confirmErr := readLine(confirmReader, "确认将以上 SQLite 数据迁移到 MySQL？[y/N]", "")
		if confirmErr != nil {
			fmt.Println("已取消。")
			return nil
		}
		if strings.ToLower(answer) != "y" && strings.ToLower(answer) != "yes" {
			fmt.Println("已取消迁移。")
			return nil
		}
		fmt.Println()
	}

	// 7. 建 checkpoint 表
	coreDB, err := openMySQLDB(global.GWAF_MYSQL_CORE_DB)
	if err != nil {
		return fmt.Errorf("连接 MySQL 核心库失败: %w", err)
	}
	t.cpDB = coreDB

	if !t.opts.DryRun {
		if err := coreDB.AutoMigrate(&MigrationCheckpoint{}); err != nil {
			return fmt.Errorf("创建 checkpoint 表失败: %w", err)
		}
	}

	for _, p := range pairs {
		fmt.Printf("\n--- [%s] %s → %s ---\n", time.Now().Format("15:04:05"), p.srcLabel, p.dstLabel)

		if _, statErr := os.Stat(p.srcPath); os.IsNotExist(statErr) {
			fmt.Printf("  源文件不存在，跳过: %s\n", p.srcPath)
			t.results = append(t.results, dbMigrateResult{SrcLabel: p.srcLabel, DstLabel: p.dstLabel})
			continue
		}

		srcDB, openErr := t.openSQLiteSource(p.srcPath, p.srcKey)
		if openErr != nil {
			return fmt.Errorf("打开源数据库 %s 失败: %w", p.srcPath, openErr)
		}

		dstDB, dstErr := openMySQLDB(p.dstDBName)
		if dstErr != nil {
			return fmt.Errorf("打开目标数据库 %s 失败: %w", p.dstDBName, dstErr)
		}

		if !t.opts.DryRun {
			fmt.Printf("  [schema] 在 MySQL 上创建/同步表结构...\n")
			if schemaErr := p.schemaMig(dstDB); schemaErr != nil {
				return fmt.Errorf("[%s] schema 迁移失败: %w", p.srcLabel, schemaErr)
			}
			fmt.Printf("  [schema] 完成\n")
		}

		result := t.migrateOneDB(srcDB, p.srcLabel, dstDB, p.dstLabel)
		t.results = append(t.results, result)

		if sqlDB, e := srcDB.DB(); e == nil {
			sqlDB.Close()
		}
		if sqlDB, e := dstDB.DB(); e == nil {
			sqlDB.Close()
		}
	}

	// Generate and save Markdown report
	report := t.generateReport()
	reportPath, saveErr := t.saveReport(report)

	fmt.Println("\n================================================")
	fmt.Print(report)
	fmt.Println("================================================")

	// 报告路径单独突出显示
	if saveErr != nil {
		fmt.Printf("\n⚠  迁移报告保存失败: %v\n", saveErr)
	} else {
		fmt.Println()
		fmt.Println("📄 迁移报告已保存：")
		fmt.Printf("      %s\n", reportPath)
	}

	// 迁移完成后，若无失败且非 dry-run，询问是否写入 config.yml
	if !t.opts.DryRun && t.countFailed() == 0 {
		cfgReader := bufio.NewReader(os.Stdin)
		answer, cfgErr := readLine(cfgReader, "迁移成功，是否将 config.yml 切换为 MySQL 驱动？[Y/n]", "y")
		if cfgErr != nil {
			fmt.Println("已跳过 config.yml 更新。")
			return nil
		}
		if answer == "" || strings.ToLower(answer) == "y" || strings.ToLower(answer) == "yes" {
			if cfgErr := t.saveMySQLToConfig(); cfgErr != nil {
				fmt.Printf("警告：config.yml 写入失败: %v\n", cfgErr)
			} else {
				fmt.Println("config.yml 已更新，下次启动将使用 MySQL 数据库。")
			}
		} else {
			fmt.Println("config.yml 未修改，如需切换请手动更新 database.driver: mysql。")
		}
	} else if t.countFailed() > 0 {
		fmt.Printf("\n有 %d 张表迁移失败，config.yml 未修改。修复后可重新运行（支持断点续传）。\n",
			t.countFailed())
	}

	return nil
}

// surveySource opens a SQLite source and returns (tableCount, totalRowCount, error).
func (t *MigrateTool) surveySource(srcPath, srcKey string) (int64, int64, error) {
	db, err := t.openSQLiteSource(srcPath, srcKey)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if sqlDB, e := db.DB(); e == nil {
			sqlDB.Close()
		}
	}()

	tables, err := listSQLiteUserTables(db)
	if err != nil {
		return 0, 0, err
	}

	var totalRows int64
	for _, tbl := range tables {
		if migrateSkipTables[tbl] {
			continue
		}
		var cnt int64
		db.Table(tbl).Count(&cnt)
		totalRows += cnt
	}
	return int64(len(tables)), totalRows, nil
}

// countFailed returns the total number of failed tables across all DB results.
func (t *MigrateTool) countFailed() int {
	n := 0
	for _, dr := range t.results {
		for _, tr := range dr.Tables {
			if tr.Status == "failed" {
				n++
			}
		}
	}
	return n
}

// errCancelled is returned when the user presses Ctrl+Z / Ctrl+D (EOF on stdin).
var errCancelled = fmt.Errorf("用户已取消")

// readLine reads one line from r, trims whitespace, and returns the default value
// when the user presses Enter without typing anything.
// Returns ("", errCancelled) on EOF (Ctrl+Z on Windows, Ctrl+D on Linux/Mac).
func readLine(r *bufio.Reader, prompt, defaultVal string) (string, error) {
	if defaultVal != "" {
		fmt.Printf("  %s [%s]: ", prompt, defaultVal)
	} else {
		fmt.Printf("  %s: ", prompt)
	}
	line, err := r.ReadString('\n')
	if err == io.EOF {
		fmt.Println()
		return "", errCancelled
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal, nil
	}
	return line, nil
}

// promptMySQLConfig interactively reads MySQL connection parameters from stdin.
// Returns errCancelled when the user presses Ctrl+Z / Ctrl+D at any prompt.
func (t *MigrateTool) promptMySQLConfig() error {
	r := bufio.NewReader(os.Stdin)

	must := func(field *string, prompt, def string) error {
		v, err := readLine(r, prompt, def)
		if err != nil {
			return err
		}
		*field = v
		return nil
	}

	fmt.Println("\n请输入 MySQL 连接信息（直接回车使用默认值，Ctrl+Z/Ctrl+D 退出）：")

	if err := must(&global.GWAF_MYSQL_HOST, "主机", global.GWAF_MYSQL_HOST); err != nil {
		return err
	}
	portStr, err := readLine(r, "端口", strconv.Itoa(global.GWAF_MYSQL_PORT))
	if err != nil {
		return err
	}
	if p, e := strconv.Atoi(portStr); e == nil && p > 0 {
		global.GWAF_MYSQL_PORT = p
	}
	if err := must(&global.GWAF_MYSQL_USER, "用户名", global.GWAF_MYSQL_USER); err != nil {
		return err
	}
	if err := must(&global.GWAF_MYSQL_PASSWORD, "密码", global.GWAF_MYSQL_PASSWORD); err != nil {
		return err
	}
	if err := must(&global.GWAF_MYSQL_CORE_DB, "核心库名", global.GWAF_MYSQL_CORE_DB); err != nil {
		return err
	}
	if err := must(&global.GWAF_MYSQL_LOG_DB, "日志库名", global.GWAF_MYSQL_LOG_DB); err != nil {
		return err
	}
	if err := must(&global.GWAF_MYSQL_STATS_DB, "统计库名", global.GWAF_MYSQL_STATS_DB); err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("  MySQL  : %s@%s:%d\n", global.GWAF_MYSQL_USER, global.GWAF_MYSQL_HOST, global.GWAF_MYSQL_PORT)
	fmt.Printf("  核心库 : %s\n", global.GWAF_MYSQL_CORE_DB)
	fmt.Printf("  日志库 : %s\n", global.GWAF_MYSQL_LOG_DB)
	fmt.Printf("  统计库 : %s\n", global.GWAF_MYSQL_STATS_DB)

	return nil
}

// saveMySQLToConfig writes database.driver=mysql and all MySQL params to config.yml.
// Uses yaml.v3 Node API to preserve key order instead of viper (which sorts alphabetically).
func (t *MigrateTool) saveMySQLToConfig() error {
	configPath := filepath.Join(t.opts.CurrentDir, "conf", "config.yml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取 config.yml 失败: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("解析 config.yml 失败: %w", err)
	}
	if len(doc.Content) == 0 {
		return fmt.Errorf("config.yml 内容为空")
	}
	root := doc.Content[0] // root MappingNode

	// Ensure database: section exists
	dbNode := yamlEnsureMapping(root, "database")

	// Set database.driver = mysql
	yamlSetNode(dbNode, "driver", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "mysql"})

	// Build mysql sub-section with keys in the desired order.
	// Completely replace to guarantee ordering even on re-run.
	mysqlNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	appendStr := func(k, v string) {
		mysqlNode.Content = append(mysqlNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v},
		)
	}
	appendStr("host", global.GWAF_MYSQL_HOST)
	mysqlNode.Content = append(mysqlNode.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "port"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(global.GWAF_MYSQL_PORT)},
	)
	appendStr("user", global.GWAF_MYSQL_USER)
	appendStr("password", global.GWAF_MYSQL_PASSWORD)
	appendStr("core_db", global.GWAF_MYSQL_CORE_DB)
	appendStr("log_db", global.GWAF_MYSQL_LOG_DB)
	appendStr("stats_db", global.GWAF_MYSQL_STATS_DB)
	yamlSetNode(dbNode, "mysql", mysqlNode)

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("序列化 config.yml 失败: %w", err)
	}
	return os.WriteFile(configPath, out, 0644)
}

// yamlEnsureMapping finds or creates a MappingNode child for key under parent.
func yamlEnsureMapping(parent *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			v := parent.Content[i+1]
			if v.Kind != yaml.MappingNode {
				v.Kind = yaml.MappingNode
				v.Tag = "!!map"
				v.Value = ""
				v.Content = nil
			}
			return v
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	parent.Content = append(parent.Content, keyNode, valNode)
	return valNode
}

// yamlSetNode replaces the value node for key in a mapping, or appends if not found.
func yamlSetNode(mapping *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content[i+1] = val
			return
		}
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		val,
	)
}

// openSQLiteSource opens an encrypted SQLite database in read mode.
func (t *MigrateTool) openSQLiteSource(path, key string) (*gorm.DB, error) {
	encodedKey := url.QueryEscape(key)
	dsn := fmt.Sprintf("%s?_db_key=%s", path, encodedKey)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	return db, nil
}

// migrateOneDB migrates all user tables from one SQLite DB to one MySQL DB.
func (t *MigrateTool) migrateOneDB(srcDB *gorm.DB, srcLabel string, dstDB *gorm.DB, dstLabel string) dbMigrateResult {
	result := dbMigrateResult{SrcLabel: srcLabel, DstLabel: dstLabel}

	tables, err := listSQLiteUserTables(srcDB)
	if err != nil {
		fmt.Printf("  [%s] 获取表列表失败: %v\n", srcLabel, err)
		return result
	}
	fmt.Printf("  发现 %d 个表\n", len(tables))

	for _, tbl := range tables {
		if migrateSkipTables[tbl] {
			result.Tables = append(result.Tables, tableMigrateResult{
				Name: tbl, Status: "skipped", Error: "内部表，跳过",
			})
			continue
		}
		r := t.migrateTable(srcDB, dstDB, srcLabel, tbl)
		result.Tables = append(result.Tables, r)
	}
	return result
}

// migrateTable copies one table from SQLite to MySQL with checkpoint/resume.
func (t *MigrateTool) migrateTable(srcDB, dstDB *gorm.DB, srcLabel, tableName string) tableMigrateResult {
	start := time.Now()
	r := tableMigrateResult{Name: tableName}

	// 1. Count source rows
	var srcCount int64
	if err := srcDB.Table(tableName).Count(&srcCount).Error; err != nil {
		r.Status = "failed"
		r.Error = "count源表: " + err.Error()
		r.Duration = time.Since(start)
		return r
	}
	r.SrcRows = srcCount

	// 2. Dry-run: just report, no writes
	if t.opts.DryRun {
		fmt.Printf("  [DRY] %-45s  src=%d 行\n", tableName, srcCount)
		r.Status = "dry-run"
		r.Duration = time.Since(start)
		return r
	}

	// 3. Target table must exist (schema migration already ran)
	if !dstDB.Migrator().HasTable(tableName) {
		fmt.Printf("  SKIP %-45s  目标表不存在\n", tableName)
		r.Status = "skipped"
		r.Error = "目标表不存在（schema 未包含此表）"
		r.Duration = time.Since(start)
		return r
	}

	// 4. Get or create checkpoint
	var cp MigrationCheckpoint
	cpErr := t.cpDB.Where("src_db = ? AND table_name = ?", srcLabel, tableName).First(&cp).Error
	if cpErr != nil {
		// No checkpoint: check for existing target data
		var dstCount int64
		dstDB.Table(tableName).Count(&dstCount)
		if dstCount > 0 && !t.opts.Force {
			fmt.Printf("  SKIP %-45s  目标已有 %d 行（使用 --force 强制覆盖）\n", tableName, dstCount)
			r.Status = "skipped"
			r.Error = fmt.Sprintf("目标已有 %d 行", dstCount)
			r.Duration = time.Since(start)
			return r
		}
		cp = MigrationCheckpoint{
			SrcDB:     srcLabel,
			TblName:   tableName,
			TotalRows: srcCount,
			Status:    "pending",
			StartedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		t.cpDB.Create(&cp)
	}

	// 5. Already done
	if cp.Status == "done" {
		var dstCount int64
		dstDB.Table(tableName).Count(&dstCount)
		fmt.Printf("  DONE %-45s  src=%d dst=%d (已完成，跳过)\n", tableName, srcCount, dstCount)
		r.DstRows = dstCount
		r.Status = "ok"
		r.Duration = time.Since(start)
		return r
	}

	// 6. Get column names from SQLite PRAGMA
	cols, colErr := getSQLiteColumnNames(srcDB, tableName)
	if colErr != nil || len(cols) == 0 {
		r.Status = "failed"
		r.Error = fmt.Sprintf("获取列信息失败: %v", colErr)
		r.Duration = time.Since(start)
		return r
	}

	// Mark checkpoint as running
	t.cpDB.Model(&cp).Updates(map[string]interface{}{
		"status":     "running",
		"total_rows": srcCount,
		"updated_at": time.Now(),
	})

	// 7. Build SQL fragments (backtick-quoted, work for both SQLite and MySQL)
	quotedCols := make([]string, len(cols))
	placeholders := make([]string, len(cols))
	for i, c := range cols {
		quotedCols[i] = "`" + c + "`"
		placeholders[i] = "?"
	}
	colsStr := strings.Join(quotedCols, ", ")
	rowPlaceholder := "(" + strings.Join(placeholders, ", ") + ")"

	offset := cp.LastCursor
	copied := cp.CopiedRows

	// 8. Batch copy loop
	for {
		sqliteRows, queryErr := srcDB.Raw(
			fmt.Sprintf("SELECT %s FROM `%s` LIMIT ? OFFSET ?", colsStr, tableName),
			t.opts.BatchSize, offset,
		).Rows()
		if queryErr != nil {
			t.cpDB.Model(&cp).Updates(map[string]interface{}{
				"status": "failed", "error_message": queryErr.Error(), "updated_at": time.Now(),
			})
			r.Status = "failed"
			r.Error = "SELECT 失败: " + queryErr.Error()
			r.Duration = time.Since(start)
			return r
		}

		var batchVals []interface{}
		var batchRowPHs []string
		rowCount := 0

		for sqliteRows.Next() {
			vals := make([]interface{}, len(cols))
			valPtrs := make([]interface{}, len(cols))
			for i := range vals {
				valPtrs[i] = &vals[i]
			}
			if scanErr := sqliteRows.Scan(valPtrs...); scanErr != nil {
				sqliteRows.Close()
				r.Status = "failed"
				r.Error = "Scan 失败: " + scanErr.Error()
				r.Duration = time.Since(start)
				return r
			}
			// []byte (BLOB/TEXT in SQLite) → string so MySQL accepts it
			for i, v := range vals {
				if b, ok := v.([]byte); ok {
					vals[i] = string(b)
				}
			}
			batchRowPHs = append(batchRowPHs, rowPlaceholder)
			batchVals = append(batchVals, vals...)
			rowCount++
		}
		sqliteRows.Close()

		if rowCount == 0 {
			break
		}

		// INSERT IGNORE handles re-runs without duplicate-key errors
		insertSQL := fmt.Sprintf(
			"INSERT IGNORE INTO `%s` (%s) VALUES %s",
			tableName, colsStr, strings.Join(batchRowPHs, ", "),
		)
		if insertErr := dstDB.Exec(insertSQL, batchVals...).Error; insertErr != nil {
			t.cpDB.Model(&cp).Updates(map[string]interface{}{
				"status": "failed", "error_message": insertErr.Error(), "updated_at": time.Now(),
			})
			r.Status = "failed"
			r.Error = "INSERT 失败: " + insertErr.Error()
			r.Duration = time.Since(start)
			return r
		}

		offset += int64(rowCount)
		copied += int64(rowCount)
		t.cpDB.Model(&cp).Updates(map[string]interface{}{
			"copied_rows": copied,
			"last_cursor": offset,
			"updated_at":  time.Now(),
		})

		fmt.Printf("\r  COPY %-45s  %d / %d", tableName, copied, srcCount)
	}
	fmt.Println()

	// 9. Final row-count verification
	var finalDst int64
	dstDB.Table(tableName).Count(&finalDst)
	r.DstRows = finalDst

	if finalDst >= srcCount {
		t.cpDB.Model(&cp).Updates(map[string]interface{}{"status": "done", "updated_at": time.Now()})
		r.Status = "ok"
		fmt.Printf("  OK   %-45s  src=%d  dst=%d ✓\n", tableName, srcCount, finalDst)
	} else {
		errMsg := fmt.Sprintf("行数不匹配: src=%d dst=%d", srcCount, finalDst)
		t.cpDB.Model(&cp).Updates(map[string]interface{}{
			"status": "failed", "error_message": errMsg, "updated_at": time.Now(),
		})
		r.Status = "failed"
		r.Error = errMsg
		fmt.Printf("  FAIL %-45s  src=%d  dst=%d ✗\n", tableName, srcCount, finalDst)
	}

	r.Duration = time.Since(start)
	return r
}

// generateReport builds a Markdown migration report.
func (t *MigrateTool) generateReport() string {
	var sb strings.Builder
	endTime := time.Now()
	duration := endTime.Sub(t.startAt).Round(time.Second)

	sb.WriteString("# SamWaf 数据迁移报告\n\n")
	sb.WriteString(fmt.Sprintf("- **开始时间**: %s\n", t.startAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("- **结束时间**: %s\n", endTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("- **总耗时**: %s\n", duration))
	sb.WriteString(fmt.Sprintf("- **目标 MySQL**: %s:%d\n", global.GWAF_MYSQL_HOST, global.GWAF_MYSQL_PORT))
	if t.opts.DryRun {
		sb.WriteString("- **模式**: DRY-RUN（未写入数据）\n")
	} else {
		sb.WriteString(fmt.Sprintf("- **批大小**: %d 行/批\n", t.opts.BatchSize))
	}
	sb.WriteString("\n")

	totalOk, totalFail, totalSkip := 0, 0, 0

	for _, dr := range t.results {
		sb.WriteString(fmt.Sprintf("## %s → %s\n\n", dr.SrcLabel, dr.DstLabel))
		if len(dr.Tables) == 0 {
			sb.WriteString("_（无数据或源文件不存在）_\n\n")
			continue
		}
		sb.WriteString("| 表名 | 源行数 | 目标行数 | 耗时 | 状态 | 备注 |\n")
		sb.WriteString("|------|-------:|--------:|------|:----:|------|\n")
		for _, tr := range dr.Tables {
			statusCell := tr.Status
			switch tr.Status {
			case "ok":
				statusCell = "✅ ok"
				totalOk++
			case "failed":
				statusCell = "❌ failed"
				totalFail++
			case "skipped":
				statusCell = "⏭ skipped"
				totalSkip++
			case "dry-run":
				statusCell = "🔍 dry-run"
			}
			sb.WriteString(fmt.Sprintf("| `%s` | %d | %d | %s | %s | %s |\n",
				tr.Name, tr.SrcRows, tr.DstRows,
				tr.Duration.Round(time.Millisecond),
				statusCell, tr.Error))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## 汇总\n\n")
	sb.WriteString("| 指标 | 数量 |\n|:-----|-----:|\n")
	sb.WriteString(fmt.Sprintf("| ✅ 成功 | %d |\n", totalOk))
	sb.WriteString(fmt.Sprintf("| ❌ 失败 | %d |\n", totalFail))
	sb.WriteString(fmt.Sprintf("| ⏭ 跳过 | %d |\n", totalSkip))
	sb.WriteString(fmt.Sprintf("| **总计** | **%d** |\n", totalOk+totalFail+totalSkip))

	return sb.String()
}

func (t *MigrateTool) saveReport(report string) (string, error) {
	dir := filepath.Join(t.opts.CurrentDir, "data")
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return "", err
	}
	filename := fmt.Sprintf("migration_report_%s.md", t.startAt.Format("20060102_150405"))
	path := filepath.Join(dir, filename)
	return path, os.WriteFile(path, []byte(report), 0644)
}

// ===========================================================================
// SQLite-specific helpers (always use SQLite syntax, dialect-agnostic)
// ===========================================================================

// listSQLiteUserTables returns user-defined table names in a SQLite database.
// Excludes sqlite_% system tables.
func listSQLiteUserTables(db *gorm.DB) ([]string, error) {
	rows, err := db.Raw(
		"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
	).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if scanErr := rows.Scan(&name); scanErr == nil {
			tables = append(tables, name)
		}
	}
	return tables, nil
}

// getSQLiteColumnNames returns column names (in declaration order) for the given table.
func getSQLiteColumnNames(db *gorm.DB, tableName string) ([]string, error) {
	rows, err := db.Raw(fmt.Sprintf("PRAGMA table_info(`%s`)", tableName)).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cols []string
	for rows.Next() {
		var (
			cid     int
			name    string
			colType string
			notNull int
			dflt    sql.NullString
			pk      int
		)
		if scanErr := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); scanErr == nil {
			cols = append(cols, name)
		}
	}
	return cols, nil
}
