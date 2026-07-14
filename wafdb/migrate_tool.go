package wafdb

import (
	"SamWaf/global"
	"SamWaf/utils"
	"SamWaf/wafdb/dialect"
	"bufio"
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
// Supported migration matrix
// ===========================================================================
//
//	sqlite -> mysql      (original behaviour, must not regress)
//	sqlite -> postgres
//	mysql  -> postgres
//
// PostgreSQL is never a source and SQLite is never a target, so "the MySQL side"
// is unambiguous: global.GWAF_MYSQL_* always describes whichever end is MySQL, and
// global.GWAF_PG_* the PostgreSQL end. No second set of source globals is needed.

type migrateRoute struct {
	From  string // "sqlite" | "mysql"
	To    string // "mysql"  | "postgres"
	Label string
}

var migrateRoutes = []migrateRoute{
	{From: "sqlite", To: "mysql", Label: "SQLite → MySQL"},
	{From: "sqlite", To: "postgres", Label: "SQLite → PostgreSQL"},
	{From: "mysql", To: "postgres", Label: "MySQL → PostgreSQL"},
}

// routeLabel returns the display label for a from/to pair, or "" if unsupported.
func routeLabel(from, to string) string {
	for _, r := range migrateRoutes {
		if r.From == from && r.To == to {
			return r.Label
		}
	}
	return ""
}

// pgMaxBindParams is PostgreSQL's hard wire-protocol limit on bind parameters in a
// single statement. The batch INSERT uses BatchSize x len(cols) placeholders, so a
// wide table at the default batch size of 1000 blows straight through it. MySQL never
// hits this because its limit is max_allowed_packet (a byte size, not a count).
const pgMaxBindParams = 65535

// ===========================================================================
// Checkpoint model
// ===========================================================================

// MigrationCheckpoint tracks per-table migration progress.
// Stored in the target core database (_migration_checkpoint table).
type MigrationCheckpoint struct {
	// SrcDB is "<srcKind>:<label>", e.g. "sqlite:core". The source kind is part of the
	// key so that a sqlite->postgres run does not pick up stale checkpoints left by an
	// earlier sqlite->mysql run against the same target.
	SrcDB        string    `gorm:"column:src_db;primaryKey;size:64"`
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
	From       string // "sqlite" | "mysql"; empty => ask interactively
	To         string // "mysql"  | "postgres"; empty => ask interactively
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

// MigrateTool runs offline data migration with checkpoint/resume.
type MigrateTool struct {
	opts    MigrateOptions
	srcKind string // "sqlite" | "mysql"
	dstKind string // "mysql"  | "postgres"

	// Dialects are held as instances rather than read from the global registry,
	// because a migration needs BOTH ends at once. Every DBDialect method takes the
	// *gorm.DB it should act on, so an instance is fully usable on its own.
	// dialect.Register() still receives the TARGET dialect: the schema-migration
	// functions (RunCoreDBMigrations -> safeCreateIndex) consult dialect.Get().
	srcDia dialect.DBDialect
	dstDia dialect.DBDialect

	cpDB    *gorm.DB // checkpoint DB (target core)
	results []dbMigrateResult
	startAt time.Time

	// stdin is a single shared reader for every prompt. It must not be re-created
	// per prompt group: bufio reads ahead, so a second bufio.NewReader(os.Stdin)
	// would find the buffer already drained and see EOF. That works by accident on
	// an interactive TTY but silently cancels the run when stdin is piped.
	stdin *bufio.Reader
}

// RunMigrateDB is the entry point called from the CLI (samwaf migratedb).
func RunMigrateDB(opts MigrateOptions) error {
	if opts.BatchSize <= 0 {
		opts.BatchSize = 1000
	}
	if opts.CurrentDir == "" {
		opts.CurrentDir = utils.GetCurrentDir()
	}
	t := &MigrateTool{opts: opts, startAt: time.Now(), stdin: bufio.NewReader(os.Stdin)}
	return t.run()
}

type migPair struct {
	srcLabel  string // core | log | stats
	srcPath   string // sqlite source: .db file path
	srcKey    string // sqlite source: encryption key
	srcDBName string // mysql source: database name
	dstDBName string
	dstLabel  string
	schemaMig func(*gorm.DB) error
}

func (t *MigrateTool) run() error {
	fmt.Println("================================================")
	fmt.Println("            SamWaf 数据迁移工具")
	fmt.Println("================================================")

	// 1. 确定迁移方向（命令行 flag 优先，否则交互式菜单）
	if err := t.resolveRoute(); err != nil {
		return err
	}
	label := routeLabel(t.srcKind, t.dstKind)
	fmt.Printf("\n迁移方向: %s\n", label)

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

	// 2. 采集连接参数
	if t.srcKind == "mysql" {
		fmt.Println("── 源库（MySQL）连接信息 ──")
		if err := t.promptMySQLConfig(); err != nil {
			return err
		}
	}
	switch t.dstKind {
	case "mysql":
		fmt.Println("── 目标库（MySQL）连接信息 ──")
		if err := t.promptMySQLConfig(); err != nil {
			return err
		}
	case "postgres":
		fmt.Println("── 目标库（PostgreSQL）连接信息 ──")
		if err := t.promptPostgresConfig(); err != nil {
			return err
		}
	}

	// 3. 注册方言。全局注册的是目标方言（schema 迁移函数内部走 dialect.Get()）。
	t.srcDia = dialectFor(t.srcKind)
	t.dstDia = dialectFor(t.dstKind)
	dialect.Register(t.dstDia)

	// 4. 测试目标连接
	fmt.Printf("\n测试 %s 连接...\n", t.dstKind)
	testDB, testErr := t.openTarget(t.dstCoreDBName())
	if testErr != nil {
		return fmt.Errorf("%s 连接失败: %w\n请检查连接参数后重试", t.dstKind, testErr)
	}
	if sqlDB, e := testDB.DB(); e == nil {
		sqlDB.Close()
	}
	fmt.Println("连接成功 ✓")

	fmt.Printf("\n批大小   : %d 行/批\n", t.opts.BatchSize)
	if t.srcKind == "sqlite" {
		fmt.Printf("数据目录 : %s/data\n", t.opts.CurrentDir)
	}

	allPairs := t.buildPairs()

	// 5. 选择迁移范围
	fmt.Println("\n请选择迁移范围：")
	fmt.Println("  1. 仅迁移核心库 (core)")
	fmt.Println("  2. 迁移全部（核心库 + 日志库 + 统计库）[默认]")
	scopeLine, scopeErr := readLine(t.stdin, "请输入选项", "2")
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

	// 6. 迁移前行数预览
	fmt.Printf("\n数据预览（%s 源库行数）：\n", t.srcKind)
	fmt.Printf("  %-8s  %-30s  %8s  %12s\n", "库", "来源", "表数量", "总行数")
	fmt.Println("  " + strings.Repeat("-", 62))
	var totalTables, totalRows int64
	for _, p := range pairs {
		desc := t.pairSourceDesc(p)
		if miss, reason := t.sourceMissing(p); miss {
			fmt.Printf("  %-8s  %-30s  %8s  %12s\n", p.srcLabel, desc, "-", reason)
			continue
		}
		tblCnt, rowCnt, surveyErr := t.surveySource(p)
		if surveyErr != nil {
			fmt.Printf("  %-8s  %-30s  %8s  %12s\n", p.srcLabel, desc, "?", "读取失败")
			continue
		}
		fmt.Printf("  %-8s  %-30s  %8d  %12d\n", p.srcLabel, desc, tblCnt, rowCnt)
		totalTables += tblCnt
		totalRows += rowCnt
	}
	fmt.Println("  " + strings.Repeat("-", 62))
	fmt.Printf("  %-39s  %8d  %12d\n", "合计", totalTables, totalRows)

	// 7. 确认后才开始写入（dry-run 跳过）
	if !t.opts.DryRun {
		fmt.Println()
		answer, confirmErr := readLine(t.stdin,
			fmt.Sprintf("确认执行 %s 迁移？[y/N]", label), "")
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

	// 8. 建 checkpoint 表（目标核心库）
	coreDB, err := t.openTarget(t.dstCoreDBName())
	if err != nil {
		return fmt.Errorf("连接目标核心库失败: %w", err)
	}
	t.cpDB = coreDB

	if !t.opts.DryRun {
		if err := coreDB.AutoMigrate(&MigrationCheckpoint{}); err != nil {
			return fmt.Errorf("创建 checkpoint 表失败: %w", err)
		}
	}

	for _, p := range pairs {
		fmt.Printf("\n--- [%s] %s → %s ---\n", time.Now().Format("15:04:05"), p.srcLabel, p.dstLabel)

		if miss, reason := t.sourceMissing(p); miss {
			fmt.Printf("  源不可用（%s），跳过: %s\n", reason, t.pairSourceDesc(p))
			t.results = append(t.results, dbMigrateResult{SrcLabel: p.srcLabel, DstLabel: p.dstLabel})
			continue
		}

		srcDB, openErr := t.openSource(p)
		if openErr != nil {
			return fmt.Errorf("打开源数据库 %s 失败: %w", t.pairSourceDesc(p), openErr)
		}

		dstDB, dstErr := t.openTarget(p.dstDBName)
		if dstErr != nil {
			return fmt.Errorf("打开目标数据库 %s 失败: %w", p.dstDBName, dstErr)
		}

		if !t.opts.DryRun {
			fmt.Printf("  [schema] 在 %s 上创建/同步表结构...\n", t.dstKind)
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

	if saveErr != nil {
		fmt.Printf("\n⚠  迁移报告保存失败: %v\n", saveErr)
	} else {
		fmt.Println()
		fmt.Println("📄 迁移报告已保存：")
		fmt.Printf("      %s\n", reportPath)
	}

	// 迁移完成后，若无失败且非 dry-run，询问是否写入 config.yml
	if !t.opts.DryRun && t.countFailed() == 0 {
		answer, cfgErr := readLine(t.stdin,
			fmt.Sprintf("迁移成功，是否将 config.yml 切换为 %s 驱动？[Y/n]", t.dstKind), "y")
		if cfgErr != nil {
			fmt.Println("已跳过 config.yml 更新。")
			return nil
		}
		if answer == "" || strings.ToLower(answer) == "y" || strings.ToLower(answer) == "yes" {
			if cfgErr := t.saveTargetToConfig(); cfgErr != nil {
				fmt.Printf("警告：config.yml 写入失败: %v\n", cfgErr)
			} else {
				fmt.Printf("config.yml 已更新，下次启动将使用 %s 数据库。\n", t.dstKind)
			}
		} else {
			fmt.Printf("config.yml 未修改，如需切换请手动更新 database.driver: %s。\n", t.dstKind)
		}
	} else if t.countFailed() > 0 {
		fmt.Printf("\n有 %d 张表迁移失败，config.yml 未修改。修复后可重新运行（支持断点续传）。\n",
			t.countFailed())
	}

	return nil
}

// dialectFor returns a dialect instance for a driver name.
func dialectFor(kind string) dialect.DBDialect {
	switch kind {
	case "mysql":
		return &dialect.MySQLDialect{}
	case "postgres":
		return &dialect.PostgresDialect{}
	default:
		return &dialect.SQLiteDialect{}
	}
}

// resolveRoute settles srcKind/dstKind from the --from/--to flags, falling back to an
// interactive menu. Option 1 is the historical SQLite -> MySQL route, so a user who
// just presses Enter through the old flow gets exactly the old behaviour.
func (t *MigrateTool) resolveRoute() error {
	from, to := strings.ToLower(t.opts.From), strings.ToLower(t.opts.To)

	if from != "" && to != "" {
		if routeLabel(from, to) == "" {
			return fmt.Errorf("不支持的迁移方向: %s → %s\n支持的方向: %s", from, to, supportedRoutesText())
		}
		t.srcKind, t.dstKind = from, to
		return nil
	}

	fmt.Println("\n请选择迁移方向：")
	for i, route := range migrateRoutes {
		suffix := ""
		if i == 0 {
			suffix = " [默认]"
		}
		fmt.Printf("  %d. %s%s\n", i+1, route.Label, suffix)
	}
	line, err := readLine(t.stdin, "请输入选项", "1")
	if err != nil {
		return errCancelled
	}
	idx, convErr := strconv.Atoi(line)
	if convErr != nil || idx < 1 || idx > len(migrateRoutes) {
		return fmt.Errorf("无效的选项: %s", line)
	}
	t.srcKind = migrateRoutes[idx-1].From
	t.dstKind = migrateRoutes[idx-1].To
	return nil
}

func supportedRoutesText() string {
	parts := make([]string, 0, len(migrateRoutes))
	for _, r := range migrateRoutes {
		parts = append(parts, fmt.Sprintf("--from=%s --to=%s", r.From, r.To))
	}
	return strings.Join(parts, " | ")
}

// buildPairs assembles the core/log/stats migration pairs for the chosen route.
func (t *MigrateTool) buildPairs() []migPair {
	dataDir := filepath.Join(t.opts.CurrentDir, "data")

	core := migPair{
		srcLabel:  "core",
		srcPath:   filepath.Join(dataDir, "local.db"),
		srcKey:    global.GWAF_PWD_COREDB,
		srcDBName: global.GWAF_MYSQL_CORE_DB,
		dstDBName: t.dstCoreDBName(),
		dstLabel:  t.dstKind + "_core",
		schemaMig: func(db *gorm.DB) error {
			if err := RunCoreDBMigrations(db); err != nil {
				return err
			}
			return RunTaskInitMigrations(db)
		},
	}
	logPair := migPair{
		srcLabel:  "log",
		srcPath:   filepath.Join(dataDir, "local_log.db"),
		srcKey:    global.GWAF_PWD_LOGDB,
		srcDBName: global.GWAF_MYSQL_LOG_DB,
		dstDBName: t.dstLogDBName(),
		dstLabel:  t.dstKind + "_log",
		schemaMig: RunLogDBMigrations,
	}
	statsPair := migPair{
		srcLabel:  "stats",
		srcPath:   filepath.Join(dataDir, "local_stats.db"),
		srcKey:    global.GWAF_PWD_STATDB,
		srcDBName: global.GWAF_MYSQL_STATS_DB,
		dstDBName: t.dstStatsDBName(),
		dstLabel:  t.dstKind + "_stats",
		schemaMig: RunStatsDBMigrations,
	}
	return []migPair{core, logPair, statsPair}
}

func (t *MigrateTool) dstCoreDBName() string {
	if t.dstKind == "postgres" {
		return global.GWAF_PG_CORE_DB
	}
	return global.GWAF_MYSQL_CORE_DB
}

func (t *MigrateTool) dstLogDBName() string {
	if t.dstKind == "postgres" {
		return global.GWAF_PG_LOG_DB
	}
	return global.GWAF_MYSQL_LOG_DB
}

func (t *MigrateTool) dstStatsDBName() string {
	if t.dstKind == "postgres" {
		return global.GWAF_PG_STATS_DB
	}
	return global.GWAF_MYSQL_STATS_DB
}

// pairSourceDesc describes the source for display.
func (t *MigrateTool) pairSourceDesc(p migPair) string {
	if t.srcKind == "sqlite" {
		return filepath.Base(p.srcPath)
	}
	return p.srcDBName
}

// sourceMissing reports whether the source for this pair is unavailable, so the pair
// can be skipped rather than aborting the whole run. A partial source is normal: an
// install that never enabled stats has no stats database at all.
func (t *MigrateTool) sourceMissing(p migPair) (bool, string) {
	if t.srcKind == "sqlite" {
		if _, err := os.Stat(p.srcPath); os.IsNotExist(err) {
			return true, "文件不存在"
		}
		return false, ""
	}

	// MySQL source: the database may simply not exist. openMySQLDBRaw never creates it,
	// and GORM's MySQL dialector queries the server version on open, so a missing
	// database surfaces as an error here rather than later mid-copy.
	db, err := openMySQLDBRaw(p.srcDBName)
	if err != nil {
		return true, "库不存在"
	}
	sqlDB, dbErr := db.DB()
	if dbErr != nil {
		return true, "库不存在"
	}
	defer sqlDB.Close()
	if pingErr := sqlDB.Ping(); pingErr != nil {
		return true, "库不存在"
	}
	return false, ""
}

// openSource opens the source database for a pair.
func (t *MigrateTool) openSource(p migPair) (*gorm.DB, error) {
	if t.srcKind == "sqlite" {
		return t.openSQLiteSource(p.srcPath, p.srcKey)
	}
	// MySQL source: never attempt CREATE DATABASE on a database we are only reading.
	return openMySQLDBRaw(p.srcDBName)
}

// openTarget opens the target database, creating it if necessary.
func (t *MigrateTool) openTarget(dbName string) (*gorm.DB, error) {
	if t.dstKind == "postgres" {
		return openPostgresDB(dbName)
	}
	return openMySQLDB(dbName)
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

// surveySource returns (tableCount, totalRowCount, error) for one pair's source.
func (t *MigrateTool) surveySource(p migPair) (int64, int64, error) {
	db, err := t.openSource(p)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if sqlDB, e := db.DB(); e == nil {
			sqlDB.Close()
		}
	}()

	tables, err := t.srcDia.ListTables(db)
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
	r := t.stdin

	must := func(field *string, prompt, def string) error {
		v, err := readLine(r, prompt, def)
		if err != nil {
			return err
		}
		*field = v
		return nil
	}

	fmt.Println("请输入 MySQL 连接信息（直接回车使用默认值，Ctrl+Z/Ctrl+D 退出）：")

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

// promptPostgresConfig interactively reads PostgreSQL connection parameters from stdin.
func (t *MigrateTool) promptPostgresConfig() error {
	r := t.stdin

	must := func(field *string, prompt, def string) error {
		v, err := readLine(r, prompt, def)
		if err != nil {
			return err
		}
		*field = v
		return nil
	}

	fmt.Println("请输入 PostgreSQL 连接信息（直接回车使用默认值，Ctrl+Z/Ctrl+D 退出）：")

	if err := must(&global.GWAF_PG_HOST, "主机", global.GWAF_PG_HOST); err != nil {
		return err
	}
	portStr, err := readLine(r, "端口", strconv.Itoa(global.GWAF_PG_PORT))
	if err != nil {
		return err
	}
	if p, e := strconv.Atoi(portStr); e == nil && p > 0 {
		global.GWAF_PG_PORT = p
	}
	if err := must(&global.GWAF_PG_USER, "用户名", global.GWAF_PG_USER); err != nil {
		return err
	}
	if err := must(&global.GWAF_PG_PASSWORD, "密码", global.GWAF_PG_PASSWORD); err != nil {
		return err
	}
	if err := must(&global.GWAF_PG_SSLMODE, "SSL 模式", global.GWAF_PG_SSLMODE); err != nil {
		return err
	}
	// 时区决定 timestamptz 的渲染时区，配错不报错、只让界面上所有时间静默偏移
	if err := must(&global.GWAF_PG_TIMEZONE, "时区", global.GWAF_PG_TIMEZONE); err != nil {
		return err
	}
	if err := must(&global.GWAF_PG_MAINTENANCE_DB, "维护库名（用于建库）", global.GWAF_PG_MAINTENANCE_DB); err != nil {
		return err
	}
	if err := must(&global.GWAF_PG_CORE_DB, "核心库名", global.GWAF_PG_CORE_DB); err != nil {
		return err
	}
	if err := must(&global.GWAF_PG_LOG_DB, "日志库名", global.GWAF_PG_LOG_DB); err != nil {
		return err
	}
	if err := must(&global.GWAF_PG_STATS_DB, "统计库名", global.GWAF_PG_STATS_DB); err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("  PostgreSQL : %s@%s:%d (sslmode=%s, timezone=%s)\n",
		global.GWAF_PG_USER, global.GWAF_PG_HOST, global.GWAF_PG_PORT,
		global.GWAF_PG_SSLMODE, global.GWAF_PG_TIMEZONE)
	fmt.Printf("  核心库 : %s\n", global.GWAF_PG_CORE_DB)
	fmt.Printf("  日志库 : %s\n", global.GWAF_PG_LOG_DB)
	fmt.Printf("  统计库 : %s\n", global.GWAF_PG_STATS_DB)

	return nil
}

// saveTargetToConfig writes database.driver and the target's connection params to
// config.yml. Uses the yaml.v3 Node API to preserve key order (viper sorts keys).
func (t *MigrateTool) saveTargetToConfig() error {
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

	dbNode := yamlEnsureMapping(root, "database")
	yamlSetNode(dbNode, "driver", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: t.dstKind})

	// Build the target's sub-section with keys in a deterministic order.
	// Replaced wholesale so ordering is guaranteed even on re-run.
	sect := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	appendStr := func(k, v string) {
		sect.Content = append(sect.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v},
		)
	}
	appendInt := func(k string, v int) {
		sect.Content = append(sect.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(v)},
		)
	}

	switch t.dstKind {
	case "postgres":
		appendStr("host", global.GWAF_PG_HOST)
		appendInt("port", global.GWAF_PG_PORT)
		appendStr("user", global.GWAF_PG_USER)
		appendStr("password", global.GWAF_PG_PASSWORD)
		appendStr("sslmode", global.GWAF_PG_SSLMODE)
		appendStr("timezone", global.GWAF_PG_TIMEZONE)
		appendStr("maintenance_db", global.GWAF_PG_MAINTENANCE_DB)
		appendStr("core_db", global.GWAF_PG_CORE_DB)
		appendStr("log_db", global.GWAF_PG_LOG_DB)
		appendStr("stats_db", global.GWAF_PG_STATS_DB)
		yamlSetNode(dbNode, "postgres", sect)
	default: // mysql
		appendStr("host", global.GWAF_MYSQL_HOST)
		appendInt("port", global.GWAF_MYSQL_PORT)
		appendStr("user", global.GWAF_MYSQL_USER)
		appendStr("password", global.GWAF_MYSQL_PASSWORD)
		appendStr("core_db", global.GWAF_MYSQL_CORE_DB)
		appendStr("log_db", global.GWAF_MYSQL_LOG_DB)
		appendStr("stats_db", global.GWAF_MYSQL_STATS_DB)
		yamlSetNode(dbNode, "mysql", sect)
	}

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

// migrateOneDB migrates all user tables from one source DB to one target DB.
func (t *MigrateTool) migrateOneDB(srcDB *gorm.DB, srcLabel string, dstDB *gorm.DB, dstLabel string) dbMigrateResult {
	result := dbMigrateResult{SrcLabel: srcLabel, DstLabel: dstLabel}

	tables, err := t.srcDia.ListTables(srcDB)
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

// effectiveBatchSize clamps the batch size so a single INSERT stays within the
// target's limits. PostgreSQL caps a statement at 65535 bind parameters, and the
// batch INSERT uses batchSize x len(cols) of them — a wide table at the default
// batch size of 1000 would exceed that and fail with an opaque protocol error.
func (t *MigrateTool) effectiveBatchSize(numCols int) int {
	batch := t.opts.BatchSize
	if t.dstKind == "postgres" && numCols > 0 {
		if maxRows := pgMaxBindParams / numCols; maxRows < batch {
			batch = maxRows
		}
	}
	if batch < 1 {
		batch = 1
	}
	return batch
}

// migrateTable copies one table from source to target with checkpoint/resume.
func (t *MigrateTool) migrateTable(srcDB, dstDB *gorm.DB, srcLabel, tableName string) tableMigrateResult {
	start := time.Now()
	r := tableMigrateResult{Name: tableName}

	// The checkpoint key carries the source kind so runs along different routes
	// against the same target do not collide.
	cpKey := t.srcKind + ":" + srcLabel

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
	cpErr := t.cpDB.Where("src_db = ? AND table_name = ?", cpKey, tableName).First(&cp).Error
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
			SrcDB:     cpKey,
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

	// 6. Column names from the SOURCE dialect (sqlite_master/PRAGMA vs information_schema)
	srcCols, colErr := t.srcDia.ColumnInfo(srcDB, tableName)
	if colErr != nil || len(srcCols) == 0 {
		r.Status = "failed"
		r.Error = fmt.Sprintf("获取列信息失败: %v", colErr)
		r.Duration = time.Since(start)
		return r
	}
	cols := make([]string, len(srcCols))
	for i, c := range srcCols {
		cols[i] = c.Name
	}

	// 7. Per-column value conversion, derived from the TARGET column types.
	coercers := buildCoercers(t.dstDia, dstDB, tableName, cols)

	// Mark checkpoint as running
	t.cpDB.Model(&cp).Updates(map[string]interface{}{
		"status":     "running",
		"total_rows": srcCount,
		"updated_at": time.Now(),
	})

	// 8. Build SQL fragments with each side's own quoting rules.
	srcCols2 := make([]string, len(cols))
	dstCols := make([]string, len(cols))
	placeholders := make([]string, len(cols))
	for i, c := range cols {
		srcCols2[i] = t.srcDia.Quote(c)
		dstCols[i] = t.dstDia.Quote(c)
		placeholders[i] = "?"
	}
	srcColsStr := strings.Join(srcCols2, ", ")
	dstColsStr := strings.Join(dstCols, ", ")
	rowPlaceholder := "(" + strings.Join(placeholders, ", ") + ")"

	batchSize := t.effectiveBatchSize(len(cols))
	if batchSize < t.opts.BatchSize {
		fmt.Printf("  NOTE %-45s  批大小降为 %d（%d 列 × %d 超过 PostgreSQL 65535 参数上限）\n",
			tableName, batchSize, len(cols), t.opts.BatchSize)
	}

	offset := cp.LastCursor
	copied := cp.CopiedRows

	// 9. Batch copy loop
	for {
		srcRows, queryErr := srcDB.Raw(
			fmt.Sprintf("SELECT %s FROM %s LIMIT ? OFFSET ?", srcColsStr, t.srcDia.Quote(tableName)),
			batchSize, offset,
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

		for srcRows.Next() {
			vals := make([]interface{}, len(cols))
			valPtrs := make([]interface{}, len(cols))
			for i := range vals {
				valPtrs[i] = &vals[i]
			}
			if scanErr := srcRows.Scan(valPtrs...); scanErr != nil {
				srcRows.Close()
				r.Status = "failed"
				r.Error = "Scan 失败: " + scanErr.Error()
				r.Duration = time.Since(start)
				return r
			}
			// Convert each value to something the target column will accept.
			for i := range vals {
				vals[i] = coercers[i](vals[i])
			}
			batchRowPHs = append(batchRowPHs, rowPlaceholder)
			batchVals = append(batchVals, vals...)
			rowCount++
		}
		srcRows.Close()

		if rowCount == 0 {
			break
		}

		// Insert-and-ignore makes re-runs idempotent on duplicate keys.
		insertSQL := t.dstDia.InsertIgnoreSQL(tableName, dstColsStr, strings.Join(batchRowPHs, ", "))
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

	// 10. Final row-count verification
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
	sb.WriteString(fmt.Sprintf("- **迁移方向**: %s\n", routeLabel(t.srcKind, t.dstKind)))
	sb.WriteString(fmt.Sprintf("- **开始时间**: %s\n", t.startAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("- **结束时间**: %s\n", endTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("- **总耗时**: %s\n", duration))
	if t.dstKind == "postgres" {
		sb.WriteString(fmt.Sprintf("- **目标 PostgreSQL**: %s:%d (timezone=%s)\n",
			global.GWAF_PG_HOST, global.GWAF_PG_PORT, global.GWAF_PG_TIMEZONE))
	} else {
		sb.WriteString(fmt.Sprintf("- **目标 MySQL**: %s:%d\n",
			global.GWAF_MYSQL_HOST, global.GWAF_MYSQL_PORT))
	}
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
			sb.WriteString("_（无数据或源不存在）_\n\n")
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
