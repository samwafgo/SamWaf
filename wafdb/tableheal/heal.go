// Package tableheal 保证关键表的必需唯一索引始终存在。
//
// 一次性迁移建的索引，后续任何一次 AutoMigrate 都可能让它消失（SQLite 改列会整表重建）。
// 这里把“唯一索引在不在”当作每次启动、全部迁移之后检查的不变量：
//   - Ensure 在启动期同步执行，只做毫秒级动作：小表直接建索引，大表换表；
//   - RunBackfill 在后台把旧表数据分批并回新表，进度就是 <table>__heal 表是否还在，重启自动续跑。
//
// 本包不依赖 wafdb，避免与迁移代码成环。
package tableheal

import (
	"SamWaf/common/diagstat"
	"SamWaf/common/zlog"
	"SamWaf/wafdb/dialect"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
)

// HealSuffix 换表后旧数据所在的表名后缀
const HealSuffix = "__heal"

const (
	newSuffix       = "__new"
	backfillLogEvry = 50000
)

var (
	// SmallTableRows 行数不超过它的表，缺索引时在启动期直接建（加密 SQLite 上 10 万行含重复检查约 0.6s）；
	// 超过则换表，耗时与行数无关。
	SmallTableRows int64 = 100000
	// BackfillBatch 回填每批读取的行数
	BackfillBatch = 1000
	// BackfillPause 回填批间让出写锁的间隔
	BackfillPause = 10 * time.Millisecond
)

// IndexDef 一个索引的结构化定义，按方言拼 SQL。
type IndexDef struct {
	Name    string
	Columns []string
	Unique  bool
}

// Spec 一张需要保证唯一索引的表。
type Spec struct {
	Table       string
	Model       interface{} // SQLite/PG 换表时建新表用；MySQL 用 CREATE TABLE LIKE
	UniqueIndex IndexDef    // 缺它才触发修复
	Indexes     []IndexDef  // 该库下这张表应有的其余索引，修复时一并补建
	// MergeBatch 从 heal 表读至多 limit 行，折叠后并入主表，并在同一事务里把这批从 heal 表删掉
	// （含被丢弃的行，保证能读空）。返回读到的行数；n==0 表示读空。
	MergeBatch func(db *gorm.DB, heal string, limit int) (n int, err error)
}

// HealTable 返回 table 对应的回填表名。
func HealTable(table string) string { return table + HealSuffix }

var (
	statMissing   atomic.Int64 // 启动时发现缺唯一索引的次数
	statDirect    atomic.Int64 // 直接建索引成功次数
	statSwapped   atomic.Int64 // 换表成功次数
	statFailed    atomic.Int64 // 修复失败次数
	statRemaining atomic.Int64 // 回填剩余行数（估计值）
	statRunning   atomic.Int64 // 回填是否在跑
	statLastErrAt atomic.Int64 // 最近一次失败的 unix 秒
	backfillMu    sync.Mutex
	diagOnce      sync.Once
)

func registerDiag() {
	diagOnce.Do(func() {
		diagstat.Register("table_heal", func() map[string]int64 {
			return map[string]int64{
				"missing_found":      statMissing.Load(),
				"direct_built":       statDirect.Load(),
				"swapped":            statSwapped.Load(),
				"failed":             statFailed.Load(),
				"backfill_running":   statRunning.Load(),
				"backfill_remaining": statRemaining.Load(),
				"last_error_unix":    statLastErrAt.Load(),
			}
		})
	})
}

func fail(label, table, step string, err error) {
	statFailed.Add(1)
	statLastErrAt.Store(time.Now().Unix())
	zlog.Error("表索引修复失败", "库", label, "表", table, "步骤", step, "error", err.Error())
}

// Ensure 逐个检查规格；任何失败只记日志，不阻断启动。
func Ensure(db *gorm.DB, label string, specs []Spec) {
	registerDiag()
	for _, sp := range specs {
		ensureOne(db, label, sp)
	}
}

func ensureOne(db *gorm.DB, label string, sp Spec) {
	defer func() {
		if r := recover(); r != nil {
			fail(label, sp.Table, "panic", fmt.Errorf("%v", r))
		}
	}()
	d := dialect.Get()
	if !d.TableExists(db, sp.Table) {
		return
	}
	if db.Migrator().HasIndex(sp.Table, sp.UniqueIndex.Name) {
		return
	}
	statMissing.Add(1)

	// 上次换表还没回填完：主表已是新表，只补索引
	if d.TableExists(db, HealTable(sp.Table)) {
		if err := db.Transaction(func(tx *gorm.DB) error { return buildIndexes(tx, sp.Table, sp) }); err != nil {
			fail(label, sp.Table, "build_indexes", err)
			return
		}
		statDirect.Add(1)
		zlog.Info("表索引已补建", "库", label, "表", sp.Table, "唯一索引", sp.UniqueIndex.Name)
		return
	}

	var rows int64
	if err := db.Table(sp.Table).Count(&rows).Error; err != nil {
		fail(label, sp.Table, "count", err)
		return
	}

	if rows <= SmallTableRows {
		dup, err := hasDuplicates(db, sp)
		if err != nil {
			fail(label, sp.Table, "dup_check", err)
			return
		}
		if !dup {
			if err := db.Transaction(func(tx *gorm.DB) error { return buildIndexes(tx, sp.Table, sp) }); err != nil {
				fail(label, sp.Table, "build_indexes", err)
				return
			}
			statDirect.Add(1)
			zlog.Info("表索引已补建", "库", label, "表", sp.Table, "唯一索引", sp.UniqueIndex.Name, "行数", rows)
			return
		}
		// 有同键重复行：走换表，由回填按键折叠，cnt 求和、时间取早/晚
	}

	if sp.MergeBatch == nil {
		fail(label, sp.Table, "swap", fmt.Errorf("需要换表但未提供回填函数"))
		return
	}
	start := time.Now()
	if err := swapTable(db, sp); err != nil {
		fail(label, sp.Table, "swap", err)
		return
	}
	statSwapped.Add(1)
	zlog.Info("表已换新，旧数据将在后台并回", "库", label, "表", sp.Table, "行数", rows, "耗时", time.Since(start).String())
}

func hasDuplicates(db *gorm.DB, sp Spec) (bool, error) {
	q := fmt.Sprintf("SELECT 1 FROM %s GROUP BY %s HAVING COUNT(*) > 1 LIMIT 1",
		dialect.Q(sp.Table), quoteAll(sp.UniqueIndex.Columns))
	var one int
	res := db.Raw(q).Scan(&one)
	return res.RowsAffected > 0, res.Error
}

func quoteAll(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = dialect.Q(c)
	}
	return strings.Join(q, ", ")
}

func createIndex(tx *gorm.DB, table string, ix IndexDef) error {
	if tx.Migrator().HasIndex(table, ix.Name) {
		return nil
	}
	kind := "INDEX"
	if ix.Unique {
		kind = "UNIQUE INDEX"
	}
	return tx.Exec(fmt.Sprintf("CREATE %s %s ON %s (%s)", kind, dialect.Q(ix.Name), dialect.Q(table), quoteAll(ix.Columns))).Error
}

// buildIndexes 在 table 上建唯一索引及其余索引（唯一索引先建）。
func buildIndexes(tx *gorm.DB, table string, sp Spec) error {
	u := sp.UniqueIndex
	u.Unique = true
	if err := createIndex(tx, table, u); err != nil {
		return err
	}
	for _, ix := range sp.Indexes {
		if err := createIndex(tx, table, ix); err != nil {
			return err
		}
	}
	return nil
}

// swapTable 把旧表改名为 <table>__heal，建出带全部索引的空新表。
func swapTable(db *gorm.DB, sp Spec) error {
	d := dialect.Get()
	heal := HealTable(sp.Table)
	if d.Name() == "mysql" {
		return swapTableMySQL(db, sp, heal)
	}
	return db.Transaction(func(tx *gorm.DB) error {
		// 改名后旧表的索引名不变，不先删则新表建不了同名索引
		for _, ix := range append([]IndexDef{sp.UniqueIndex}, sp.Indexes...) {
			if err := tx.Exec(fmt.Sprintf("DROP INDEX IF EXISTS %s", dialect.Q(ix.Name))).Error; err != nil {
				return err
			}
		}
		if err := d.RenameTable(tx, sp.Table, heal); err != nil {
			return err
		}
		if d.Name() == "postgres" {
			// 主键索引不随表改名，新表建主键会撞名
			if err := tx.Exec(fmt.Sprintf("ALTER INDEX IF EXISTS %s RENAME TO %s",
				dialect.Q(sp.Table+"_pkey"), dialect.Q(heal+"_pkey"))).Error; err != nil {
				return err
			}
		}
		if err := tx.AutoMigrate(sp.Model); err != nil {
			return err
		}
		return buildIndexes(tx, sp.Table, sp)
	})
}

// swapTableMySQL：DDL 不进事务，先在 __new 上建好全部索引，再用一条 RENAME 原子互换。
func swapTableMySQL(db *gorm.DB, sp Spec, heal string) error {
	nt := sp.Table + newSuffix
	if err := db.Exec("DROP TABLE IF EXISTS " + dialect.Q(nt)).Error; err != nil {
		return err
	}
	if err := db.Exec(fmt.Sprintf("CREATE TABLE %s LIKE %s", dialect.Q(nt), dialect.Q(sp.Table))).Error; err != nil {
		return err
	}
	cleanup := func(err error) error {
		_ = db.Exec("DROP TABLE IF EXISTS " + dialect.Q(nt)).Error
		return err
	}
	if err := buildIndexes(db, nt, sp); err != nil {
		return cleanup(err)
	}
	if err := db.Exec(fmt.Sprintf("RENAME TABLE %s TO %s, %s TO %s",
		dialect.Q(sp.Table), dialect.Q(heal), dialect.Q(nt), dialect.Q(sp.Table))).Error; err != nil {
		return cleanup(err)
	}
	return nil
}

// RunBackfill 把 <table>__heal 的数据分批并回主表，读空后删除 heal 表。
// heal 表不存在则立即返回；失败会在下次启动时从断点继续。
func RunBackfill(db *gorm.DB, label string, sp Spec) {
	defer func() {
		if r := recover(); r != nil {
			fail(label, sp.Table, "backfill_panic", fmt.Errorf("%v", r))
		}
	}()
	if sp.MergeBatch == nil || db == nil {
		return
	}
	heal := HealTable(sp.Table)
	if !dialect.Get().TableExists(db, heal) {
		return
	}
	if !backfillMu.TryLock() {
		return
	}
	defer backfillMu.Unlock()
	statRunning.Store(1)
	defer func() { statRunning.Store(0); statRemaining.Store(0) }()

	var total int64
	if err := db.Table(heal).Count(&total).Error; err != nil {
		fail(label, sp.Table, "backfill_count", err)
		return
	}
	statRemaining.Store(total)
	zlog.Info("开始并回旧表数据", "库", label, "表", sp.Table, "待并回", total)

	start := time.Now()
	var done, lastLogged int64
	prevLeft := total + 1
	retries := 0
	for {
		// 每批都从头读：批内行已在同一事务里删除，所以不需要游标；
		// 被跳过的行（如「正常」标签）也会被一并删除，保证读得空。
		n, err := sp.MergeBatch(db, heal, BackfillBatch)
		if err != nil {
			retries++
			if retries > 5 {
				fail(label, sp.Table, "backfill_batch", err)
				return
			}
			time.Sleep(2 * time.Second)
			continue
		}
		retries = 0
		if n == 0 {
			break
		}
		// 每批都应让 heal 表变小；剩余行数不降说明本批没被删掉，继续只会原地打转
		var now int64
		if err := db.Table(heal).Count(&now).Error; err == nil {
			if now >= prevLeft && prevLeft >= 0 {
				fail(label, sp.Table, "backfill_no_progress", fmt.Errorf("一批处理后剩余行数未减少(%d)", now))
				return
			}
			prevLeft = now
		}
		done += int64(n)
		statRemaining.Store(max(total-done, 0))
		if done-lastLogged >= backfillLogEvry {
			lastLogged = done
			zlog.Info("并回旧表数据进行中", "库", label, "表", sp.Table, "已处理", done, "共", total, "耗时", time.Since(start).String())
		}
		time.Sleep(BackfillPause)
	}

	var left int64
	if err := db.Table(heal).Count(&left).Error; err != nil || left != 0 {
		if err == nil {
			err = fmt.Errorf("读空后仍剩 %d 行", left)
		}
		fail(label, sp.Table, "backfill_verify", err)
		return
	}
	if err := db.Migrator().DropTable(heal); err != nil {
		fail(label, sp.Table, "drop_heal", err)
		return
	}
	zlog.Info("旧表数据并回完成", "库", label, "表", sp.Table, "处理行数", done, "耗时", time.Since(start).String())
}
