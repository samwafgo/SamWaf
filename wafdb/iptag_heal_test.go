package wafdb

import (
	"SamWaf/customtype"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafdb/tableheal"
	"fmt"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	healUser   = "heal_user"
	healTenant = "heal_tenant"
)

var healT0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.Local)

func openHealTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dialect.Register(&dialect.SQLiteDialect{})
	dsn := filepath.Join(t.TempDir(), "heal.db") + "?_db_key=" + url.QueryEscape("heal")
	db, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("打开 sqlite 失败: %v", err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			s.Close()
		}
	})
	return db
}

// 模拟现场：表存在、数据在、唯一索引与 idx_iptag_ip 都丢了。
func newBrokenIPTags(t *testing.T) *gorm.DB {
	t.Helper()
	db := openHealTestDB(t)
	if err := db.AutoMigrate(&model.IPTag{}); err != nil {
		t.Fatal(err)
	}
	return db
}

func healRow(id, ip, tag string, cnt int64, create, update time.Time) model.IPTag {
	return model.IPTag{
		BaseOrm: baseorm.BaseOrm{
			Id: id, USER_CODE: healUser, Tenant_ID: healTenant,
			CREATE_TIME: customtype.JsonTime(create), UPDATE_TIME: customtype.JsonTime(update),
		},
		IP: ip, IPTag: tag, Cnt: cnt,
	}
}

func hasIdx(db *gorm.DB, name string) bool { return db.Migrator().HasIndex("ip_tags", name) }

func cntOf(t *testing.T, db *gorm.DB, table, ip, tag string) (int64, int64) {
	t.Helper()
	var rows []model.IPTag
	if err := db.Table(table).Where("ip = ? AND ip_tag = ?", ip, tag).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	var sum int64
	for _, r := range rows {
		sum += r.Cnt
	}
	return int64(len(rows)), sum
}

func withSmallRows(t *testing.T, n int64) {
	t.Helper()
	old := tableheal.SmallTableRows
	tableheal.SmallTableRows = n
	t.Cleanup(func() { tableheal.SmallTableRows = old })
	oldPause := tableheal.BackfillPause
	tableheal.BackfillPause = 0
	t.Cleanup(func() { tableheal.BackfillPause = oldPause })
}

// 1. 索引齐全：Ensure 不改动
func TestIPTagHeal_NoopWhenIndexExists(t *testing.T) {
	db := newBrokenIPTags(t)
	ensureIPTagIndexes(db, true)
	if !hasIdx(db, "uni_iptags_full") {
		t.Fatal("空表应直接建出唯一索引")
	}
	db.Create(&[]model.IPTag{healRow("a", "1.1.1.1", "SQL注入", 3, healT0, healT0)})
	ensureIPTagIndexes(db, true)
	if n, _ := cntOf(t, db, "ip_tags", "1.1.1.1", "SQL注入"); n != 1 {
		t.Fatalf("行数被改动: %d", n)
	}
	if db.Migrator().HasTable("ip_tags__heal") {
		t.Fatal("不应换表")
	}
}

// 2. 复现现场：无索引、无重复的小表 -> 直接建
func TestIPTagHeal_SmallTableDirect(t *testing.T) {
	db := newBrokenIPTags(t)
	for i := 0; i < 50; i++ {
		db.Create(&[]model.IPTag{healRow(fmt.Sprint("id", i), fmt.Sprintf("10.0.0.%d", i), "XSS", 2, healT0, healT0)})
	}
	ensureIPTagIndexes(db, true)
	if !hasIdx(db, "uni_iptags_full") || !hasIdx(db, "idx_iptag_ip") {
		t.Fatal("两个索引都应补建")
	}
	if db.Migrator().HasTable("ip_tags__heal") {
		t.Fatal("无重复的小表不应换表")
	}
}

// 3. 含同键重复：走换表，回填后 cnt 求和、时间取早/晚，「正常」被丢弃，heal 表消失
func TestIPTagHeal_DuplicatesFoldedByBackfill(t *testing.T) {
	db := newBrokenIPTags(t)
	early, late := healT0, healT0.Add(48*time.Hour)
	db.Create(&[]model.IPTag{
		healRow("d1", "9.9.9.9", "SQL注入", 3, late, late),
		healRow("d2", "9.9.9.9", "SQL注入", 4, early, early.Add(time.Hour)),
		healRow("d3", "9.9.9.9", "SQL注入", 5, healT0.Add(time.Hour), healT0.Add(72*time.Hour)),
		healRow("o1", "8.8.8.8", "XSS", 7, healT0, healT0),
		healRow("b1", "8.8.8.8", "正常", 100, healT0, healT0),
	})
	ensureIPTagIndexes(db, true)
	if !hasIdx(db, "uni_iptags_full") {
		t.Fatal("换表后新表应有唯一索引")
	}
	if !db.Migrator().HasTable("ip_tags__heal") {
		t.Fatal("有重复应换表")
	}
	tableheal.RunBackfill(db, "测试库", ipTagHealSpec(true))
	if db.Migrator().HasTable("ip_tags__heal") {
		t.Fatal("回填完成后 heal 表应删除")
	}
	n, sum := cntOf(t, db, "ip_tags", "9.9.9.9", "SQL注入")
	if n != 1 || sum != 12 {
		t.Fatalf("重复键应折叠为一行 cnt=12，实得 %d 行 cnt=%d", n, sum)
	}
	var got model.IPTag
	db.Where("ip = ?", "9.9.9.9").First(&got)
	if !time.Time(got.CREATE_TIME).Equal(early) || !time.Time(got.UPDATE_TIME).Equal(healT0.Add(72*time.Hour)) {
		t.Fatalf("时间应取最早创建/最晚更新: create=%v update=%v", time.Time(got.CREATE_TIME), time.Time(got.UPDATE_TIME))
	}
	if n, _ := cntOf(t, db, "ip_tags", "8.8.8.8", "正常"); n != 0 {
		t.Fatal("「正常」标签不应被并回")
	}
	if n, sum := cntOf(t, db, "ip_tags", "8.8.8.8", "XSS"); n != 1 || sum != 7 {
		t.Fatalf("普通行应原样并回: %d/%d", n, sum)
	}
}

// 4. 超阈值：换表；中途中断后续跑，结果与一次跑完一致
func TestIPTagHeal_LargeTableResumable(t *testing.T) {
	withSmallRows(t, 10)
	db := newBrokenIPTags(t)
	const total = 250
	rows := make([]model.IPTag, 0, total)
	for i := 0; i < total; i++ {
		rows = append(rows, healRow(fmt.Sprint("id", i), fmt.Sprintf("10.1.%d.%d", i/256, i%256), "扫描工具", int64(1+i%5), healT0, healT0))
	}
	db.CreateInBatches(rows, 50)
	var wantSum int64
	for _, r := range rows {
		wantSum += r.Cnt
	}

	ensureIPTagIndexes(db, true)
	if !db.Migrator().HasTable("ip_tags__heal") || !hasIdx(db, "uni_iptags_full") {
		t.Fatal("超阈值应换表并带全部索引")
	}
	var cur int64
	db.Table("ip_tags").Count(&cur)
	if cur != 0 {
		t.Fatalf("换表后新表应为空，实得 %d", cur)
	}

	// 只并回一批就“中断”
	spec := ipTagHealSpec(true)
	if _, err := spec.MergeBatch(db, "ip_tags__heal", 100); err != nil {
		t.Fatal(err)
	}
	var left int64
	db.Table("ip_tags__heal").Count(&left)
	if left != total-100 {
		t.Fatalf("一批后应剩 %d，实得 %d", total-100, left)
	}

	// “重启”：Ensure 不应再次换表（索引已在、heal 存在），回填接着做
	ensureIPTagIndexes(db, true)
	tableheal.RunBackfill(db, "测试库", spec)
	if db.Migrator().HasTable("ip_tags__heal") {
		t.Fatal("续跑后 heal 表应删除")
	}
	var after, sum int64
	db.Table("ip_tags").Count(&after)
	db.Table("ip_tags").Select("SUM(cnt)").Scan(&sum)
	if after != total || sum != wantSum {
		t.Fatalf("续跑结果应与一次跑完一致: 行 %d/%d cnt %d/%d", after, total, sum, wantSum)
	}
}

// 5. 回填期间实时写入照常累加，且不与回填重复计数
func TestIPTagHeal_ConcurrentUpsertDuringBackfill(t *testing.T) {
	withSmallRows(t, 1)
	db := newBrokenIPTags(t)
	db.Create(&[]model.IPTag{
		healRow("x1", "7.7.7.7", "CC攻击", 10, healT0, healT0),
		healRow("x2", "7.7.7.7", "CC攻击", 5, healT0, healT0),
		healRow("x3", "6.6.6.6", "CC攻击", 1, healT0, healT0),
	})
	ensureIPTagIndexes(db, true)

	// 换表之后、回填之前来了新流量
	if err := UpsertIPTags(db, []model.IPTag{healRow("n1", "7.7.7.7", "CC攻击", 2, healT0.Add(time.Hour), healT0.Add(time.Hour))}); err != nil {
		t.Fatal(err)
	}
	tableheal.RunBackfill(db, "测试库", ipTagHealSpec(true))
	if n, sum := cntOf(t, db, "ip_tags", "7.7.7.7", "CC攻击"); n != 1 || sum != 17 {
		t.Fatalf("应累加为 10+5+2=17，实得 %d 行 cnt=%d", n, sum)
	}
}

// 6. 批内同键折叠（PG 同一条语句命中同一行两次会报错）
func TestIPTagHeal_UpsertFoldsBatchDuplicates(t *testing.T) {
	db := openHealTestDB(t)
	if err := db.AutoMigrate(&model.IPTag{}); err != nil {
		t.Fatal(err)
	}
	ensureIPTagIndexes(db, true)
	err := UpsertIPTags(db, []model.IPTag{
		healRow("a", "5.5.5.5", "XSS", 1, healT0, healT0),
		healRow("b", "5.5.5.5", "XSS", 2, healT0, healT0),
		healRow("c", "5.5.5.5", "XSS", 3, healT0, healT0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if n, sum := cntOf(t, db, "ip_tags", "5.5.5.5", "XSS"); n != 1 || sum != 6 {
		t.Fatalf("批内同键应折叠: %d 行 cnt=%d", n, sum)
	}
}

// 迁移之后自动自愈：真实迁移流程跑完，唯一索引一定在
func TestIPTagHeal_AfterRealMigrations(t *testing.T) {
	db := openHealTestDB(t)
	if err := RunCoreDBMigrations(db); err != nil {
		t.Fatal(err)
	}
	if !hasIdx(db, "uni_iptags_full") {
		t.Fatal("迁移后唯一索引应存在")
	}
	// 模拟后续某次 AutoMigrate 把索引弄丢，再启动一遍
	db.Exec("DROP INDEX uni_iptags_full")
	db.Exec("DROP INDEX idx_iptag_ip")
	if err := RunCoreDBMigrations(db); err != nil {
		t.Fatal(err)
	}
	if !hasIdx(db, "uni_iptags_full") || !hasIdx(db, "idx_iptag_ip") {
		t.Fatal("迁移已记为完成后，启动检查仍应补回索引")
	}
}

// 折叠函数本身：不依赖引擎行为（SQLite 对批内同键不报错，只有 PG 会，光看写入结果抓不住缺陷）
func TestIPTagHeal_FoldMergesSameKey(t *testing.T) {
	early, late := healT0, healT0.Add(time.Hour)
	out := foldIPTags([]model.IPTag{
		healRow("a", "5.5.5.5", "XSS", 1, late, early),
		healRow("b", "5.5.5.5", "XSS", 2, early, late),
		healRow("c", "5.5.5.5", "SQL注入", 4, early, early),
	})
	if len(out) != 2 {
		t.Fatalf("同键应折叠，期望 2 行，实得 %d", len(out))
	}
	if out[0].Cnt != 3 || !time.Time(out[0].CREATE_TIME).Equal(early) || !time.Time(out[0].UPDATE_TIME).Equal(late) {
		t.Fatalf("cnt 应求和、创建取早、更新取晚: %+v", out[0])
	}
}

// 回填期间别的连接持续写入：回填不能因为 BUSY 失败（延迟事务先读后写会立刻返回 BUSY，不等 busy_timeout）
func TestIPTagHeal_BackfillSurvivesConcurrentWriter(t *testing.T) {
	withSmallRows(t, 1)
	old := tableheal.BackfillBatch
	tableheal.BackfillBatch = 5
	t.Cleanup(func() { tableheal.BackfillBatch = old })

	path := filepath.Join(t.TempDir(), "conc.db")
	dsn := path + "?_db_key=" + url.QueryEscape("heal") + "&_busy_timeout=5000"
	dialect.Register(&dialect.SQLiteDialect{})
	db, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	_ = db.Exec("PRAGMA journal_mode=WAL")
	if err := db.AutoMigrate(&model.IPTag{}); err != nil {
		t.Fatal(err)
	}
	const total = 2500
	rows := make([]model.IPTag, 0, total)
	for i := 0; i < total; i++ {
		rows = append(rows, healRow(fmt.Sprintf("id%05d", i), fmt.Sprintf("10.2.%d.%d", i/256, i%256), "扫描工具", 1, healT0, healT0))
	}
	rows = append(rows, healRow("dup", "10.2.0.0", "扫描工具", 1, healT0, healT0)) // 触发换表
	db.CreateInBatches(rows, 200)
	ensureIPTagIndexes(db, true)
	if !db.Migrator().HasTable("ip_tags__heal") {
		t.Fatal("应已换表")
	}

	writer, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Exec("CREATE TABLE IF NOT EXISTS side_writes (id INTEGER PRIMARY KEY, v TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	if ws, err := writer.DB(); err == nil {
		ws.Close()
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 3; w++ { // 多条写入连接不留空隙地写，让回填事务读完之后总有别的提交插进来
		wr, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err != nil {
			t.Fatal(err)
		}
		ws, _ := wr.DB()
		ws.SetMaxOpenConns(1)
		t.Cleanup(func() { ws.Close() })
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				wr.Exec("INSERT INTO side_writes (v) VALUES ('x')")
			}
		}()
	}
	tableheal.RunBackfill(db, "测试库", ipTagHealSpec(true))
	close(stop)
	wg.Wait()

	if db.Migrator().HasTable("ip_tags__heal") {
		t.Fatal("并发写入下回填应能完成（heal 表仍在，说明回填失败退出）")
	}
	var sum int64
	db.Table("ip_tags").Select("SUM(cnt)").Scan(&sum)
	if sum != total+1 {
		t.Fatalf("cnt 总和应守恒 %d，实得 %d", total+1, sum)
	}
}
