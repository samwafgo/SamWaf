//go:build iptagperf

// ip_tags 缺唯一索引时「小表直接建索引」的阈值基准：在加密 SQLite 上按不同行数测同步段耗时，
// 并用另一条连接持续写旁表，量出建索引期间写入最长被阻塞多久。
//
// 运行（需要 CGO + mingw）：
//
//	go test -tags iptagperf ./wafdb/ -run TestIPTagHealThreshold -v -timeout 60m
//	SAMWAF_HEAL_SIZES=200000,500000 go test -tags iptagperf ./wafdb/ -run TestIPTagHealThreshold -v -timeout 60m
package wafdb

import (
	"SamWaf/model"
	"SamWaf/wafdb/dialect"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const healPerfKey = "heal_perf"

func healSizes() []int {
	s := os.Getenv("SAMWAF_HEAL_SIZES")
	if s == "" {
		return []int{50000, 100000, 200000, 500000, 1000000}
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}

type healCase struct {
	name     string
	dupEvery int  // 每多少行插一条同键重复，0=无重复
	relaxed  bool // synchronous=NORMAL（统计库）；false=FULL（核心库）
}

func openHealDB(t *testing.T, path string, relaxed bool) *gorm.DB {
	t.Helper()
	dsn := path + "?_db_key=" + url.QueryEscape(healPerfKey)
	db, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1) // 连接级 pragma 只作用于这一条连接
	applyPerfPragmas(db, relaxed)
	return db
}

// seedHealRows 造 n 行无索引的 ip_tags（模拟被重建后丢了索引的表），返回实际行数
func seedHealRows(t *testing.T, db *gorm.DB, n, dupEvery int) int {
	t.Helper()
	if err := db.AutoMigrate(&model.IPTag{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	tags := []string{"SQL注入", "XSS跨站注入", "扫描工具", "RCE:存在OS命令注入", "OWASP:942100",
		"静态文件安全检查: 文件未找到", "威胁情报IP", "CC攻击", "疑似爬虫", "自定义规则放行"}
	const user, tenant = "c0b4f6a2e7d94e1b8f3a5c6d7e8f9a0b", "SamWafCom"
	now := time.Now().Format("2006-01-02 15:04:05")
	const per = 100
	insertSQL := "INSERT INTO ip_tags (id,user_code,tenant_id,create_time,update_time,ip,ip_tag,cnt) VALUES " +
		strings.TrimSuffix(strings.Repeat("(?,?,?,?,?,?,?,?),", per), ",")
	total := 0
	err := db.Transaction(func(tx *gorm.DB) error {
		args := make([]interface{}, 0, per*8)
		k := 0
		flush := func() error {
			if k == 0 {
				return nil
			}
			q := insertSQL
			if k < per {
				q = "INSERT INTO ip_tags (id,user_code,tenant_id,create_time,update_time,ip,ip_tag,cnt) VALUES " +
					strings.TrimSuffix(strings.Repeat("(?,?,?,?,?,?,?,?),", k), ",")
			}
			if err := tx.Exec(q, args...).Error; err != nil {
				return err
			}
			total += k
			k, args = 0, args[:0]
			return nil
		}
		add := func(id string, i int) error {
			ip := fmt.Sprintf("%d.%d.%d.%d", 1+(i/16777216)%223, (i/65536)%256, (i/256)%256, i%256)
			args = append(args, id, user, tenant, now, now, ip, tags[i%len(tags)], int64(1+i%97))
			k++
			if k >= per {
				return flush()
			}
			return nil
		}
		for i := 0; i < n; i++ {
			if err := add(fmt.Sprintf("id-%09d", i), i); err != nil {
				return err
			}
			if dupEvery > 0 && i%dupEvery == 0 {
				if err := add(fmt.Sprintf("dup-%09d", i), i); err != nil {
					return err
				}
			}
		}
		return flush()
	})
	if err != nil {
		t.Fatalf("造数据失败: %v", err)
	}
	return total
}

// healSmallTable 小表路径：先直接建唯一索引；撞重复再去重重试。全程一个事务。
func healSmallTable(db *gorm.DB) (dedupRows int64, err error) {
	const uni = "CREATE UNIQUE INDEX IF NOT EXISTS uni_iptags_full ON ip_tags (user_code, tenant_id, ip, ip_tag)"
	err = db.Transaction(func(tx *gorm.DB) error {
		if e := tx.Exec(uni).Error; e != nil {
			if !strings.Contains(strings.ToUpper(e.Error()), "UNIQUE") {
				return e
			}
			// 重复组汇总到临时表：保留 MIN(id)，cnt 求和，时间取早/晚
			steps := []string{
				`CREATE TEMP TABLE heal_dup AS SELECT user_code, tenant_id, ip, ip_tag, MIN(id) AS keep_id,
					SUM(cnt) AS s, MIN(create_time) AS c, MAX(update_time) AS u
					FROM ip_tags GROUP BY user_code, tenant_id, ip, ip_tag HAVING COUNT(*) > 1`,
				`CREATE INDEX temp.heal_dup_k ON heal_dup (user_code, tenant_id, ip, ip_tag)`,
				`CREATE INDEX temp.heal_dup_id ON heal_dup (keep_id)`,
				`UPDATE ip_tags SET cnt = (SELECT s FROM heal_dup d WHERE d.keep_id = ip_tags.id),
					create_time = (SELECT c FROM heal_dup d WHERE d.keep_id = ip_tags.id),
					update_time = (SELECT u FROM heal_dup d WHERE d.keep_id = ip_tags.id)
					WHERE id IN (SELECT keep_id FROM heal_dup)`,
			}
			for _, s := range steps {
				if e := tx.Exec(s).Error; e != nil {
					return e
				}
			}
			r := tx.Exec(`DELETE FROM ip_tags WHERE EXISTS (SELECT 1 FROM heal_dup d WHERE d.user_code = ip_tags.user_code
				AND d.tenant_id = ip_tags.tenant_id AND d.ip = ip_tags.ip AND d.ip_tag = ip_tags.ip_tag AND d.keep_id <> ip_tags.id)`)
			if r.Error != nil {
				return r.Error
			}
			dedupRows = r.RowsAffected
			if e := tx.Exec("DROP TABLE temp.heal_dup").Error; e != nil {
				return e
			}
			if e := tx.Exec(uni).Error; e != nil {
				return e
			}
		}
		return tx.Exec("CREATE INDEX IF NOT EXISTS idx_iptag_ip ON ip_tags (user_code, tenant_id, ip)").Error
	})
	return
}

// healSwap 换表路径：旧表改名 __heal，建空新表+索引（不含回填）
func healSwap(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		for _, s := range []string{
			"DROP INDEX IF EXISTS uni_iptags_full",
			"DROP INDEX IF EXISTS idx_iptag_ip",
			"ALTER TABLE ip_tags RENAME TO ip_tags__heal",
		} {
			if e := tx.Exec(s).Error; e != nil {
				return e
			}
		}
		if e := tx.AutoMigrate(&model.IPTag{}); e != nil {
			return e
		}
		if e := tx.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uni_iptags_full ON ip_tags (user_code, tenant_id, ip, ip_tag)").Error; e != nil {
			return e
		}
		return tx.Exec("CREATE INDEX IF NOT EXISTS idx_iptag_ip ON ip_tags (user_code, tenant_id, ip)").Error
	})
}

// sideWriter 另开一条连接每 2ms 往旁表插一行；stop() 返回最长单次写耗时、写失败数、总写数
func sideWriter(t *testing.T, path string) func() (time.Duration, int, int) {
	t.Helper()
	dsn := path + "?_db_key=" + url.QueryEscape(healPerfKey) + "&_busy_timeout=5000"
	w, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("写连接打开失败: %v", err)
	}
	w.SetMaxOpenConns(1)
	if _, err := w.Exec("CREATE TABLE IF NOT EXISTS side_writes (id INTEGER PRIMARY KEY, v TEXT)"); err != nil {
		t.Fatalf("旁表建表失败: %v", err)
	}
	var (
		mu    sync.Mutex
		maxD  time.Duration
		fails int
		n     int
		done  = make(chan struct{})
		wg    sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			st := time.Now()
			_, e := w.Exec("INSERT INTO side_writes (v) VALUES (?)", "x")
			d := time.Since(st)
			mu.Lock()
			n++
			if e != nil {
				fails++
			}
			if d > maxD {
				maxD = d
			}
			mu.Unlock()
			time.Sleep(2 * time.Millisecond)
		}
	}()
	time.Sleep(50 * time.Millisecond)
	return func() (time.Duration, int, int) {
		close(done)
		wg.Wait()
		w.Close()
		return maxD, fails, n
	}
}

func TestIPTagHealThreshold(t *testing.T) {
	dialect.Register(&dialect.SQLiteDialect{})
	cases := []healCase{
		{"核心库FULL-无重复", 0, false},
		{"核心库FULL-1%重复", 100, false},
		{"统计库NORMAL-无重复", 0, true},
	}
	var report []string
	for _, n := range healSizes() {
		for _, c := range cases {
			path := filepath.Join(t.TempDir(), "heal.db")
			db := openHealDB(t, path, c.relaxed)
			st := time.Now()
			rows := seedHealRows(t, db, n, c.dupEvery)
			seedDur := time.Since(st)

			st = time.Now()
			var cnt int64
			db.Raw("SELECT COUNT(*) FROM ip_tags").Scan(&cnt)
			countDur := time.Since(st)

			stop := sideWriter(t, path)
			st = time.Now()
			removed, err := healSmallTable(db)
			healDur := time.Since(st)
			maxW, fails, writes := stop()
			if err != nil {
				t.Fatalf("[%d %s] 小表路径失败: %v", n, c.name, err)
			}
			var after, idx int64
			db.Raw("SELECT COUNT(*) FROM ip_tags").Scan(&after)
			db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('uni_iptags_full','idx_iptag_ip')").Scan(&idx)
			if idx != 2 || int64(rows)-removed != after {
				t.Fatalf("[%d %s] 结果不对: 索引=%d 行数 %d-%d≠%d", n, c.name, idx, rows, removed, after)
			}

			// 换表路径对照：先删掉刚建的索引回到缺失状态
			db.Exec("DROP INDEX uni_iptags_full")
			db.Exec("DROP INDEX idx_iptag_ip")
			st = time.Now()
			if err := healSwap(db); err != nil {
				t.Fatalf("[%d %s] 换表失败: %v", n, c.name, err)
			}
			swapDur := time.Since(st)

			line := fmt.Sprintf("| %d | %s | %d | %s | %s | %s | %d | %s | %d/%d | %s |",
				n, c.name, rows, seedDur.Round(time.Millisecond), countDur.Round(time.Millisecond),
				healDur.Round(time.Millisecond), removed, maxW.Round(time.Millisecond), fails, writes,
				swapDur.Round(time.Millisecond))
			t.Log(line)
			report = append(report, line)
			if sqlDB, e := db.DB(); e == nil {
				sqlDB.Close()
			}
		}
	}
	fmt.Println("\n| 目标行数 | 场景 | 实际行数 | 造数 | COUNT | 小表路径 | 去重删行 | 并发写最长等待 | 写失败/总写 | 换表路径 |")
	fmt.Println("|---|---|---|---|---|---|---|---|---|---|")
	for _, l := range report {
		fmt.Println(l)
	}
}
