//go:build iptagperf

// 换表后台回填期间，并发写入被拖慢多少：回填线程分批并回 ip_tags__heal 的同时，
// 另外两条连接持续写入——一条写旁表（代表日志落库等其他业务），一条对 ip_tags 做真实的 UpsertIPTags
// （代表实时标签统计）。量写入的最长等待、P99 和失败数，并核对回填前后 cnt 总和不变。
//
// 运行（需要 CGO + mingw）：
//
//	go test -tags iptagperf ./wafdb/ -run TestIPTagHealBackfillLatency -v -timeout 60m
//	SAMWAF_HEAL_SIZES=200000,1000000 go test -tags iptagperf ./wafdb/ -run TestIPTagHealBackfillLatency -v -timeout 60m
package wafdb

import (
	"SamWaf/customtype"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafdb/tableheal"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type latencyProbe struct {
	mu    sync.Mutex
	lat   []time.Duration
	fails int
}

func (p *latencyProbe) record(d time.Duration, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lat = append(p.lat, d)
	if err != nil {
		p.fails++
	}
}

func (p *latencyProbe) summary() (max, p99 time.Duration, n, fails int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.lat) == 0 {
		return
	}
	s := append([]time.Duration(nil), p.lat...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)-1], s[len(s)*99/100], len(s), p.fails
}

func TestIPTagHealBackfillLatency(t *testing.T) {
	dialect.Register(&dialect.SQLiteDialect{})
	cases := []healCase{
		{"核心库FULL-1%重复", 100, false},
		{"统计库NORMAL-1%重复", 100, true},
	}
	sizes := healSizes()
	var report []string
	for _, n := range sizes {
		for _, c := range cases {
			path := filepath.Join(t.TempDir(), "heal.db")
			db := openHealDB(t, path, c.relaxed)
			rows := seedHealRows(t, db, n, c.dupEvery)
			var wantSum int64
			db.Raw("SELECT COALESCE(SUM(cnt),0) FROM ip_tags").Scan(&wantSum)

			st := time.Now()
			ensureIPTagIndexes(db, !c.relaxed)
			swapDur := time.Since(st)
			if !db.Migrator().HasTable("ip_tags__heal") {
				t.Fatalf("[%d %s] 应已换表", n, c.name)
			}

			// 写入线程 1：旁表（代表其他业务写入）
			dsn := path + "?_db_key=" + url.QueryEscape(healPerfKey) + "&_busy_timeout=5000"
			side, err := sql.Open("sqlite3", dsn)
			if err != nil {
				t.Fatal(err)
			}
			side.SetMaxOpenConns(1)
			if _, err := side.Exec("CREATE TABLE IF NOT EXISTS side_writes (id INTEGER PRIMARY KEY, v TEXT)"); err != nil {
				t.Fatal(err)
			}
			// 写入线程 2：对 ip_tags 的真实 upsert，独立连接
			tagDB, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
			if err != nil {
				t.Fatal(err)
			}
			tsql, _ := tagDB.DB()
			tsql.SetMaxOpenConns(1)

			var sideProbe, tagProbe latencyProbe
			var liveCnt int64
			done := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-done:
						return
					default:
					}
					s := time.Now()
					_, e := side.Exec("INSERT INTO side_writes (v) VALUES (?)", "x")
					sideProbe.record(time.Since(s), e)
					time.Sleep(2 * time.Millisecond)
				}
			}()
			go func() {
				defer wg.Done()
				now := customtype.JsonTime(time.Now())
				for i := 0; ; i++ {
					select {
					case <-done:
						return
					default:
					}
					batch := make([]model.IPTag, 0, 20)
					for j := 0; j < 20; j++ {
						k := (i*20 + j) % n
						batch = append(batch, model.IPTag{
							BaseOrm: baseorm.BaseOrm{Id: fmt.Sprintf("live-%d-%d", i, j), USER_CODE: "c0b4f6a2e7d94e1b8f3a5c6d7e8f9a0b", Tenant_ID: "SamWafCom", CREATE_TIME: now, UPDATE_TIME: now},
							IP:      fmt.Sprintf("%d.%d.%d.%d", 1+(k/16777216)%223, (k/65536)%256, (k/256)%256, k%256),
							IPTag:   "live", Cnt: 1,
						})
					}
					s := time.Now()
					e := UpsertIPTags(tagDB, batch)
					tagProbe.record(time.Since(s), e)
					if e == nil {
						liveCnt += int64(len(batch))
					}
					time.Sleep(20 * time.Millisecond)
				}
			}()
			time.Sleep(100 * time.Millisecond)

			st = time.Now()
			tableheal.BackfillPause = 10 * time.Millisecond
			tableheal.RunBackfill(db, "基准", ipTagHealSpec(!c.relaxed))
			fillDur := time.Since(st)
			close(done)
			wg.Wait()
			side.Close()
			tsql.Close()

			if db.Migrator().HasTable("ip_tags__heal") {
				t.Fatalf("[%d %s] 回填后 heal 表应已删除", n, c.name)
			}
			var gotSum, gotRows int64
			db.Raw("SELECT COALESCE(SUM(cnt),0) FROM ip_tags").Scan(&gotSum)
			db.Raw("SELECT COUNT(*) FROM ip_tags").Scan(&gotRows)
			if gotSum != wantSum+liveCnt {
				t.Fatalf("[%d %s] cnt 总和不守恒: 期望 %d+%d，实得 %d", n, c.name, wantSum, liveCnt, gotSum)
			}

			sMax, sP99, sN, sFail := sideProbe.summary()
			tMax, tP99, tN, tFail := tagProbe.summary()
			line := fmt.Sprintf("| %d | %s | %d | %s | %s | %.0f | %s / %s | %d/%d | %s / %s | %d/%d |",
				n, c.name, rows, swapDur.Round(time.Millisecond), fillDur.Round(time.Millisecond),
				float64(rows)/fillDur.Seconds(),
				sMax.Round(time.Millisecond), sP99.Round(time.Millisecond), sFail, sN,
				tMax.Round(time.Millisecond), tP99.Round(time.Millisecond), tFail, tN)
			t.Log(line)
			report = append(report, line)
			if s, e := db.DB(); e == nil {
				s.Close()
			}
		}
	}
	fmt.Println("\n| 目标行数 | 场景 | 实际行数 | 换表 | 回填总耗时 | 回填行/s | 旁表写 最长/P99 | 失败/总数 | ip_tags upsert 最长/P99 | 失败/总数 |")
	fmt.Println("|---|---|---|---|---|---|---|---|---|---|")
	for _, l := range report {
		fmt.Println(l)
	}
}
