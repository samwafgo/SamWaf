//go:build crossdb

// 归档分片缺列时的日志查询回归。
//
// 归档分片是分库那一刻的结构快照，此后给 web_logs 加的列它没有。日志列表的 SELECT 是按当前
// 结构体反射出来的显式列名，少一列整条查询就报错；而同一次请求里的 Count 不带列、照样数得出来，
// 页面于是变成「有分页、没数据」。这组用例钉住两件事：按交集列查得通，按全量列必然报错
// （对照组一旦不报错，说明这个引擎不介意多选一列，用例本身就失去意义了）。
package waf_service

import (
	"SamWaf/innerbean"
	"strings"
	"testing"

	"gorm.io/gorm"
)

func runShardColumnCases(t *testing.T, logdb *gorm.DB) {
	want := getWebLogListColumns()
	const dropped = "truncated"

	keep := make([]string, 0, len(want))
	for _, c := range want {
		if c != dropped {
			keep = append(keep, c)
		}
	}
	if len(keep) == len(want) {
		t.Fatalf("结构体里已经没有 %s 列了，用例需要换一列来模拟", dropped)
	}

	name := "web_logs_xcol" + sfx()
	must(t, logdb.Exec("CREATE TABLE "+name+" AS SELECT "+strings.Join(keep, ", ")+" FROM web_logs WHERE 1=0").Error)
	defer logdb.Exec("DROP TABLE IF EXISTS " + name)

	sel := webLogSelect(logdb, name, name, want, "list")
	if strings.Contains(sel, dropped) {
		t.Fatalf("缺列的分片不该把 %s 放进 SELECT: %s", dropped, sel)
	}

	var rows []innerbean.WebLog
	if err := logdb.Table(name).Select(sel).Limit(1).Find(&rows).Error; err != nil {
		t.Fatalf("按交集列查缺列分片仍然报错: %v", err)
	}

	// 对照组：修复前就是这么查的
	if err := logdb.Table(name).Select(strings.Join(want, ", ")).Limit(1).Find(&rows).Error; err == nil {
		t.Fatal("对照组没报错——这个引擎不介意多选一列，用例失去意义，需要换验证方式")
	}

	// 列齐全的实时表不受影响，该选的一列都不能少
	live := webLogSelect(logdb, "", "web_logs", want, "list")
	if !strings.Contains(live, dropped) {
		t.Fatalf("实时表列是齐的，不该丢 %s: %s", dropped, live)
	}
}
