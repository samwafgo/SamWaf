//go:build crossdb

// 时间分区三动词（E1）的三库回归：建 / 列 / 丢。
//
// 三个引擎的语义故意不一样，所以必须各跑一遍：
// MySQL 是 CREATE TABLE LIKE、PG 是 LIKE ... INCLUDING ALL（索引名由 PG 自己生成，
// 写成复制原名会撞），SQLite 按文件分区、建与丢一律返回「不适用」让调用方分流。
// 丢分区是不可逆动作，这里同时钉住「基表 + 分区表」的配对校验：名字不同族就必须拒绝。
// 由 TestCrossEngine 每引擎调一次。
package waf_service

import (
	"SamWaf/model"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafdb/partition"
	"testing"

	"gorm.io/gorm"
)

func runPartitionCases(t *testing.T, logdb *gorm.DB) {
	d := dialect.Get()
	base := model.AccessLogTableName
	part := partition.TableName(base, "209901") // 远期周期键，不会和真实分片撞

	// 收尾：无论断言走到哪一步都别留下测试表
	defer func() {
		if !d.IsFileBased() {
			_ = d.DropPartition(logdb, base, part)
		}
	}()

	if d.IsFileBased() {
		// SQLite：建与丢发生在文件层，dialect 必须明确说不适用，
		// 而不是静默成功——静默成功会让清理任务以为分区已经删掉了
		if err := d.CreatePartition(logdb, base, part); err == nil {
			t.Error("SQLite 的 CreatePartition 应返回不适用错误")
		}
		if err := d.DropPartition(logdb, base, part); err == nil {
			t.Error("SQLite 的 DropPartition 应返回不适用错误")
		}
		// 列分区在 SQLite 上返回空是正常的（一个文件里不会有周期表），不该报错
		parts, err := d.ListPartitions(logdb, base)
		if err != nil {
			t.Errorf("SQLite 列分区不该报错: %v", err)
		}
		for _, p := range parts {
			if p == part {
				t.Errorf("SQLite 上不该出现分区表 %s", p)
			}
		}
		return
	}

	// 1) 建分区：与基表同构
	if err := d.CreatePartition(logdb, base, part); err != nil {
		t.Fatalf("建分区 %s 失败: %v", part, err)
	}
	// 幂等：同一个周期重复建不能报错（切库重试、任务重跑都会碰到）
	if err := d.CreatePartition(logdb, base, part); err != nil {
		t.Fatalf("重复建同一个分区应幂等，实际报错: %v", err)
	}
	if !d.TableExists(logdb, part) {
		t.Fatalf("分区表 %s 建完却不存在", part)
	}

	// 结构可用：基表的列都在，且能写能读
	baseCols, err := d.ColumnInfo(logdb, base)
	fatalIf(t, err)
	partCols, err := d.ColumnInfo(logdb, part)
	fatalIf(t, err)
	if len(partCols) != len(baseCols) {
		t.Fatalf("分区表列数 %d 与基表 %d 不一致（结构没复制全）", len(partCols), len(baseCols))
	}
	uid := "part_" + sfx()
	must(t, logdb.Table(part).Create(&model.AccessLog{
		LogNarrow: model.LogNarrow{
			ReqUUID:  uid,
			HostCode: "h1",
			UserCode: xtestUser,
			TenantId: xtestTenant,
			Day:      20990101,
		},
	}).Error)
	var cnt int64
	must(t, logdb.Table(part).Where("req_uuid = ?", uid).Count(&cnt).Error)
	if cnt != 1 {
		t.Fatalf("分区表里应能读到刚写的行，实际 %d 行", cnt)
	}
	// 写进分区的行不该出现在基表里（两张独立的表，不是同一份数据）
	var liveCnt int64
	must(t, logdb.Table(base).Where("req_uuid = ?", uid).Count(&liveCnt).Error)
	if liveCnt != 0 {
		t.Fatalf("分区表的行漏进基表了，基表命中 %d 行", liveCnt)
	}

	// 2) 列分区：认自己的分区，不认别的基表的
	parts, err := d.ListPartitions(logdb, base)
	fatalIf(t, err)
	found := false
	for _, p := range parts {
		if p == part {
			found = true
		}
		if p == base {
			t.Errorf("基表 %s 自己不该出现在分区列表里", base)
		}
	}
	if !found {
		t.Fatalf("分区列表里找不到 %s，实际 %v", part, parts)
	}
	otherParts, err := d.ListPartitions(logdb, model.SecurityEventTableName)
	fatalIf(t, err)
	for _, p := range otherParts {
		if p == part {
			t.Errorf("%s 是 %s 的分区，不该出现在 %s 的分区列表里", p, base, model.SecurityEventTableName)
		}
	}

	// 3) 丢分区：名字不同族一律拒绝，别把无关的表丢掉
	if err := d.DropPartition(logdb, base, model.SecurityEventTableName); err == nil {
		t.Errorf("拿 %s 当基表去丢 %s 应被拒绝", base, model.SecurityEventTableName)
	}
	if !d.TableExists(logdb, model.SecurityEventTableName) {
		t.Fatalf("%s 表被误删了", model.SecurityEventTableName)
	}
	if err := d.DropPartition(logdb, base, base); err == nil {
		t.Error("把基表自己当分区丢应被拒绝")
	}
	if !d.TableExists(logdb, base) {
		t.Fatal("基表被误删了")
	}

	// 正常丢
	if err := d.DropPartition(logdb, base, part); err != nil {
		t.Fatalf("丢分区 %s 失败: %v", part, err)
	}
	if d.TableExists(logdb, part) {
		t.Fatalf("分区表 %s 丢完却还在", part)
	}
	// 幂等：清理任务重跑不能因为已经没了而报错
	if err := d.DropPartition(logdb, base, part); err != nil {
		t.Fatalf("重复丢同一个分区应幂等，实际报错: %v", err)
	}
}
